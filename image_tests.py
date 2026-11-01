"""Runtime-only image controls and judge transport tests."""
import io
import json
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch
from PIL import Image, ImageDraw, PngImagePlugin
import image_support as images
import publish_gate as gate


def controls(root):
    im = Image.new('RGB', (240, 40), 'white')
    im.save(root / 'clean.png')
    info = PngImagePlugin.PngInfo()
    info.add_text('Author', 'Example')
    im.save(root / 'text.png', pnginfo=info)
    exif = Image.Exif()
    exif[270] = 'Example'
    im.save(root / 'exif.jpg', exif=exif)
    ImageDraw.Draw(im).text((5, 5), 'fake' + '@' + 'example.invalid', fill='black')
    im.save(root / 'pixels.png')


class ImageTest(unittest.TestCase):
    def test_containers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            controls(root)
            self.assertFalse(images.inspect((root / 'clean.png').read_bytes()))
            self.assertTrue(images.inspect((root / 'text.png').read_bytes()))
            self.assertTrue(images.inspect((root / 'exif.jpg').read_bytes()))
            for fmt in ['PNG', 'JPEG', 'WEBP', 'GIF']:
                path = root / fmt
                Image.new('RGB', (8, 8), 'white').save(path, format=fmt)
                self.assertFalse(images.inspect(path.read_bytes()), fmt)
                self.assertTrue(images.inspect(path.read_bytes() + b'extra'), fmt)
            images.strip(root / 'text.png', root / 'stripped.png')
            self.assertFalse(images.inspect((root / 'stripped.png').read_bytes()))
            self.assertEqual(images.frames((root / 'clean.png').read_bytes())[0].tobytes(), images.frames((root / 'stripped.png').read_bytes())[0].tobytes())
            self.assertEqual(images.inspect(b'\x89PNG\r\n\x1a\n' + b'A' * images.MAX_BYTES), ['image-size-limit'])

    def test_png_ignored_chunks(self):
        for mode, prefix in [('RGB', bytes(6)), ('L', bytes(2)), ('RGBA', bytes(6))]:
            buf = io.BytesIO()
            Image.new(mode, (8, 8), 'white').save(buf, format='PNG')
            clean = buf.getvalue()
            payload = prefix + 'Example'.encode('utf-16le')
            tag = b'tRNS'
            chunk = struct.pack('>I', len(payload)) + tag + payload + struct.pack('>I', zlib.crc32(tag + payload))
            self.assertTrue(images.inspect(clean[:33] + chunk + clean[33:]))
        self.assertTrue(images.inspect(clean[:33] + clean[8:33] + clean[33:]))

    def test_unused_codec_data(self):
        im = Image.new('RGB', (8, 8), 'white')
        payload = 'Example'.encode('utf-16le')
        for fmt in ['PNG', 'WEBP', 'GIF', 'JPEG']:
            buf = io.BytesIO()
            im.save(buf, format=fmt)
            data = buf.getvalue()
            if fmt == 'PNG':
                pos, parts = 8, []
                while pos < len(data):
                    size = int.from_bytes(data[pos:pos + 4], 'big')
                    tag = data[pos + 4:pos + 8]
                    body = data[pos + 8:pos + 8 + size]
                    pos += size + 12
                    if tag == b'IDAT':
                        body += payload
                    parts.append(struct.pack('>I', len(body)) + tag + body + struct.pack('>I', zlib.crc32(tag + body)))
                bad = data[:8] + b''.join(parts)
            elif fmt == 'WEBP':
                size = int.from_bytes(data[16:20], 'little')
                body = data[20:20 + size] + payload
                riff = data[8:16] + struct.pack('<I', len(body)) + body + b'\0' * (len(body) % 2)
                bad = b'RIFF' + struct.pack('<I', len(riff)) + riff
            elif fmt == 'GIF':
                bad = data[:-2] + bytes([len(payload)]) + payload + data[-2:]
            else:
                bad = data[:-2] + payload + data[-2:]
            self.assertTrue(images.inspect(bad), fmt)

    def test_hidden_container_payloads(self):
        im = Image.new('RGB', (8, 8), 'white')
        buf = io.BytesIO()
        im.save(buf, format='PNG')
        payload = 'Example'.encode('utf-16le')
        tag = b'IEND'
        bad = buf.getvalue()[:-12] + struct.pack('>I', len(payload)) + tag + payload + struct.pack('>I', zlib.crc32(tag + payload))
        self.assertTrue(images.inspect(bad))
        buf = io.BytesIO()
        im.save(buf, format='WEBP', save_all=True, append_images=[Image.new('RGB', (8, 8), 'black')])
        data = buf.getvalue()
        def chunk(tag, body):
            return tag + struct.pack('<I', len(body)) + body + b'\0' * (len(body) % 2)
        pos, parts = 12, []
        while pos < len(data):
            tag = data[pos:pos + 4]
            size = int.from_bytes(data[pos + 4:pos + 8], 'little')
            body = data[pos + 8:pos + 8 + size]
            if tag == b'ANMF':
                body += chunk(b'EXIF', payload)
            parts.append(chunk(tag, body))
            pos += 8 + size + size % 2
        body = b'WEBP' + b''.join(parts)
        self.assertTrue(images.inspect(b'RIFF' + struct.pack('<I', len(body)) + body))

    def test_image_gate_and_plumbing(self):
        import argparse
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree = root / 'tree'
            tree.mkdir()
            controls(tree)
            hard, _, _ = gate.scan(tree, [])
            self.assertTrue(any(f['file'] == 'text.png' for f in hard))
            self.assertTrue(any(f['file'] == 'exif.jpg' for f in hard))
            self.assertFalse(any(f['file'] == 'clean.png' for f in hard))
            # Only the clean pixel control enters the end-to-end verdict checks.
            clean = root / 'clean'
            clean.mkdir()
            (clean / 'pixels.png').write_bytes((tree / 'pixels.png').read_bytes())
            deny = root / 'deny'
            deny.write_text('ForbiddenExample')
            scripts = []
            for index in range(2):
                script = root / f'judge{index}.py'
                script.write_text('import json,sys\nfrom pathlib import Path\np=json.loads(sys.stdin.read().splitlines()[-1])\nassert sys.argv[1]=="--image"\nassert Path(sys.argv[2]).read_bytes().startswith(bytes([137,80,78,71]))\nitems=[dict(file=i["file"],verdict="PASS",reason="Synthetic control.") for i in p["image_items"]]\nprint(json.dumps(dict(verdict="PASS",findings=[],review_items=[],image_items=items)))\n')
                scripts.append(f'{sys.executable} {script}')
            args = argparse.Namespace(tree=str(clean), denylist=str(deny), out=str(root / 'out.json'), judge_cmd=scripts)
            with patch.object(gate, 'analyzer_load', return_value=None), patch.object(gate, 'external', return_value=([], {})):
                result, _ = gate.check(args)
                self.assertEqual(result['stages']['4']['result'], 'PASS')
                script.write_text(script.read_text().replace('image_items=items', 'image_items=[]'))
                result, _ = gate.check(args)
                self.assertEqual(result['stages']['4']['result'], 'FAIL')
            (clean / 'unknown.bin').write_bytes(bytes([0, 255, 1, 2]))
            hard, _, _ = gate.scan(clean, [])
            self.assertTrue(any(f['rule_id'] == 'unsupported-encoding' for f in hard))

    def test_adapter_transport(self):
        import judge_adapter
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / 'animated.gif'
            Image.new('RGB', (8, 8), 'white').save(path, save_all=True, append_images=[Image.new('RGB', (8, 8), 'black')])
            for provider in ['claude', 'codex']:
                def respond(cmd, **kwargs):
                    if provider == 'claude':
                        self.assertIn('--input-format', cmd)
                        content = json.loads(kwargs['input'])['message']['content']
                        self.assertEqual(len([x for x in content if x['type'] == 'image']), 2)
                    else:
                        self.assertEqual(cmd.count('--image'), 2)
                    return type('Response', (), {'returncode': 0, 'stdout': '{"type":"result","result":"{}"}' if provider == 'claude' else '{}'})()
                with patch.object(sys, 'argv', ['adapter', provider, '--image', str(path)]), patch.object(sys, 'stdin', io.StringIO('Review')), patch.object(judge_adapter, 'run_cli', side_effect=respond):
                    self.assertEqual(judge_adapter.main(), 0)
