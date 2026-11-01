"""Batch coverage, failure diagnostics and committed-scope regression controls."""
import argparse
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import publish_gate as gate
import image_support as images
from PIL import Image


class RoundFourTest(unittest.TestCase):
    def test_batches_and_failures(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree = root / 'tree'
            tree.mkdir()
            for name in ('one.txt', 'two.txt'):
                (tree / name).write_text('Example ' * 30)
            Image.new('RGB', (2, 2)).save(tree / 'picture.png')
            deny = root / 'deny'
            deny.write_text('ForbiddenExample')
            def analyze(*args, **kwargs):
                import re
                return [type('Entity', (), dict(entity_type='PERSON', start=m.start(), end=m.end()))()
                        for m in re.finditer('Example', kwargs['text'])]
            analyzer = type('Analyzer', (), {'analyze': analyze})()
            args = argparse.Namespace(tree=str(tree), denylist=str(deny), out=str(root / 'e.json'), judge_cmd=['one', 'two'], judge_batch_size=7, judge_timeout=13)
            for failure in (None, 'missing', 'error'):
                seen = {'one': [], 'two': []}
                pics = {'one': [], 'two': []}
                read = {'one': set(), 'two': set()}
                def respond(argv, cwd, stdin, **kwargs):
                    self.assertEqual(kwargs['timeout'], 13)
                    payload = json.loads(stdin.splitlines()[-1])
                    who = argv[0]
                    items = payload['review_items']
                    self.assertLessEqual(len(items), 7)
                    seen[who].extend(i['id'] for i in items)
                    pics[who].extend(i['file'] for i in payload['image_items'])
                    for name, text in payload['files'].items():
                        if name.endswith('.txt'):
                            self.assertEqual(text, (tree / name).read_text())
                        read[who].add(name)
                    result = dict(verdict='PASS', findings=[], review_items=[dict(id=i['id'], verdict='PASS', reason='Generic.') for i in items], image_items=[dict(file=i['file'], verdict='PASS', reason='Generic.') for i in payload['image_items']])
                    code = 0
                    if who == 'two' and items and items[0]['id'] == 8:
                        if failure == 'missing':
                            result['review_items'] = []
                        if failure == 'error':
                            code = 3
                    return subprocess.CompletedProcess(argv, code, json.dumps(result), 'usage limit exceeded' if code else '')
                with patch.object(gate, 'analyzer_load', return_value=analyzer), patch.object(gate, 'external', return_value=([], {})), patch.object(gate, 'run', side_effect=respond):
                    evidence, _ = gate.check(args)
                self.assertEqual(evidence['result'], 'FAIL' if failure else 'PASS')
                for who in seen:
                    self.assertEqual(sorted(seen[who]), [i['id'] for i in evidence['review_items']])
                    self.assertEqual(pics[who], ['picture.png'])
                    self.assertEqual(read[who], {'one.txt', 'two.txt', 'picture.png'})
                if failure:
                    data = json.loads((root / 'e.judge-2.json').read_text())
                    self.assertIn('usage-limit' if failure == 'error' else 'id mismatch', [b.get('diagnostic', {}).get('failure_class') for b in data['batches']])

    def test_diagnostics(self):
        from diagnostics import diagnostic
        secret = 'sk-' + 'proj-' + 'A' * 40
        for error, process, expected in [
            (subprocess.TimeoutExpired('x', 1), None, 'timeout'),
            (ValueError(), subprocess.CompletedProcess('x', 7, '', secret), 'non-zero exit'),
            (ValueError(), subprocess.CompletedProcess('x', 0, '', ''), 'JSON parse')]:
            result = diagnostic(process, error, expected, 1.2)
            self.assertEqual(result['failure_class'], expected)
            self.assertNotIn(secret, result['stderr_tail'])
            self.assertEqual(result['elapsed_seconds'], 1.2)

    def test_tracked_export(self):
        from tracked_export import export_head
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / 'repo'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
            git('init')
            (repo / 'file.txt').write_text('Committed')
            (repo / 'dist').mkdir()
            (repo / 'dist' / 'ignored.txt').write_text('Excluded')
            git('add', '.')
            git('-c', 'user.name=Example', '-c', 'user.email=' + 'example' + '@' + 'example.invalid', 'commit', '-m', 'Fixture')
            (repo / 'file.txt').write_text('Dirty')
            (repo / 'untracked.txt').write_text('Untracked')
            export = root / 'export'
            export.mkdir()
            export_head(repo, export)
            self.assertEqual([p.name for p in export.iterdir()], ['file.txt'])
            self.assertEqual((export / 'file.txt').read_text(), 'Committed')

    def test_pixel_exclusion_and_ancillary_control(self):
        import struct
        import zlib
        secret = ('sk-' + 'proj-' + 'A' * 40).encode()
        def chunk(tag, body):
            return struct.pack('>I', len(body)) + tag + body + struct.pack('>I', zlib.crc32(tag + body))
        buf = io.BytesIO()
        Image.new('RGB', (2, 2)).save(buf, format='PNG')
        original = buf.getvalue()
        # Stored DEFLATE bytes deliberately contain printable text.
        pixels = b'\0' + secret + b' ' * (60 - len(secret))
        png = original[:8] + chunk(b'IHDR', struct.pack('>IIBBBBB', 20, 1, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(pixels, 0)) + chunk(b'IEND', b'')
        self.assertFalse(images.inspect(png))
        self.assertNotIn(secret.decode(), images.printable(png))
        for data in [png + secret, png[:-12] + chunk(b'tEXt', b'Comment\0' + secret) + png[-12:]]:
            self.assertTrue(images.inspect(data))
            self.assertIn(secret.decode(), images.printable(data))


    def test_adapter_preserves_diagnostic(self):
        import sys
        import judge_adapter
        from diagnostics import diagnostic
        for code, output, stderr, expected in [(0, 'not-json', 'parse warning', 'JSON parse'), (1, '', 'usage_limit_exceeded', 'usage-limit')]:
            captured = io.StringIO()
            with patch.object(sys, 'argv', ['adapter', 'claude']), patch.object(sys, 'stdin', io.StringIO('Review')), patch.object(sys, 'stdout', io.StringIO()), patch.object(sys, 'stderr', captured), patch.object(judge_adapter, 'run_cli', return_value=subprocess.CompletedProcess([], code, output, stderr)):
                returned = judge_adapter.main()
            result = diagnostic(subprocess.CompletedProcess([], returned, output, captured.getvalue()), ValueError(), 'JSON parse' if code == 0 else 'non-zero exit', 0)
            self.assertEqual(result['failure_class'], expected)
            if code == 0:
                self.assertIn('parse warning', result['stderr_tail'])


    def test_unrendered_animation_rejected(self):
        import struct
        import zlib
        def chunk(tag, body):
            return struct.pack('>I', len(body)) + tag + body + struct.pack('>I', zlib.crc32(tag + body))
        buf = io.BytesIO()
        Image.new('RGB', (2, 2)).save(buf, format='PNG')
        data = buf.getvalue()
        control = chunk(b'fcTL', struct.pack('>IIIIIHHBB', 0, 2, 2, 0, 0, 1, 10, 0, 0))
        frame = chunk(b'fdAT', struct.pack('>I', 1) + zlib.compress(bytes(14)))
        for declaration in (b'', chunk(b'acTL', struct.pack('>II', 1, 0))):
            self.assertTrue(images.inspect(data[:-12] + declaration + control + frame + data[-12:]))

    def test_timeout_keeps_streamed_stderr(self):
        import sys
        command = [sys.executable, '-c', 'import sys,time;sys.stderr.write("warning-before-wait\\n");sys.stderr.flush();time.sleep(5)']
        adapter = Path(__file__).with_name('judge_adapter.py')
        script = 'import sys;sys.path.insert(0,sys.argv[1]);from judge_adapter import run_cli;run_cli(sys.argv[2:],input="",cwd=".",env=None,timeout=5)'
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            gate.run([sys.executable, '-c', script, str(adapter.parent), *command], adapter.parent, timeout=1)
        self.assertIn('warning-before-wait', caught.exception.stderr)


    def test_adapter_timeout_without_newline(self):
        import sys
        import os
        from diagnostics import diagnostic
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cli = root / 'claude'
            cli.write_text('#!' + sys.executable + '\nimport sys,time\nsys.stderr.write("warning-before-wait");sys.stderr.flush();time.sleep(20)\n')
            cli.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'], PUBLISH_GATE_JUDGE_TIMEOUT='3')
            adapter = Path(__file__).with_name('judge_adapter.py')
            process = gate.run([sys.executable, str(adapter), 'claude'], root, stdin='Review', timeout=3, env=env)
            self.assertNotEqual(process.returncode, 0)
            result = diagnostic(process, None, 'non-zero exit', 3)
            self.assertEqual(result['failure_class'], 'timeout')
            self.assertIn('warning-before-wait', result['stderr_tail'])
