"""Strict image containers and deterministic metadata removal."""
import io
import re
import struct
import zlib
from pathlib import Path
from PIL import Image, ImageSequence

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 20_000_000
MAX_FRAMES = 100


def kind(data):
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'PNG'
    if data.startswith(b'\xff\xd8'):
        return 'JPEG'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'GIF'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'WEBP'


def metadata(data, pixel_ranges=None):
    """Reject unknown extensions too; renderer acceptance is not sanitization."""
    pixel_ranges = pixel_ranges if pixel_ranges is not None else []
    fmt = kind(data)
    bad = set()
    def take(pos, size):
        if pos + size > len(data):
            raise ValueError('truncated-image')
        return data[pos:pos + size]
    if fmt == 'PNG':
        streams, current = [], bytearray()
        dimensions = None
        bits_per_pixel = None
        interlace = 0
        seen = set()
        palette_size = 0
        color = None
        animation_count = None
        frame_count = 0
        sequence = 0
        previous_tag = None
        canvas = None
        pos = 8
        while pos < len(data):
            size = int.from_bytes(take(pos, 4), 'big')
            tag = take(pos + 4, 4)
            payload = take(pos + 8, size)
            crc = int.from_bytes(take(pos + 8 + size, 4), 'big')
            if tag not in {b'IDAT', b'fdAT', b'fcTL'} and tag in seen:
                raise ValueError('png-duplicate-chunk')
            if not seen and tag != b'IHDR':
                raise ValueError('png-header-order')
            if b'IDAT' in seen and tag in {b'PLTE', b'tRNS', b'sBIT', b'gAMA', b'cHRM', b'sRGB'}:
                raise ValueError('png-chunk-order')
            seen.add(tag)
            fixed = {b'IHDR': 13, b'IEND': 0, b'gAMA': 4, b'cHRM': 32, b'sRGB': 1, b'acTL': 8, b'fcTL': 26}
            if tag in fixed and size != fixed[tag]:
                raise ValueError('png-chunk-size')
            if tag == b'IHDR':
                width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', payload)
                dimensions = canvas = (width, height)
                bits_per_pixel = depth * {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
            if tag == b'PLTE' and (size == 0 or size > 768 or size % 3):
                raise ValueError('png-palette-size')
            if tag == b'PLTE':
                if color != 3:
                    raise ValueError('png-unused-palette')
                palette_size = size // 3
                if palette_size > 2 ** depth:
                    raise ValueError('png-palette-depth')
            if tag == b'sBIT' and size != {0: 1, 2: 3, 3: 3, 4: 2, 6: 4}[color]:
                raise ValueError('png-significant-bits-size')
            if tag == b'tRNS':
                if not ((color == 0 and size == 2) or (color == 2 and size == 6) or (color == 3 and 0 < size <= palette_size)):
                    raise ValueError('png-transparency-size')
            if tag == b'acTL':
                if b'IDAT' in seen or frame_count:
                    raise ValueError('png-animation-order')
                animation_count = int.from_bytes(payload[:4], 'big')
                if not 1 <= animation_count <= MAX_FRAMES:
                    raise ValueError('png-animation-count')
            if tag in {b'fcTL', b'fdAT'}:
                if animation_count is None or int.from_bytes(payload[:4], 'big') != sequence:
                    raise ValueError('png-animation-sequence')
                sequence += 1
            if tag == b'fcTL':
                if (frame_count == 0 and b'IDAT' in seen) or (frame_count and not current):
                    raise ValueError('png-unrendered-frame')
                fw, fh, x, y = struct.unpack('>IIII', payload[4:20])
                if not fw or not fh or x + fw > canvas[0] or y + fh > canvas[1]:
                    raise ValueError('png-frame-bounds')
                if frame_count == 0 and (x or y or (fw, fh) != canvas):
                    raise ValueError('png-first-frame-bounds')
                if payload[24] > 2 or payload[25] > 1:
                    raise ValueError('png-frame-operations')
                frame_count += 1
            if tag == b'IDAT':
                if frame_count > 1 or (animation_count is not None and frame_count != 1):
                    raise ValueError('png-image-frame-order')
                if streams or (current and previous_tag != b'IDAT'):
                    raise ValueError('png-image-data-order')
            if tag == b'fdAT' and (frame_count < 2 or b'IDAT' not in seen):
                raise ValueError('png-frame-data-order')
            if tag == b'fdAT' and size < 4:
                raise ValueError('png-frame-size')
            if zlib.crc32(tag + payload) != crc:
                raise ValueError('image-crc')
            if tag not in {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS', b'gAMA', b'cHRM', b'sRGB', b'sBIT', b'acTL', b'fcTL', b'fdAT'}:
                # ICC profiles may contain arbitrary private descriptions even with a generic name.
                bad.add('metadata-' + tag.decode('ascii', 'replace'))
            if tag == b'fcTL' and current:
                streams.append((bytes(current), dimensions))
                current.clear()
            if tag == b'fcTL':
                dimensions = struct.unpack('>II', payload[4:12])
            if tag in {b'IDAT', b'fdAT'}:
                pixel_ranges.append((pos + 8 + (4 if tag == b'fdAT' else 0), pos + 8 + size))
            if tag == b'IDAT':
                current.extend(payload)
            if tag == b'fdAT':
                current.extend(payload[4:])
            previous_tag = tag
            pos += size + 12
            if tag == b'IEND':
                break
        if pos != len(data) or tag != b'IEND':
            raise ValueError('image-trailing-data')
        if animation_count is not None and (frame_count != animation_count or not current):
            raise ValueError('png-animation-frame-count')
        if current:
            streams.append((bytes(current), dimensions))
        if animation_count is not None and len(streams) != animation_count:
            raise ValueError('png-animation-stream-count')
        for stream, (width, height) in streams:
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(stream, MAX_PIXELS * 8 + 100_000)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError('png-unconsumed-stream')
            passes = [(0, 0, 1, 1)] if not interlace else [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
            expected = 0
            for x, y, dx, dy in passes:
                cols, rows = max(0, (width - x + dx - 1) // dx), max(0, (height - y + dy - 1) // dy)
                if cols and rows:
                    expected += rows * (1 + (cols * bits_per_pixel + 7) // 8)
            if len(decoded) != expected:
                raise ValueError('png-extra-pixel-data')
    elif fmt == 'JPEG':
        pos = 2
        while pos < len(data):
            if take(pos, 1) != b'\xff':
                raise ValueError('jpeg-marker')
            while take(pos, 1) == b'\xff':
                pos += 1
            tag = take(pos, 1)[0]
            pos += 1
            if tag == 0xD9:
                break
            size = int.from_bytes(take(pos, 2), 'big')
            if size < 2:
                raise ValueError('jpeg-length')
            payload = take(pos + 2, size - 2)
            if tag == 0xFE or 0xE0 <= tag <= 0xEF:
                # Only the fixed, thumbnail-free JFIF rendering header is accepted.
                if not (tag == 0xE0 and len(payload) == 14 and payload[:5] == b'JFIF\0' and payload[-2:] == b'\0\0'):
                    bad.add('metadata-jpeg-extension')
            pos += size
            if tag == 0xDA:
                entropy_start = pos
                while True:
                    end = data.find(b'\xff', pos)
                    if end < 0:
                        raise ValueError('jpeg-entropy')
                    next_pos = end + 1
                    while take(next_pos, 1) == b'\xff':
                        next_pos += 1
                    marker = take(next_pos, 1)[0]
                    if marker == 0 or 0xD0 <= marker <= 0xD7:
                        pos = next_pos + 1
                    else:
                        pixel_ranges.append((entropy_start, end))
                        pos = end
                        break
        if pos != len(data) or tag != 0xD9:
            raise ValueError('image-trailing-data')
    elif fmt == 'WEBP':
        if int.from_bytes(take(4, 4), 'little') + 8 != len(data):
            raise ValueError('webp-length')
        pos = 12
        while pos < len(data):
            tag = take(pos, 4)
            size = int.from_bytes(take(pos + 4, 4), 'little')
            take(pos + 8, size + size % 2)
            if tag not in {b'VP8 ', b'VP8L', b'VP8X', b'ALPH', b'ANIM', b'ANMF'}:
                bad.add('metadata-webp-extension')
            if tag in {b'VP8 ', b'VP8L', b'ALPH'}:
                pixel_ranges.append((pos + 8, pos + 8 + size))
            if tag == b'ANMF':
                nested = pos + 24
                end = pos + 8 + size
                if size < 16:
                    raise ValueError('webp-frame')
                while nested < end:
                    inner = take(nested, 4)
                    length = int.from_bytes(take(nested + 4, 4), 'little')
                    if inner in {b'ALPH', b'VP8 ', b'VP8L'}:
                        pixel_ranges.append((nested + 8, nested + 8 + length))
                    nested += 8 + length + length % 2
                    if inner not in {b'ALPH', b'VP8 ', b'VP8L'} or nested > end:
                        raise ValueError('webp-frame-extension')
                if nested != end:
                    raise ValueError('webp-frame-length')
            pos += 8 + size + size % 2
    elif fmt == 'GIF':
        header = take(6, 7)
        pos = 13 + (3 * (2 ** ((header[4] & 7) + 1)) if header[4] & 128 else 0)
        def blocks(pos):
            chunks = []
            while True:
                size = take(pos, 1)[0]
                pos += 1
                if not size:
                    return pos, chunks
                chunks.append(take(pos, size))
                pos += size
        while True:
            tag = take(pos, 1)[0]
            pos += 1
            if tag == 0x3B:
                break
            if tag == 0x21:
                label = take(pos, 1)[0]
                pos, chunks = blocks(pos + 1)
                if label == 0xF9 and len(chunks) == 1 and len(chunks[0]) == 4:
                    pass
                elif label == 0xFF and len(chunks) == 2 and chunks[0] == b'NETSCAPE2.0' and len(chunks[1]) == 3 and chunks[1][0] == 1:
                    pass
                else:
                    bad.add('metadata-gif-extension')
            elif tag == 0x2C:
                desc = take(pos, 9)
                pos += 9 + (3 * (2 ** ((desc[8] & 7) + 1)) if desc[8] & 128 else 0)
                take(pos, 1)
                pixel_start = pos
                pos, _ = blocks(pos + 1)
                pixel_ranges.append((pixel_start, pos))
            else:
                raise ValueError('gif-block')
        if pos != len(data):
            raise ValueError('image-trailing-data')
    else:
        raise ValueError('unsupported-image')
    return sorted(bad)


def frames(data):
    with Image.open(io.BytesIO(data)) as im:
        if im.width * im.height * getattr(im, 'n_frames', 1) > MAX_PIXELS or getattr(im, 'n_frames', 1) > MAX_FRAMES:
            raise ValueError('image-render-limit')
        return [frame.convert('RGBA').copy() for frame in ImageSequence.Iterator(im)]


def inspect(data):
    if len(data) > MAX_BYTES:
        return ['image-size-limit']
    try:
        bad = metadata(data)
        frames(data)
        if kind(data) != 'PNG':
            # These decoders expose no consumed-byte count. Accept only byte-exact
            # renderer re-encodings, so invisible codec payload cannot survive.
            with Image.open(io.BytesIO(data)) as im:
                im.info.clear()
                encoded = io.BytesIO()
                options = {'quality': 'keep'} if kind(data) == 'JPEG' else {}
                if getattr(im, 'n_frames', 1) > 1:
                    options.update(save_all=True)
                im.save(encoded, format=kind(data), **options)
                if encoded.getvalue() != data:
                    bad.append('image-noncanonical-stream-use-strip')
        return bad
    except Exception:
        return ['invalid-image']


def printable(data):
    ranges = []
    try:
        metadata(data, ranges)
    except Exception:
        pass  # inspect() rejects malformed containers; retain unconsumed bytes.
    chunks, pos = [], 0
    for start, end in sorted(ranges):
        chunks.append(data[pos:start])
        pos = end
    chunks.append(data[pos:])
    return '\n'.join(x.decode('ascii') for chunk in chunks
                     for x in re.findall(rb'[\x20-\x7e]{4,}', chunk))


def strip(source, output):
    data = Path(source).read_bytes()
    if len(data) > MAX_BYTES or not kind(data):
        raise ValueError('unsupported-image')
    # Re-render to PNG, preserving all displayed frames but discarding metadata.
    rendered = frames(data)
    for frame in rendered:
        frame.info.clear()
    rendered[0].save(output, format='PNG', save_all=len(rendered) > 1,
                     append_images=rendered[1:], duration=100, loop=0)
    if inspect(Path(output).read_bytes()):
        raise ValueError('strip-verification-failed')
