#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 PolitCubes
"""Convert a splash PNG into the raw resource the wrapper embeds (ТЗ §4: no PNG/SVG
decoder at runtime).

Output layout: b"MBSP", u32 width, u32 height, u32 scale percent (little endian), then
width * height premultiplied BGRA pixels, top row first — exactly what
UpdateLayeredWindow wants.

Usage: png_to_bgra.py <in.png> <scale percent> <out.bin>
"""
import struct
import sys
import zlib


def paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode_png(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos = 8
    width = height = depth = ctype = interlace = None
    idat = b""
    palette = None
    trns = None
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        chunk = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", chunk)
        elif kind == b"PLTE":
            palette = chunk
        elif kind == b"tRNS":
            trns = chunk
        elif kind == b"IDAT":
            idat += chunk
        elif kind == b"IEND":
            break
    if depth != 8 or interlace != 0 or ctype not in (2, 3, 6):
        raise ValueError("only 8-bit non-interlaced RGB/RGBA/palette PNGs are supported")
    channels = {2: 3, 3: 1, 6: 4}[ctype]
    stride = width * channels
    raw = zlib.decompress(idat)
    rows = []
    prev = bytearray(stride)
    i = 0
    for _ in range(height):
        f = raw[i]
        line = bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            a = line[x - channels] if x >= channels else 0
            b = prev[x]
            c = prev[x - channels] if x >= channels else 0
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + b) & 255
            elif f == 3:
                line[x] = (line[x] + ((a + b) >> 1)) & 255
            elif f == 4:
                line[x] = (line[x] + paeth(a, b, c)) & 255
        rows.append(bytes(line))
        prev = line
    rgba = bytearray()
    for line in rows:
        for x in range(width):
            if ctype == 6:
                rgba += line[4 * x:4 * x + 4]
            elif ctype == 2:
                rgba += line[3 * x:3 * x + 3] + b"\xff"
            else:
                idx = line[x]
                rgba += palette[3 * idx:3 * idx + 3] + bytes([trns[idx] if trns and idx < len(trns) else 255])
    return width, height, bytes(rgba)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as fh:
        width, height, rgba = decode_png(fh.read())
    scale = int(sys.argv[2])
    out = bytearray(b"MBSP" + struct.pack("<III", width, height, scale))
    for p in range(0, len(rgba), 4):
        r, g, b, a = rgba[p], rgba[p + 1], rgba[p + 2], rgba[p + 3]
        out += bytes(((b * a + 127) // 255, (g * a + 127) // 255, (r * a + 127) // 255, a))
    with open(sys.argv[3], "wb") as fh:
        fh.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
