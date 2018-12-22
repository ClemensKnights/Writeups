#!/usr/bin/python3

import bitstring
import sys
from PIL import Image

if len(sys.argv) <= 2:
    print('Usage: {} <source> <target>'.format(sys.argv[0]), file=sys.stderr)
    exit(1)

source = sys.argv[1]
target = sys.argv[2]

with Image.open(source) as img:
    bits = ''
    for row in range(img.height):
        for col in range(img.width):
            bits += '1' if img.getpixel((col, row))[0] >= 0x80 else '0'
    with open(target, 'wb') as tgt:
        tgt.write(bitstring.BitArray(bin=bits).bytes)
