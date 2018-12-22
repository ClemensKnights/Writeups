#!/usr/bin/python

import binascii
import warnings
import zlib

# Read the IHDR block
def describe(png):
    ihdr = png.find(b'IHDR')
    width = int.from_bytes(png[ihdr + 4 : ihdr + 8], byteorder='big')
    height = int.from_bytes(png[ihdr + 8 : ihdr + 12], byteorder='big')
    bit_depth = png[ihdr + 12]
    color_type = png[ihdr + 13]
    compression = png[ihdr + 14]
    filter_method = png[ihdr + 15]
    interlacing = png[ihdr + 16]

    return ihdr, width, height, bit_depth, color_type, compression, filter_method, interlacing

# Extracts the IDAT block
def image_data(png):
    idat = png.find(b'IDAT')
    size = int.from_bytes(png[idat - 4 : idat], byteorder='big')
    crc  = int.from_bytes(png[idat + 4 + size : idat + 4 + size + 4], byteorder='big')
    data = png[idat + 4 : idat + 4 + size]
    return idat, data


if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 2:
        print('Usage: {} <Celebration> <output>'.format(sys.argv[0]), file=sys.stderr)
        exit(1)

    # Read the file 
    with open(sys.argv[1], 'rb') as source:
        png = bytearray(source.read())

    # Restore PNG header
    png[1:3] = b'PN'

    # Show some metadata
    ihdr, width, height, bit_depth, color_type, compression, filter_method, interlacing = describe(png)
    color_type = {0: 'Grayscale', 2: 'RGB', 3: 'Indexed', 4: 'Gray with Alpha', 5: 'RGBA'}[color_type]
    bpp = {'Grayscale': 1, 'RGB': 3, 'Indexed': 1, 'Gray with Alpha': 2, 'RGBA': 4}[color_type] * bit_depth
    assert compression == 0, 'Unexpected compression method {}'.format(compression)
    assert filter_method == 0, 'Unexpected filter method {}'.format(filter_method)
    interlacing = {0: 'no interlacing', 1: 'Adam7'}[interlacing]
    print('PNG image, {} x {}, {} bit {} ({} bpp), {}'.format(width, height, bit_depth, color_type, bpp, interlacing))

    # Get the data
    _, compressed = image_data(png)
    raw_data = zlib.decompress(compressed)
    print('IDAT contains {} bytes of data (expected {})'.format(len(raw_data), width * height * bit_depth // 8 + height))

    # Our image is actually way bigger.
    new_height = len(raw_data) // (width * bpp // 8 + 1)
    print('Resizing image to {} x {}'.format(width, new_height))
    png[ihdr+8:ihdr+12] = new_height.to_bytes(length=4, byteorder='big')
    png[ihdr+17:ihdr+21] = binascii.crc32(png[ihdr:ihdr+17]).to_bytes(length=4, byteorder='big')
    with open(sys.argv[2], 'wb') as output:
        output.write(png)
