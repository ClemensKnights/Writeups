#!/usr/bin/python
# This is a simple XOR stream cipher, so we need to predict the PRNG's output.
# We can obtain the first six bytes of output (the flag starts with 'X-MAS{').

import sys
if len(sys.argv) <= 1:
    print('Usage: {} <flag.enc>'.format(sys.argv[0]), file=sys.stderr)
    exit(1)

with open(sys.argv[1], 'r') as flag_file:
    encrypted_flag = bytes.fromhex(flag_file.read())

print('[*] Computing output leak...')

leaked_output = bytes(a ^ b for a, b in zip(b'X-MAS{', encrypted_flag[:6]))
unprefixed_flag = encrypted_flag[6:]

def bit(byte_data, byte_index, r_bit_index):
    return (byte_data[byte_index] & (1 << r_bit_index)) >> r_bit_index

# The PRNG's seed is 12 bytes, read from os.urandom. The first four bytes seed
# the IV, the second four the extraction key (specifying where the LFSR taps are),
# and the final four seed an XOR mask that is applied to the output.
#
# Note that the IV technically has 33 bits, but the 33rd bit does not have an impact on the
# calculated output (it never reaches the last byte during the extraction process). This does,
# however, mean that the 33rd bit is always initialized to zero, and that new bits are visible
# in the output only after one iteration.
#
# Whenever we extract a byte, the following operations take place:
#    x = iv ^ mask
#    y = x ^ (x >> 16)
#    z = y ^ (y >> 8)
#    return z & 255
#
# Then, the IV is advanced by one bit:
#    iv = (iv >> 1) | (parity(iv & key) << 32)
#
# This boils down to the following operations:
#    x = iv ^ mask = [XA XB XC XD]
#    y = x ^ [00 00 XA XB] = [XA XB (XA^XC) (XB^XD)]
#    z = x ^ [00 XA XB (XA^XC)] = [XA (XA^XB) (XA^XB^XC) (XA^XB^XC^XD)]
# and finally
#    result = z & 255 = XA ^ XB ^ XC ^ XD
# The returned value is the XOR of all bytes of the IV and the mask.
#
# Because the mask does not change when shifting, we can simplify this.
# If IV = [A B C D] and mask = [ma mb mc md], then
#    x = [(A^ma) (B^mb) (C^mc) (D^md)]
# and
#    result = (A^ma) ^ (B^mb) ^ (C^mc) ^ (D^md) = A ^ B ^ C ^ D ^ (ma^mb^mc^md)
#
# We set m* = (ma^mb^mc^md) = const, and index the bits s32..s0 in the state and m7..m0 in m*.
# Within the leaked PRNG outputs r0 through r6, we also label the bits (e.g. r07..r00).
# For r0, this gives
#    s0 ^ s8 ^ s16 ^ s24 ^ m0 = r00
#    s1 ^ s9 ^ s17 ^ s25 ^ m1 = r01
# and analogous equations for r02 through r07.
# After shifting (s0 is removed from the bitstring, and s33 inserted in the front),
# we obtain the values for r1:
#    s1 ^ s9 ^ s17 ^ s25 ^ m0 = r10
#    ...
# It is obvious that r01 ^ r10 = m0 ^ m1 (and analogous r02 ^ r11 = m1 ^ m2, etc.)
# We can therefore limit our search for m* to two possibilities, one of which is the
# bitwise inverse of the other.

print('[*] Determining masks (m*)...')

zero_mask = '0'
one_mask  = '1'
flip = lambda bit: str('10'.index(bit))
for last in range(1, 8):
    if bit(leaked_output, 0, last) != bit(leaked_output, 1, last - 1):
        # Flip the last bit before adding it
        zero_mask = flip(zero_mask[0]) + zero_mask
        one_mask  = flip(one_mask[0]) + one_mask
    else:
        # Keep the bit
        zero_mask = zero_mask[0] + zero_mask
        one_mask  = one_mask[0]  + one_mask
zero_mask = int(zero_mask, 2)
one_mask  = int(one_mask, 2)

masks = [zero_mask, one_mask]

# We index the unmasked bits analogous to r: d(n) is the n-th output byte, d(n)[0] its LSB.
# After each shift from s(n) to s(n+1), the generated output byte d(n+1) differs from d(n) as follows:
#    d(n+1)[k] = d(n)[k+1] for k < 7
#    d(n+1)[7] = d(n)[0] ^ s(n)[0] ^ s(n)[32]
#              = d(n)[0] ^ s[n] ^ s[32 + n]
# Only the MSB of d(n+1) is affected by values we cannot compute from previous stages.
# Since we know that the MSB of each character in the output is 0 (printable ASCII flag), we can also
# compute the MSB of d(n+1).
for mask in masks:
    print('[*] Attempting to use mask {}...'.format(mask))

    flag = []
    xor_state = mask ^ leaked_output[-1]
    for byte in unprefixed_flag:
        # Unmask the byte
        unmasked = mask ^ byte
        # Take the MSB so that MSB(unmasked ^ xor_state) = MSB(flag) = 0
        msb = unmasked & 0x80
        # Update the state
        xor_state = (xor_state >> 1) | msb
        # Compute the flag byte
        flag.append(unmasked ^ xor_state)
    flag = bytes(flag)

    # Dump the flag
    try:
        print('X-MAS{' + flag.decode())
        break
    except:
        print('[x] Failed to decode flag')


