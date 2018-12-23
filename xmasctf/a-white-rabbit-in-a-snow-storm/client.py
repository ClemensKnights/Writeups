#!/usr/bin/python

def XOR(a, b):
    assert len(a) == len(b), 'XOR expects both inputs to have the same length'
    return [_a ^ _b for _a, _b in zip(a, b)]

# In this challenge, we are dealing with a modified DES cipher.
# In particular, the S-boxes were replaced with the identity transformation.
#
# The key schedule as well as the E- and P-boxes remain unmodified.
# An application of the Feistel function now performs the following:
#    F(x, key) = P(E(x) ^ key)
#
# If you further investigate the E-box, we can see that because the S-boxes are
# all the same, and the S-box input bits that modify the index of the result bit
# are enumerated from 1 through to 32, the original S(E(x) ^ key) collapses into
# x ^ C(key), where C is a "collapse" function that only keeps the middle four
# bits of every six bits in the input string. Therefore,
#    F(x, key) = P(x ^ C(key))

def C(x):
    assert len(x) == 48, 'Collapse function expects 48 bits of key input'
    return [x[index] for index in range(len(x)) if index % 6 not in (0, 5)]

p_box = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
         1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

def P(x):
    assert len(x) == 32, 'P-box expects 32 bits of input'
    return [x[index] for index in p_box]

def F(x, subkey):
    return P(XOR(x, C(subkey)))

# DES itself is a repeated application of these primitives, plus an additional
# initial and final permutation

initial = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
           56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
           60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]

final = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
         37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
         35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
         33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24]

def process_block(data, keys):
    assert len(data) == 64, 'DES-style cipher expects 64-bit blocks'
    assert len(keys) == 16, 'DES-style cipher expects 16 subkeys'

    # Initial permutation
    data = [data[index] for index in initial]
    
    # Split for the Feistel cipher
    left, right = data[:32], data[32:]
    
    # Perform the Feistel iterations
    for key in keys:
        result = F(right, key)
        left, right = right, XOR(left, result)

    # Merge the halves back together (inverted, because of the last swap)
    result = right + left

    # Final permutation
    result = [result[index] for index in final]

    return result


# The key schedule used by DES also uses two (selecting) permutations,
# alongside a list of pre-defined rotation values

key_schedule_initial = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
                        9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
                        62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                        13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]

key_schedule_permutation = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
                            25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
                            50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]

key_schedule_rotates = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def keys(master_key):
    assert len(master_key) == 64, 'Master key must have 64 bits'

    # Initial permutation, reduces to 56 bit
    data = [master_key[index] for index in key_schedule_initial]

    # Split in half
    left, right = data[:28], data[28:]

    # Generate keys
    keys = []
    for index in range(16):
        rotation = key_schedule_rotates[index]

        left = left[rotation:] + left[:rotation]
        right = right[rotation:] + right[:rotation]

        intermediate = left + right
        keys.append([intermediate[index] for index in key_schedule_permutation])

    return keys

def master_key_from_56(permuted_key):
    assert len(permuted_key) == 56, 'Permuted master key must have 56 bits'

    key = [False] * 64
    for index, value in enumerate(permuted_key):
        key[key_schedule_initial[index]] = value

    return key

# Encryption and decryption work the same way, only with reversed subkey order

def encrypt(data, master_key):
    assert len(data) % 8 == 0, 'Data length is not a multiple of the block size'
    result = []
    subkeys = keys(master_key)
    for block in range(0, len(data), 8):
        result += process_block(data, subkeys)
    return result

def decrypt(data, master_key):
    assert len(data) % 8 == 0, 'Data length is not a multiple of the block size'
    result = []
    subkeys = keys(master_key)[::-1]
    for block in range(0, len(data), 8):
        result += process_block(data, subkeys)
    return result

if __name__ == '__main__':
    import bitstring
    import os
    import re
    import sys
    sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captcha'))

    from pwn import *
    from sympy import symbols
    from powdb import lookup as get_pow

    HOST = '199.247.6.180'
    PORT = 16003

    tube = remote(HOST, PORT)
    print('[*] Solving proof of work')
    captcha = tube.recvline_contains(b'Give a string X')
    query = re.search(b'=([0-9a-f]{5})', captcha).group(1).decode()
    tube.sendline(get_pow(query).encode())

    print('[*] Retrieving encrypted flag')
    cipher_hex = tube.recvline_contains(b'encrypted flag')
    cipher_match = re.search(b': ([0-9a-f]{16})!', cipher_hex).group(1).decode()
    encrypted_flag = bitstring.BitArray(bytes.fromhex(cipher_match))

    def random_valid_ciphertext():
        while True:
            value = random.randrange(2 ** len(encrypted_flag))
            bits = bitstring.BitArray(value.to_bytes(length=len(encrypted_flag) // 8, byteorder='big'))
            if (bits ^ encrypted_flag).bin.count('1') >= len(encrypted_flag) // 2:
                return bits

    def query(cipher_hex):
        tube.sendline(cipher_hex)
        plain_hex = tube.recvline_contains(b'decryption')
        segment = re.search(rb'([0-9a-f]{16})\.', plain_hex).group(1).decode()
        decrypted = bitstring.BitArray(bytes.fromhex(segment))
        return decrypted

    print('[*] Building symbols')
    key_bits = symbols('k(0:56)')
    message_bits = symbols('m(0:64)')
    derived_master = master_key_from_56(key_bits[::-1])
    decryption_subkeys = keys(derived_master)[::-1]
    symbolic_solution = process_block(message_bits[::-1], decryption_subkeys)

    print('[*] Counting message bits')
    message_bit_count = [None] * 64
    for bit in range(64):
        relevant = symbolic_solution[bit].atoms()
        message_bit_count[bit] = sum(1 if sym in relevant else 0 for sym in message_bits)
    flip_bits = ''.join('1' if message_bit_count[i] % 2 else '0' for i in range(64))
    flips = bitstring.BitArray(bin=flip_bits)

    print('[*] Submitting inverted flag')
    inverted = query((~encrypted_flag).hex)
    flipped = inverted ^ flips

    print('[*] Got flag: {}'.format(flipped.bytes.decode()))


