#!/usr/bin/python

import os
import random
import sys

import gmpy2

from pwn import *

def random_bytes(byte_count, banned=b''):
    while True:
        value = random.randrange(256 ** byte_count).to_bytes(length=byte_count, byteorder='big')
        if all(v not in banned for v in value):
            return value
def random_printable_str(byte_count):
    res = ''
    for _ in range(byte_count):
        res += chr(random.randrange(0x33, 0x7F))
    return res

class Client:
    def __init__(self, host = None, port = None):
        self.comm = pwnlib.tubes.remote.remote(host, port)
        galf = self.comm.recvline_contains(b'Galf').strip().split(b' - ')[1].decode()
        galf_cleaned = ''.join(char for char in galf if char in '0123456789abcdefABCDEF')
        self.encrypted_flag = bytes.fromhex(galf_cleaned)
        self.encrypted_flag_value = int.from_bytes(self.encrypted_flag, byteorder='big')
        self._wait()
        
    def _wait(self):
        self.comm.recvline_contains(b'[3] Exit')

    def encrypt(self, message):
        assert isinstance(message, str), 'Can only send strings'
        assert '\n' not in message, 'No newlines allowed'
        self.comm.sendline(b'1')
        self.comm.sendline(message)
        value = int(self.comm.recvline_contains(b'Encrypted: ').split(b': ')[1].decode())
        raw = value.to_bytes(length=128, byteorder='big')
        self._wait()
        return value, raw

    def decrypt(self, **kwargs):
        if 'raw' in kwargs and 'value' not in kwargs and isinstance(kwargs['raw'], bytes):
            value = kwargs['raw'].to_int(byteorder='big')
        elif 'raw' not in kwargs and 'value' in kwargs and isinstance(kwargs['value'], int):
            value = kwargs['value']
        else:
            raise ValueError('Must specify raw=bytes(...) ^ value=int(...)')
        self.comm.sendline(b'2')
        self.comm.sendline(str(value).encode())
        line = self.comm.recvline_regex('(Ho, ho, no)|(Decrypted)')
        if b'Ho, ho, no' in line:
            raise ValueError('Ho, ho, no...')
        result = int(line.split()[1])
        raw = result.to_bytes(length=128, byteorder='big')
        return result, raw

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-t', '--target', help='The target host and port', metavar=('HOST', 'PORT'), nargs=2, default=('199.247.6.180', '16001'))
    args = p.parse_args()

    client = Client(*args.target)

    # Obtain the public key
    # Based on how the key was generated, we know e = 65537
    e = 65537
    # Given:
    #     m_1^e ~= c_1 mod n
    #     m_2^e ~= c_2 mod n
    #     ...
    # Trivially, m_i^e = k_i * n + c_i, and therefore
    #     m_i^e - c_i = k_i * n
    #     gcd(m_i^e - c_i, m_j^e - c_j) = gcd(k_i, k_j) * n = r_ij
    # Since all r_ij are divisible by 2,
    # Set r_ij = gcd(k_i, k_j) * n
    # With enough messages, we compute g = gcd(r_ij) over all i, j and very likely g = n.
    print('[*] Recovering n: Generating message pairs')
    N_DET_SZ = 3
    m_ = []
    c_ = []
    for i in range(N_DET_SZ):
        message = random_printable_str(128)
        value, _ = client.encrypt(message)
        m_.append(int.from_bytes(message.encode(), byteorder='big'))
        c_.append(value)
    print('[*] Recovering n: Computing GCDs')
    r_ = []
    for i in range(N_DET_SZ):
        for j in range(i):
            v_i = pow(gmpy2.mpz(m_[i]), e) - c_[i]
            v_j = pow(gmpy2.mpz(m_[j]), e) - c_[j]
            r_ij = gmpy2.gcd(v_i, v_j)
            if r_ij.bit_length() < 500:
                print('[!] Failed to recover n (r_ij too small)')
                exit(1)
            r_.append(r_ij)
    print('[*] Recovering n: Computing n')
    n = r_[0]
    for i in range(1, len(r_)):
        n = gmpy2.gcd(n, r_[i])
    for i in range(1, 1000):
        # Sanity check
        if n % i == 0:
            n //= i
    if n.bit_length() < 500:
        print('[!] Failed to recover n (n too small)')
        exit(1)

    # Now that we have n and e, try to decrypt the flag
    # The naive approach of trying to decrypt C' = k^e C doesn't
    # work here, because after decryption, M' % M == 0 (which the
    # server verifies at least for the flag). However, this check
    # is not performed modulo n.
    print('[*] Decrypting flag: Preparing challenge')
    inv = gmpy2.invert(2, n)
    fac = gmpy2.powmod(inv, e, n)
    cprime = (fac * client.encrypted_flag_value) % n
    mprime, _ = client.decrypt(value=int(cprime))
    print('[*] Decrypting flag: Unpacking response')
    m = (2 * mprime) % n
    flag = int(m).to_bytes(length=128, byteorder='big')
    try:
        print(flag.strip(b'\x00').decode())
    except:
        print('[!] Decoding failed')
        print(flag)
