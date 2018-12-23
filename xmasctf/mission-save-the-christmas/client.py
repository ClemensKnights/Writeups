#!/usr/bin/python

if __name__ == '__main__':
    import bitstring
    import itertools
    import os
    import re
    import subprocess
    import time

    from pwn import *

    HOST = '199.247.6.180'
    PORT = 18000

    tube = remote(HOST, PORT)

    print('[*] Solving stage 1 (Riddle)')
    tube.sendline('secret')

    print('[*] Solving stage 2 (Hashes)')

    if not os.path.exists('hashes'):
        print('[*] Bruteforcing hashes (C++)')
        os.mkdir('hashes')
        if not os.path.exists('generate-table'):
            subprocess.check_output(['g++', '-Ofast', '-openmp', '-march=native', 'generate-table.cc', '-o', 'generate-table'])
        subprocess.check_output([os.path.abspath(os.path.join(os.path.dirname(__file__), 'generate-table')), 'hashes'])

    tube.recvline_contains(b'Anyway here are the hashes')
    hashes = [int(tube.recvline().strip(b'\n')) for _ in range(10)]

    plain = []
    for h in hashes:
        entry = subprocess.check_output(['grep', '-hir', '--', str(h), 'hashes/']).strip().decode()
        plain.append(entry.split()[1])

    for user in plain:
        tube.sendline(user)
        time.sleep(0.1)

    print('[*] Solving stage 3 (Reindeers)')
    line = tube.recvline_contains(b'You should send me').decode()
    modulus = int(re.search('%\s+(\d+)', line).group(1))
    value = (17 * (666013 ** 3)) % modulus
    tube.sendline(str(value).encode())

    print('[*] Solving stage 4 (Image Forensics)')
    tube.recvline_contains(b'pasteboard.co')
    tube.sendline(b'sternocleidomastoidian')

    print('[*] Solving stage 5 (Merry Christmas)')
    tube.recvline_contains(b'pasteboard.co')
    tube.sendline(b'this_is_not_a_red_herring')

    tube.interactive()
