#!/usr/bin/python
import os
import pickle

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'powdb.pickle'), 'rb') as dbfile:
    db = pickle.load(dbfile)

def from_index(index):
    alpha_min = 0x21
    alpha_max = 0x7E
    alpha_sz = alpha_max - alpha_min + 1

    length = 0
    while index >= pow(alpha_sz, length):
        index -= pow(alpha_sz, length)
        length += 1

    data = b''
    for _ in range(length):
        data = bytes([alpha_min + (index % alpha_sz)]) + data
        index //= alpha_sz

    return data.decode()

def lookup(hexvalue):
    if hexvalue not in db:
        return None
    return from_index(db[hexvalue])


if __name__ == '__main__':
    while True:
        hexvalue = input('hex> ')
        solution = lookup(hexvalue)
        if solution is None:
            print('Unknown')
            continue
        print(solution)
        print('\x1b[32m' + '^' * len(solution) + '\x1b[0m' + ' ({} characters)'.format(len(solution)))
            
