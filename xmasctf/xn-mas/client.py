#!/usr/bin/python

from pwn import *
import gf_poly

ATTEMPTS = 50

class Client:
    def __init__(self, host, port, max_queries=50):
        self._limit = max_queries
        self._host  = host
        self._port  = port
        self._ctr   = 0
    def _close_comm(self):
        self._comm.close()
    def _init_comm(self):
        self._comm  = pwnlib.tubes.remote.remote(self._host, self._port)
        self.modulo = int(re.search('(\d+)', self._comm.recvline_contains(b'modulo').decode()).group(1))
    def query(self, number):
        if self._ctr == 0:
            self._init_comm()
        self._ctr += 1
        self._comm.sendline(str(number).encode())
        value = int(re.search('(\d+)', self._comm.recvline_contains(b'output').decode()).group(1))
        if self._ctr >= self._limit:
            self._close_comm()
        return value

def build_poly(mod, kvpairs):
    K = gf_poly.GF(mod)
    X = [[kvp[0]] for kvp in kvpairs]
    Y = [[kvp[1]] for kvp in kvpairs]
    interpolated = gf_poly.interp_poly(X, Y, K)
    return interpolated

if __name__ == '__main__':
    HOST = '199.247.6.180'
    PORT = '16000'

    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-t', '--target', help='The target host and port', metavar=('HOST', 'PORT'), nargs=2, default=(HOST, PORT))
    args = p.parse_args()

    client = Client(*args.target)
    observations = []
    for i in range(ATTEMPTS):
        observations.append((i, client.query(i)))
    poly = build_poly(client.modulo, observations)
    print(bytes(int(coefficient[0]) for coefficient in poly if len(coefficient) > 0).strip(b'\x00').decode())

