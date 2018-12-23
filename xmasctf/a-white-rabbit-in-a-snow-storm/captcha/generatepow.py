#!/usr/bin/python

import hashlib
import pickle

from powdb import from_index

def _with_data(binary):
    return hashlib.md5(binary).hexdigest()[:5]

def _with_index(index):
    return _with_data(from_index(index).encode())

attempt = 0
results = {}

# Generate all options
while len(results) < 16 ** 5:
    solution = _with_index(attempt)
    if solution not in results:
        results[solution] = attempt
    print("Attempt {}, {:02.4%}".format(attempt, len(results) / 16 ** 5))
    attempt += 1

# Dump
with open('powdb.pickle', 'wb') as powdb:
    pickle.dump(results, powdb)
