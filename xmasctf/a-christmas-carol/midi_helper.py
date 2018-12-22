#!/usr/bin/env python3

import argparse

from difflib import SequenceMatcher

def longest_match(string1, string2):
    match = SequenceMatcher(None, string1, string2).find_longest_match(0, len(string1), 0, len(string2))
    return(string1[match.a: match.a + match.size])


def convert_midi_to_easy(content):
    content = content[0x18:-10]  # remove header and footer
    content = content.replace(b'\x00', b'')
    content = content.replace(b'\x14', b'')
    content = content.replace(b'\x64', b'')
    content = content.replace(b'\x80', b'')
    content = content.split(b'\x90')[:-1]
    return content


def read_to_bytes(filename):
    with open(filename, "rb") as midifile:
       content = midifile.read()
    return convert_midi_to_easy(content)


def compare_files(file1, file2):
    c1 = read_to_bytes(file1)
    c2 = read_to_bytes(file2)
    return longest_match(b"".join(c1), b"".join(c2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs='+')
    args = parser.parse_args()
    if len(args.file) == 2:
        print(compare_files(args.file[0], args.file[1]))
    elif len(args.file) == 1:
        print(read_to_bytes(args.file[0]))
    else:
        print("No idea what to do!")
