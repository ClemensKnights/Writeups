#!/usr/bin/env python3

import subprocess
import string

import midi_helper

chars = string.printable

front_pad = "X-MAS{"
back_pad = "}"

def make_flag(c):
    return front_pad + c.ljust(32, "A") + back_pad

# testflag = "4_n07_50_u5u4l_chr157m45_c4r0l"
testflag = ""
while len(testflag) < 32:
    matches = []
    for c in chars:
        with open("tmpflag", "w+") as f:
            f.write(make_flag(testflag+c))
        subprocess.check_call(["./encoder.exe", "tmpflag", "tmpflag.mid"])

        longest_match = midi_helper.compare_files("tmpflag.mid", "flag.mid")

        matches.append((len(longest_match), c))

    matches.sort()
    best_ratios = [i for i in matches if i[0] == matches[-1][0]]
    if len(best_ratios) == 1:
        next_char = best_ratios[0][1]
    else:
        print(matches)
        next_char = input("Please select the most plausible char: ").strip()
    testflag = testflag + next_char
