1. Look at flag.mid and generate a ton more midi files with encoder.exe
2. Try to reverse it and fail because I can't reverse
3. Use some generated tmpflag.mid files with AAAA and AAAB and find out they have a long match
4. Write a semi-automatic brute-forcer:

We take the MIDI-File and strip all unnecessary information from it. Then there's only the stuff that represents the encoded data.
If we now take 2 MIDI-Files and strip them with midi_helper.py, we can find out how similar they are by computing the longest matching substring.

So let's bruteforce this character by character. For each character `<X>` we try to encode X-MAS{`<known><X><pad>`} and match it with the data from flag.mid
Then we show the user all characters with the highest score, such that he can select the best match based on intuition. The flags all build sentences, so that's quite easy for a human. In the end we need around 5-6 guesses.

So by running flag_bruter.py we can find the flag: X-MAS{4_n07_50_u5u4l_chr157m45_c4r0l}

