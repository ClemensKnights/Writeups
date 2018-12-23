# A black rabbit in the dark

### X-MAS CTF 2018, Crypto [497]

> After retrieving the first string Santa Claus found out that there exists a string made by the same author that ended up in the same situation. Now Santa needs your help again!

This challenge very closely resembles [_A white rabbit in a snow storm_](https://github.com/ClemensKnights/Writeups/tree/master/xmasctf/a-white-rabbit-in-a-snow-storm). Again, we are provided with a modified DES implementation, and a web server protected by the same captcha method (note that in order to run the exploit attached here, you should copy the captcha solver from that challenge).

However, this time we encounter a full-fledged encryption oracle on the server:

    Ok, you can continue, go on!
    The key will be the same for all the encryptions during this session!
    You can do at most 512 encryptions every session.
    Here's the encrypted flag: 5a6fdf690f9f7f6a634c6eb6bd9eef44072085bca184d942664345adb931379f8c7fa90e8946d19185fb627196a6d35152694097b4b6e1586d57d170a50b24959bc75b5dc979b31aa6fe7f66c5fb2bd798fc6c778493e46ea6c7727ef2f22bc61b4a487fb4244f47!
    Here's the encryption oracle!
    
    Provide a string you want to encrypt as hex input:
    (the string has to be 8 bytes long)

This time, the S-boxes in our modified DES algorithm are correct this time, but the E-box is modified, and the final permutation after each round (P-box) is not applied at all. The modifications mean that the nonlinearity introduced by the S-boxes is never scrambled across the nibbles (4-bit blocks) that result from each S-box. Within one eight-byte block, each pair of nibbles between the half-blocks is independent from the rest (corresponding nibbles in each half-block _are_ interdependent because they are XOR'd after every round):

    # Interdependent nibbles in a 8-byte block
    f e d c b a 9 8    7 6 5 4 3 2 1 0
    |_|________________| |
      |__________________|    ...

If we remove the permutations introduced by DES at the very start and end of the processing (they are trivially invertible, and essentially exist only to support processing on hardware contemporary to DES), this means that if two blocks share the same combination of nibbles at some position (e.g. nibbles 0 and 8 are the same in both blocks), then so will be the nibbles in the (un-permuted) ciphertext.

By having the server encrypt all hexadecimal inputs of the form `xxxxxxxxyyyyyyyy` (where `x` and `y` are arbitrary hexadecimal characters), we obtain the ciphertext representations of each possible pair of nibbles `xy` in each position across the ciphertext to build a dictionary. This takes 256 requests, only half of the limit given by the challenge.

We then remove the permutation on the encrypted flag's blocks and look up each nibble pair in the dictionary, which yields the corresponding nibbles in the (permuted) flag plaintext. Then we also invert the initial permutation and obtain the flag:

    X-MAS{If_y0u_r3m0ve_th3_av4l4nch3_3ff3c7_th3n_4_bl0ckc1ph3r_1s_vuln3r4ble_t0_st4tis7ic4l_an4lys1s!!!!!!}

