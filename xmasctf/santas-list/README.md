# Santa's List

### X-MAS CTF 2018, Crypto [286, 328]

Santa's List and Santa's List 2.0 were two challenges solvable with the exact same algorithm (the challenge was re-released with a limit on the number of requests).

> Santa's database got corrupted and now he doesn't know who was nice anymore... Can you help him find out if Galf was nice?

> Santa's MechaGnomes caught up to some intense traffic on their servers so they decided to modify santa's database server to be DDoS-proof but it still is corrupted, find out if Galf was nice or not but try not to DDoS the server.

The server allows you to encrypt and decrypt arbitrary data with Santa's (textbook) 1024-bit RSA key, and freely gives you the results. The task is to decrypt the RSA-encrypted flag sent by the server at the start of the challenge.

If the message to decrypt is the encrypted flag, or if the decrypted text is a multiple of the flag or of _any_ of the previously encrypted messages, you cannot obtain the result.

Chosen-ciphertext attacks on textbook RSA are well-documented: For a ciphertext `c` send `(k ** e) * c mod n` to the server for decryption, and receive `k * m`. Unfortunately, this runs into two problems: We know neither `n` nor `e`, _and_ the server will not send us `k * m` because it is a multiple of the flag.

##### Finding the public key

We can find the public key exponent `e` by looking at the server code. It uses PyCrypto to generate the key (`RSA.generate(1024)`), [whose documentation](https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html#generate) reveals that by default `e = 65537`.

We let the server encrypt a number of (random) messages. For each message, we know `m ** e = k * n + c`, and therefore `m ** e - c = k * n = r`. If we do this for a bunch of messages (the provided code uses three messages to keep the computing time low and to stay under the limit of five requests on Santa's List 2.0), we can compute the GCD of all the `r`s obtained to get `n` with some fairly high probability. Just to be sure, we remove common low factors from the result. This is not entirely failsafe, if you get garbage results, just re-run the script.

##### Decrypting the flag

We cannot build an exploit in such a way that the server would send us a trivial multiple of the flag. However, as soon as `k * m > n` the divisibility check on the server side will also not trigger.

We simply compute the multiplicative inverse of 2 modulo `n`, have the server decrypt our "halved" flag, double the result, and obtain the flag:

    X-MAS{N1c3_bu7_chr1s7m4s_is_n0t_ab0u7_g1f7s_17_1s_ab0u7_fl4gs}
    X-MAS{n4ugh7y_dd0s_pr073c710n_1sn7_h4rd_r1gh7?}


