# A white rabbit in a snow storm

### X-MAS CTF 2018, Crypto [482]

> If you didn't know Santa also visits sometime the Hell's Kitchen! He saw a while ago this beautiful pirece of art, a string called A white rabbit in a snowstorm. But it seems something happend to the string, it got encrypted! Help him decrypt the flag so he can enjoy it's beauty again!

Attached is the Python script used to encrypt the flag. Some quick research reveals that it is a modified version of [this DES implementation](https://github.com/RobinDavid/pydes/blob/master/pydes.py).

On the server, we find a (captcha-"protected") partial decryption oracle. The captcha requires us to solve a small proof-of-work:

    CAPTCHA!!!
    Give a string X such that md5(X).hexdigest()[:5]=0e840.

Of course, a lookup table for all possible values is built relatively quickly, so that we don't have to repeatedly solve these captchas - especially as the same mechanism is also used in other challenges. The `captcha` folder has the scripts needed to generate and query the table. Before running the client for this challenge, make sure to generate the table using the `captcha/generatepow.py` script. Then, the `powdb` module allows you to query for captcha solutions - both interactively and from Python.

After solving the captcha, we are provided with the encrypted flag and a partial decryption oracle that will decrypt any message where at least half of the ciphertext bits differ from the flag:

    Ok, you can continue, go on!
    The key will be the same for the encryption and all decryptions during this session!
    Here's the encrypted flag: 3b8f42dda5f88553!
    Here's the partial decription oracle!
    
    Provide a 8-byte string you want to decrypt as hex input:
    (the string has to have at least half of the bits different from the ciphertext)

As mentioned before, the algorithm that was used in this challenge is not pure DES. In comparison to the textbook version described [on Wikipedia](https://en.wikipedia.org/wiki/Data_Encryption_Standard), the E-box (an initial permutation-and-expansion on the half-block input to each round) is modified, but more damning are the missing S-boxes. Normally, this nonlinear transformation scrambles the bits enough to make DES somewhat secure against trivial attacks. Here, however, they were replaced with the identity transformation.

This means that in each round, the input half-block was only permuted in a predictable fashion and XOR'd with the relevant subkey - a trivial linear system. Using `sympy`, we can directly compute each ciphertext bit as an XOR of a set of plaintext bits and key bits.

In theory, this would now allow us to recover the key by solving a bunch of linear equations in GF(2) using an arbitrary plaintext / ciphertext pair, but here, we can pick the ciphertext sent to the decryption oracle.

We invert each bit in the encrypted flag and submit that as our ciphertext. Then, the XOR relations discovered in the previous step mean that the output bit is the flag's plaintext bit if there is an even number of message bits in the ciphertext bit (the bit flips cancel each other out), or the inverse if there is an odd number.

After flipping the appropriate bits, we obtain the flag (which as per the challenge notes must be wrapped in `X-MAS{...}`:

    X-MAS{Sb0xd3s!}

