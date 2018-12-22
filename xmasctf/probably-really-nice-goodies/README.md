# Probably Really Nice Goodies from Santa

### X-MAS CTF 2018, Crypto [460]

> Everybody knows that Santa loves sharing! Of course, you should Probably be Really Nice with your friends to get any Goodies from him.

As the title and description already hint, this challenge is accompanied by a [LFSR](https://en.wikipedia.org/wiki/Linear-feedback_shift_register) pseudo-random number generator implemented in Python, and the encrypted flag (which is obtained by simply XOR'ing each byte of the flag with subsequent outputs from the LSFR).

Because we know that the flag starts with `X-MAS{`, we can obtain the first six bytes of the PRNG's output.

Unlike traditional LFSRs, this implementation extracts one entire byte at a time by XOR'ing the internal state `i` with a random but constant (i.e. part of the seed) mask `m`, and then computing

    x = i ^ m
    x ^= (x >> 16)
    x ^= (x >> 8)
    output = x & 0xFF

Even though the state is technically 33 bits long, this only extracts the lowest 32 bits from the state. XOR'ing those four bytes gives us the PRNG's output that is used in the stream cipher:

    x = i ^ m
    output = x[31:24] ^ x[23:16] ^ x[15:8] ^ x[7:0]


#### Finding the mask `m`

We can rewrite this equation to simply finding `m`:

    output = (i[31:24] ^ m[31:24]) ^ \
             (i[23:16] ^ m[23:16]) ^ \
             (i[15:8]  ^ m[15:8])  ^ \
             (i[7:0]   ^ m[7:0])

and finally

    output = (i[31:24] ^ i[23:16] ^ i[15:8] ^ i[7:0]) ^ \
             (m[31:24] ^ m[23:16] ^ m[15:8] ^ m[7:0])

We set `M = m[31:24] ^ m[23:16] ^ m[15:8] ^ m[7:0]`. Because `m` never changes (it is only set when seeding the PRNG), neither does `M`, and we only need to solve for that.

Let us look at how `M` influences the PRNG's outputs across a shift in the LSFR. We will call the first output `o0` and the second output `o1`. In this system, `i` denotes the state used to generate `o0` (i.e. before the shift right):

    o0[0] = M[0] ^ (i[0] ^ i[8] ^ i[16] ^ i[24])
    o0[1] = M[1] ^ (i[1] ^ i[9] ^ i[17] ^ i[25])
    # ...

    o1[0] = M[0] ^ (i[1] ^ i[9] ^ i[17] ^ i[25])
    # ...

We can see that the bits of the second output are generated from exactly the same state bits as the bits of the first output. Because of the shift operation, they shift _behind the mask_ - the output bits should stay the same (except of course being shifted), unless the mask bits in those locations are different.

From this, we get `M[1] ^ M[0] = o0[1] ^ o1[0]` and analogous relations up to `M[7] ^ M[6]`. This leaves us with exactly two different options for `M`, which we can simply try out later. That's an enormous improvement over the 32 bits of randomness we had for `m` at the start!

#### Simulating the LSFR

Knowledge of `M` is not enough to reconstruct the entire LSFR state `i`, of course. Thankfully, we do not need to do that. As we saw earlier, each shift operation also shifts the (un-masked) output value. If we label these unmasked outputs `u0` and `u1` (again `i` is the initial state), we see:

    u1[k] = u0[k + 1]              # for k < 7
    u1[7] = u0[0] ^ i[0] ^ new_bit # Removes the state's LSB, and adds the newly shifted bit

Of course, we do not know the value of the newly-shifted bit, because we do not know the locations of the taps in the LFSR (those are also randomly seeded), and we do not have enough output to recover them using Berlekamp-Massey.

Luckily, predicting `u1[7]` after every shift is enough to recover the full output sequence to decrypt the flag. Ultimately, our encrypted flag byte `c` is obtained from the plaintext byte `p` through

    c = p ^ M ^ u

We know `M` and `c`, but we _also_ know that `p[7] = 0` - our flags are all ASCII strings, in which the most significant bits are never set. Then `u[7] = p[7] ^ M[7]`, and we have the full output ready for the next shift.

Replaying the LFSR in this fashion allows us to recover the flag:

    X-MAS{S4n7a_4lw4ys_g1ve5_n1c3_pr3s3n7s}

