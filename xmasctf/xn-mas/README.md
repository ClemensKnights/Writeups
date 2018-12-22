# X^n-mas

### X-MAS CTF 2018, Crypto [383]

> Crypto mecha gnomes love random *polynomial* functions, can you guess what’s hidden in there?

The server allowed you to query up to 50 points on a polynomial, relative to a modulo selected by the server:

    Hello to the most amazing Christmas event. The X^n-Mas!
    You can send at most 50 requests to the server.
    The modulo is 1705110751. Good luck!
    Enter an integer:

The problem can be solved using Langrange interpolation in the finite field specified by the modulo.
Sage provides an implementation, but a direct Python version is also available [courtesy of an anonymous
StackOverflow user](https://stackoverflow.com/a/48067397), and attached to this writeup as `gf_poly.py`. 

`client.py` reads 50 (x, y) pairs on the polynomial, and solves for the coefficients. Decoding the coefficients yields the flag:

    X-MAS{W3_w1sh_you_4_m3rry_Christmas}
