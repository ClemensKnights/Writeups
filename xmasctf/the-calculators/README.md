# The Calculator / The Calculator 2.0

### X-MAS CTF 2018, Pwn [495, 497]

 Greetings! These challenges exhibit a typical Pwn setup consisting of a 64-bit ELF binary for each challenge running on the CTF's servers when a client connects to a specific port.

> Here is some strange calculator that is used by Elves, but it seems very poorly implemented. Could you take a look if it is secure?
>
>Download [chall](https://drive.google.com/open?id=1oQyh1R8cJAg_uo6aEJrehGT2Mz_SvXdn)
>
>Running on: nc 199.247.6.180 10008
>
>Author: littlewho

>I know you pwned it last time, but it was too easy. Could you give it another shot?
>
>Download [chall](https://drive.google.com/open?id=1QOJu-5lOXbyT3Dg_XqJgGmgUUZrpIiD4)
>
>Running on: nc 199.247.6.180 10009
>
>Author: littlewho


#### The functionality

Even though I'm writing about two challenges in this report, the binaries are extremely similar, with one enhancement added in the second one that shrinks the window of vulnerabilities exposed in the first one. Therefore, I am going to first describe the things that both binaries have in common, followed by the vulnerability and exploit of the first challenge (which does not work for the second challenge) and the vulnerability and exploit of the second challenge (which can be applied to the first challenge as well).

Both binaries provide a basic software calculator implementation, whose operations get their operands from a stack-like memory pool and keeping a top-of-stack index pointing to the next available slot in the memory pool. The calculator gets its inputs by parsing a user input string to extract the operands (that must be encoded in decimal representation) and the symbols corresponding to the operations. The input string can be 31 bytes long and for each connection we are given 45 rounds, i.e. we can send 45 input lines to the calculator for computing. The calculator also provides two registers, let's call them `register1` and `register2`, for keeping two 64-bit values persistent across rounds. For each operation, the calculator takes its operands from the last two positions of the memory pool, while the result is written back on the last position of the memory pool, overwriting the last inserted element.  

The operators supported by the calculator:
 * `#` &rarr; loads the last inserted operand into `register1`
 * `!` &rarr; stores `register1` into the next available memory slot
 * `$` &rarr; loads the last inserted operand into `register2`
 * `@` &rarr; stores `register2` into the next available memory slot
 * `+` &rarr; adds the last two operands from the memory pool
 * `-` &rarr; subtracts the last two operands from the memory pool
 * `>` &rarr; high compares the previous to last operand with the last operand
 * `<` &rarr; low compares the previous-to-last operand with the last operand
 * `=` &rarr; compares the equality of the last two operands

Immediately after the program reached the `main` function, it reads in the `flag` from the local filesystem and keeps it on the stack. Each input line that a client sends is stored on the stack, in a 32 byte buffer, that comes right before the flag and terminates with a `\0` on the 31st position (counting started from zero). We shall call it `buf` from now on. The memory pool where the calculator operands are taken from is also kept in the main's stack, before our input line buffer, and has a size of 1024 byte. Oddly enough, the program draws a random number between `-500000` and `500000` (boundaries included), and saves the address of the buffer indexed with this random value in a variable on the stack (`rand_stack_ptr = &buf[rand_value]`). The random stack pointer is stored one position before the operands memory pool on the stack.

#### The vulnerability

Further in the execution flow, after the calculator performed the operations and returned to main for a new round, a wild `printf(buf)` is executed, where `buf` our controlled input line. Here's the principal vulnerability in both programs. The techniques we implemented to exploit them are different for each of the two challenges. Before describing the exploit, it is worth mentioning that the binaries employed input validation on the string buffers that we are sending. They do not allow for any format specifiers other than `%X$n`, where `X` is a natural number used in conjunction with `$` specifying the Xth parameter of printf that the corresponding format is applied to. Therefore, we cannot use the vulnerability to leak the flag from the stack, but only to write (but where?). Remember our controlled `buf` that was lying on the stack before the `flag` buffer? These two are only separated by a `\0`. That means, if we could write a printable character at `buf[31]` and overwrite the null character, `buf` and `flag` will merge into a single printable string making `printf(buf)` leak the flag (credits to `@manu`). Another crucial artifact was that the program loads at the start of its execution the address of `buf` into `register2`, so that we can use it later as an calculator operand (credits to `@Watergun`). For both challenges, the exploit was a matter of somehow getting the address of the 32nd byte of the input buffer on the stack. Then we could use it against itself when printf is called so that a `\t` overwrites the `\0` separating the buffer from the flag. Since we can use the address of buf in the operands memory pool, and since the memory operands pool lies in the main's stack, we only need to use some `%X$hhn` to trigger the write to the address found on the Xth position of printf's argument list which is an address that points to our target byte. This includes the 6 register, the first stack position that stores the `i` used to count the rounds, the random stack pointer and then the operands memory pool.

#### Exploiting *The Calculator*

When the program finished validating our input string, it calls the calculator where we already have the address of `buf` in `register2`. Therefore, we use the `@` symbol to store it into the operands memory pool. As a second operand we use the value `31` and then trigger an addition with the `+` symbol. This operation writes the value of `&buf+31` to the second position in the memory operands pool, which is at position 9 in the printf arguments list. Therefore, when the program returns to main from the calculator, the `printf(buf)` is called, which writes 9 bytes to stdout, and when it reaches `%9$n` the value `\x09` is written at `buf[31]`. In the next round, we send a bunch of random characters in `buf` to fill in the first 31 bytes and when printf is called, the flag is leaked, since buf is not null-terminated anymore, and the flag follows it immediately.

#### Exploiting *The Calculator 2.0*

Even though there are only minor differences between the two challenges, the exploit for the first challenge doesn't work on the second challenge. The author patched the binary to prevent the program from using the value stored in `register2` in any calculator operations involving `+` or `-`. Nevertheless, we discovered that the calculator can be triggered to compute even when only one operand has been inserted into the operands memory pool. The program doesn't check if it has at least two operands in the memory pool before executing the operation. Therefore, if the program receives an operand and then an operator, one of the calculator operands will be the element found immediately before the memory pool, outside of its lower bounds. Remember which one was that was? Indeed, it was the `random stack pointer`. The program doesn't allow us to use `register2` (which stores the address of buf) in any calculator operations involving `+` or `-`, but it doesn't do so for `>` or `=`. Therefore, we could use the random stack pointer and the address of buf as operands and try to guess the random offset between the two. This can be achieved by performing a series of equality checks and comparisons in a binary-search like fashion. The random value used to set the random stack offset is chosen in the beginning of the program between -500000 and 500000 (including the boundaries). Therefore, we choose as our first binary search median the value `262144` which is the nearest power of two to our limits. We are allowed to execute 45 rounds. The random offset can be found in 19 binary search steps, since the initial median equals 2**18. Each binary search step is performed on the random stack pointer and the address of the buf, meaning that we make use of the lack of checks on the number of operands, which allows us to access the random stack pointer. The strategy at each binary search step is the following:
  1. we first subtract our (so called) `guessed_offset` from the random stack pointer, then we check if the resulted value equals the address of the buf; if it does, then we found the random offset
  1. if they are not equal, we compare the two operands; if the subtracted random stack pointer is greater than the address of the buf, we divide the current median by two and add it to our guessed_offset; if it is smaller, then we subtract the divided median from our guessed_offset; we continue with another round (jump back to 1.)

As said before, in the worst case scenario, the algorithm will perform in 18 binary search steps, which implies 36 rounds in the program, since we need 2 checks for each step. The algorithm is guaranteed to find the correct offset since the binary search needs at most 36 rounds, and we get 45 rounds from the program. Our first guessed_offset is 262144 and we need to make an initial comparison to check weather the random stack pointer is bigger or smaller than the buf address. From that point on, our algorithm adds the guessed_offset in case the initial random stack pointer is smaller than the buf, and subtracts otherwise. After we found the offset between our target and the random stack pointer, we use the technique described in the first challenge, but we adjust the random stack pointer this time to obtain the same value as the address of buf. Then we use it as operand to add the offset 31 and point it to buf[31], which we'll overwrite with a `\t` and leak the flag.

#### Flags

> X-MAS{7h15_15_4_v3ry_7r1cky_c4lcul470r}

>

#### Conclusions

* Beware of where you keep your sensitive data into memory
* Don't allow for user controlled format strings
* Check the bounds of your operator's lists
