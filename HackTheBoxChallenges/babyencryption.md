### BabyEncryption
---

#### Files
`chall.py`
```py
import string
from secret import MSG

def encryption(msg):
    ct = []
    for char in msg:
        ct.append((123 * char + 18) % 256)
    return bytes(ct)

ct = encryption(MSG)
f = open('./msg.enc','w')
f.write(ct.hex())
f.close()
```

`msg.enc`
```
6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921
```
#### Writeup

We are given a similar scenario with `sekur julius`. A source code that encrypts some message, and then the encrypted ciphertext in `msg.enc`.

We note that `msg.enc` is written in hex, meaning every two values correspond to some number from $0$ to $255$ that denotes a byte value.

We also observe that for every character in the message, the code performs a mapping $x \rightarrow 123 * x + 18$ (mod $256$), and saves the new $x$ value.

Thus, in order to reverse the encryption and derive our message, we first do a subtraction by 18 modulo 256. The hard part is doing division by 123 modulo 256, but we can do this by computing the multiplicative inverse of 123 mod 256. That is, the number $Y$ such that $Y * 123 == 1 mod 256$. This allows $Y$ to function as $1/123$ over the modulo, allowing us to perform our division by multiplying the subtracted number with $Y$.

There's many ways to compute the multiplicative inverse. In python, we can do so by doing `pow(123, -1, 256)`.

Note: We know that an inverse exists simply because $123$ and $256$ share no common factors other than $1$. we will leave proof of why `gcd(a,b) = 1` implies `a` has a multiplicative inverse mod `b` as an exercise to the reader.

With some adhoc coding, we get the flag, `HTB{l00k_47_y0u_r3v3rs1ng_3qu4710n5_c0ngr475}`.

An interesting thing to note is that `BabyEncryption` encrypts data using a `Linear Congruential Generator (LCG)`. LCGs essentially take in an input number $x$, computes $a*x + b$ mod $m$ for some parameters $a, b, m$ and returns the result. While LCGs are obviously insecure if all the parameters are known as well as the full output, in practice LCGs are used in randomness, where a truncated output is used instead of the full number. If done correctly and its outputs handled properly, the LCG can be secure*.

#### solve.py
```py
ct = "6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921"
ct = bytes.fromhex(ct)
for i in ct:
    i = (i - 18) % 256
    i *= pow(123, -1, 256)
    i %= 256
    print(chr(i), end='')
"""
Th3 nucl34r w1ll 4rr1v3 0n fr1d4y.
HTB{l00k_47_y0u_r3v3rs1ng_3qu4710n5_c0ngr475}
"""
```