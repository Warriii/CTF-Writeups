### I Luv Linear 🩸 | 28 Solves 939 Points
```
I heard matrices are cool

Author: Ariana
```

`chal.py`
```py
import random
flag = input().encode()
assert len(flag)==32

def enc(pt):
    random.seed(0)
    ct = int(pt.hex(),16)
    for _ in range(100):
        ct ^= ct>>random.randint(1,32)
    return bytes.fromhex(hex(ct)[2:])

assert enc(flag)==b'n\xb2t"l(cWp\x8c\x83\xb3\xc5\xee\x98T\x0e\xceI&\x83\xe9ZZ7uvFf\x88\xdcz'
```

In contrast to the previous challenges we get a relatively shorter one :D

It looks pretty simple, using Python's random library it obtains 100 randon values from 1 to 32, and given a ciphertext `ct`, which would initially be set to the flag, xors it with itself bit shifted by that random value.

100 times of that later, it outputs the encrypted flag which turns out to be that exact bytestring.

We can easily use the same random seed of 0 and reproduce the exact 100 random values used in that order, but recovering the flag is not so easy.

### Simply Bit Shifting is Insecure!

This encryption method is insecure in that it uses `>>`. As `>>` just shifts the value to the right and doesnt have them come in from the left like rotations such as `rotr()`, every `ith` bit in the encrypted output can only be affected by itself and the bits to the left of it. That is, `ith` ciphertext bit is only affected by the `256, 255, ...., i+1, i`th bits of the plaintext.

Hence, we first recover the last bit of the plaintext by checking it with the last bit of the encrypted output. We then use this to recover the second last, then the third last, all the way till we recover the rest of the flag.

```py
import random

def enc_int_to_bin(pt):
    random.seed(0)
    ct = pt
    for _ in range(100):
        ct ^= ct>>random.randint(1,32)
    return format(ct, "0256b")

enc_flag = b'n\xb2t"l(cWp\x8c\x83\xb3\xc5\xee\x98T\x0e\xceI&\x83\xe9ZZ7uvFf\x88\xdcz'
enc_bin = format(int(enc_flag.hex(), 16), "0256b")

flag_bin = ""
for i in range(256):
    for j in ("0", "1"):
        test = flag_bin + j + "0" * (255 - len(flag_bin))
        test_ct = enc_int_to_bin(int(test, 2))
        if test_ct[:1+i] == enc_bin[:1+i]:
            flag_bin += j
            break

flag = int(flag_bin, 2).to_bytes(32, "big")
print(flag) # b'grey{m4tr1ces_4re_s0_c00l_heheh}'
```

A problem with this method is that it relies on the `enc()` function using `>>`. If right rotation is used, any `ith` bit of the ciphertext could well be affected by any of the 256 plaintext bits! This method would not work in that case...

Plus this is clearly unintended; The flag implies something to do with matrices, yet we have not even used one at all. hmm...

### Matrices are so cool

Instead of focusing on the bits as we did earlier, let's take a look at the operations used in `enc()`. It only uses xor (`^`) and bit shifting (`>>`). A property both of these operations share is that the `ith` bit will only affect one other bit, being itself if xor is used, or the bit that occurs when it bit shifts.

At the macro-level, what this means is that every input plaintext bit exerts an influence on the output ciphertext bit that is **independent** of the influence exerted upon by the other input plaintext bits!

Additionally, upon deeper inspection you might find that this influence is not only independent, but also cannot necessarily be reproduced by a combination of other bit's influences. If I have an input plaintext whose bits representation is `0....010...0` for example, no plaintext combination that lack the `1` bit in that position can reproduce the same ciphertext.

Thus, if we catalogue the individual influences exerted by all of the 256 plaintext bits, there must only be one unique `{0, 1, ...}` set of influences that when "summed" together produces our encrypted output. Fortunately as everything happens at the bit-level, we can directly use the bit representation of the encrypted output as our measure of an influence.

We represent the influences in a 256 by 256 matrix where the rows indicate the influence of a bit and the columns the `enc()` output in bits. Now we just need to find a 256-length vector of the form `{1,0,....}` that when multiplied with our matrix gives the encrypted output. 

Recovering this vector isn't as hard as you might think. 

Let this vector be `{x0, x1, ..., x255}` and our encrypted flag in bits be represented as a 256 vector `{y0, y1, ..., y255}`. Let our matrix be represented as;

```
m0_0, m0_1, ..., m0_255
m1_0, m1_1, ..., m1_255
...
m255_0, m255_1, ..., m255_255
```

When we perform the dot product between the vector and the matrix, we get;

```
m0_0 * x0 + m0_1 * x1 + ... + m0_255 * x255 == y0
m1_0 * x0 + m1_1 * x1 + ... + m1_255 * x255 == y1
...
```

Its important to note that in here `+` is supposed to represent bitwise xor. Since xor at a bit level is just addition modulo 2, we'll have our matrix's and vector's elements be values in integers mod 2 `(i.e. Zmod(2) )`.

Anyways, this gives us a system of 256 unknown variables and 256 equations. We can use Gaussain Elimination to obtain our unknowns, or let sage do it for us with matrices and vectors. Ultimately this lets us recover our `{x0, x1, ...}` vector, which would naturally be the flag.

```py
from Crypto.Util.number import *
from sage.all import *

encflag = bytes_to_long(b'n\xb2t"l(cWp\x8c\x83\xb3\xc5\xee\x98T\x0e\xceI&\x83\xe9ZZ7uvFf\x88\xdcz')

import random

# since each bit is either a 1 or a 0, and we're using the xor operation as "addition" in our vector * matrix idea, we use Zmod(2).
# This way, much like how 1 + 1 == 0 modulo 2, 1 ^ 1 == 0
# Zmod(2) creates the environment we need for addition to be equivalent to bitwise xor. An alternative way is to use GF(2) 

v = vector(Zmod(2), [int(i) for i in format(encflag, f"0256b")])
M = []

for i in range(256):
    random.seed(0)
    x = 2**i
    for _ in range(100):
        x ^= x >> random.randint(1, 32)
    M.append([int(j) for j in format(x, "0256b")])
M = Matrix(Zmod(2), M)

flag_bin = ''.join([str(int(i)) for i in M.solve_left(v)])
flag = int(flag_bin[::-1], 2).to_bytes(32, "big")
print(flag) # b'grey{m4tr1ces_4re_s0_c00l_heheh}'
```