### Learning With Mistakes - 10 Solves, 712 Pts, 🩸
```
Original LWE use field GF(prime). TFHE use Mod(2^n). I use GF(2^n) so that it's still a field so obviously mine is gonna be more secure lmao.

Author: JuliaPoo
```

`lwe.sage`
```py
from secrets import randbits
from Crypto.Util.number import bytes_to_long, long_to_bytes
import numpy as np
from hashlib import sha512

n = 500
qbits = 32
mbits = 4
q = 2**qbits
F = GF(q)
x = F.gen()

def int_to_F(n):
    return sum(b*x**i for i,b in enumerate(map(int, bin(n)[2:][::-1])))

def F_to_int(f):
    return f.integer_representation()

def gen_key():
    return np.array([b for b in map(int, format(randbits(n), "0500b"))], dtype=object) 

def gen_a():
    return np.array([int_to_F(randbits(qbits)) for _ in range(n)], dtype=object) 

def gen_noise():
    return int_to_F(randbits(qbits - mbits))

def encrypt_mbits(m, s):
    a = gen_a() 
    f = np.vectorize(F_to_int) 
    m = int_to_F(m << (qbits - mbits)) 
    return (f(a), F_to_int(np.dot(a, s) + m + gen_noise()))

def decrypt_mbits(c, s):
    a,b = c
    f = np.vectorize(int_to_F)
    a,b = f(a), int_to_F(b)
    return F_to_int(b - np.dot(a,s)) >> (qbits - mbits)

def encrypt_m(m, s):
    m = bytes_to_long(m)
    c = []
    while m != 0:
        mb = m & 0b1111
        c.append(encrypt_mbits(mb, s))
        m >>= 4
    return c[::-1]

def decrypt_m(c, s):
    m = 0
    for cb in c:
        m <<= 4
        mb = decrypt_mbits(cb, s)
        m += int(mb)
    return long_to_bytes(m)


# https://www.daniellowengrub.com/blog/2024/01/03/fully-homomorphic-encryption
message = b"Original LWE use field GF(prime). TFHE use Mod(2^n). I use GF(2^n)"
msg = b"A"
key = gen_key() # 500 1,0s
ciphertext = encrypt_m(message, key)
assert decrypt_m(ciphertext, key) == message

recover key, decrypt flag_xored.
flag = b"grey{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"
keyhash = sha512(long_to_bytes(int(''.join(map(str, key)), 2))).digest()
flag_xored = bytes([a^^b for a,b in zip(flag, keyhash)]).hex()

print(ciphertext)
print(flag_xored)
# sage lwe.sage > log
```

We are given two files, a learning-with-errors (LWE) implementation as well as a `log` file containing a sample output when the script is run. The idea seems rather straightforward. To get the flag, given the sample output we're supposed to recover the `key` used in the learning with errors encryption, and from there decrypt the flag.

The general principle behind a `LWE` cryptosystem revolves around the idea that to encrypt a message `m`, one normally generates a (typically 2-D) matrix `A`, dot products it with a secret `key` to get a 1-D vector result. This vector result is added by the message `m` which is expressed as another 1-D vector of equal dimension. Following which, an error vector `e` is added to this. The matrix `A` as well as `A*key + m + e` is returned as the ciphertext.

The security behind a `LWE` lies in that without `key`, one cannot deduce `A*key` and thus not recover `m + e`. It should be noted that normally `m` and `e` are set such that it is possible to distinguish `m` from `m + e`. The reasoning behind `e` is such that as `e` is always random, no matter how many pairs `(A, A*key + m + e)` you can get, even if you know all the `m` (thus getting `(A, A*key+e)` pairs), you simply cannot recover the `key` without having to guess for possible `e` vectors.

This security is absent in the implementation. Looking at `encrypt_mbits()`, we find that the `m` vector is of the form `{m0, m1, m2, m3, 0, 0, ...., 0}`, whereas the `e` vector is of the form `{0, 0, 0, 0, e0, e1, e2, ...., e27}`. Thus, if we can isolate out equations involving the first four terms of the ciphertext result, we can derive a bunch of `(A, A*key)` values by subtracting our known message vectors.

Since `encrypt_mbits()` is called 132 times, we obtain 528 different linear equations with 500 unknowns being the `key` vector itself. We can then perform Gaussian Elimination to recover `key`, and thus the flag.

`solve.py`
```py
from secrets import randbits
from Crypto.Util.number import bytes_to_long, long_to_bytes
import numpy as np
from hashlib import sha512

from sage.all import Matrix, GF, vector

flag_xored = bytes.fromhex("b70262bb880763fe7f3ce2b67e130ed866330acae6f38fb7e4ded75afa12e02036b8c8bbb2b9672e7739fa162cad5ca289ed4c7d70915e5152b6d6e5ec763f8a")
ciphertext = eval(open('log1','r').read()) # modified by removing all of the `numpy.array()` in the original log file

n = 500
qbits = 32
mbits = 4
q = 2**qbits
F = GF(q)
x = F.gen()

def int_to_F(n):
    return sum(b*x**i for i,b in enumerate(map(int, bin(n)[2:][::-1])))

def F_to_int(f):
    return f.to_integer() # f.integer_representation()

def gen_key():
    return np.array([b for b in map(int, format(randbits(n), "0500b"))], dtype=object)

def gen_a():
    return np.array([int_to_F(randbits(qbits)) for _ in range(n)], dtype=object)
def gen_noise():
    return int_to_F(randbits(qbits - mbits))

message = b"Original LWE use field GF(prime). TFHE use Mod(2^n). I use GF(2^n)"
ms = []
m = bytes_to_long(message)
while m != 0:
    mb = m & 0b1111 
    ms.append(mb)
    m >>= 4
ms = ms[::-1]

from tqdm import tqdm
M = []
v = []
for mt, ct in tqdm(zip(ms, ciphertext)):
    mbits = [int(i) for i in format(mt, "04b")]
    fa, dotprod = ct
    vprod = [int(i) for i in format(dotprod, "032b")[:4]] # z32^31, 30, 29 28
    arrays = []
    for i in fa:
        arrays.append(format(i, "032b")[:4]) # z32^31, z32^30, z32^29, z32^28
    r0, r1, r2, r3 = [], [], [], []
    for i in arrays:
        r0.append(int(i[0]))
        r1.append(int(i[1]))
        r2.append(int(i[2]))
        r3.append(int(i[3]))
    M += [r0, r1, r2, r3]
    v += [(i - j) % 2 for i,j in zip(vprod, mbits)]
M = Matrix(GF(2), M)
v = vector(GF(2), v)
key = M.solve_right(v)
key = np.array([i for i in key], dtype=object)
print(key)
keyhash = sha512(long_to_bytes(int(''.join(map(str, key)), 2))).digest()
flag = bytes([a^b for a,b in zip(flag_xored, keyhash)])
print(flag)
```

```
>> sage solve.py
132it [00:00, 883.09it/s]
[0 1 1 0 0 0 1 0 1 1 1 1 0 0 0 0 0 0 0 1 0 1 0 1 1 1 0 1 0 1 0 0 0 1 1 0 0
 1 1 0 0 1 1 0 0 0 0 0 0 1 0 1 0 1 0 1 0 1 1 1 0 1 1 1 1 1 1 1 1 0 1 0 0 1
 1 0 1 1 0 1 1 0 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 0 1 0 0 1 1 1 1 1 1 1 1 0 0
 0 0 0 1 0 0 1 0 1 0 0 0 1 0 0 1 1 1 0 0 0 1 0 0 0 1 0 0 1 0 1 1 0 1 1 1 0
 0 0 0 1 0 1 1 1 0 0 1 0 0 0 1 1 1 0 0 0 0 1 1 1 1 0 0 0 1 1 0 1 0 0 0 0 0
 1 0 1 0 1 0 1 0 1 0 0 0 1 0 1 1 0 0 1 0 0 0 1 0 0 1 0 0 0 0 0 1 1 1 1 1 1
 1 0 0 1 1 1 0 1 1 1 1 0 0 0 1 1 0 0 0 1 0 1 1 0 0 1 1 1 0 1 0 1 0 1 1 1 0
 1 1 0 0 0 0 0 1 1 1 0 1 0 0 1 1 1 0 1 1 0 1 0 1 1 0 0 0 0 1 1 0 1 0 1 1 1
 1 0 1 1 0 0 0 0 1 0 0 0 0 0 0 0 0 1 1 0 0 0 1 1 1 0 1 0 0 1 0 0 1 0 1 1 1
 1 0 0 0 0 0 1 0 0 1 0 1 0 1 1 0 0 0 0 1 1 1 0 0 1 0 0 1 1 0 1 1 1 1 0 0 0
 0 0 1 1 0 1 1 1 1 0 1 1 1 1 0 1 1 1 0 0 1 1 1 0 1 1 1 1 0 0 1 1 1 0 1 0 1
 0 0 1 1 0 1 0 1 0 1 1 1 0 1 1 1 1 0 1 0 0 0 0 1 1 1 0 0 1 1 1 0 0 0 0 0 1
 0 0 0 1 0 1 0 0 1 1 1 0 1 1 0 0 0 0 0 1 1 1 0 0 1 0 1 1 1 1 1 1 1 0 0 1 0
 0 1 0 1 0 1 0 0 0 0 0 0 1 1 1 1 1 1 1]
b"grey{I'm_flyin_soon_I'm-_rushing-this-challenge-rn-ajsdadsdasks}"
```