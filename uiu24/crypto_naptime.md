## Naptime (180 Solves, 363 Pts)
```
Author: Anakin

I'm pretty tired. Don't leak my flag while I'm asleep.
```

This challenge was solved by my teammate Yun. This writeup will briefly mention Yun's solve as well as my own version which was hopefully what the author had originally intended lol.

`pub.txt`
```
a =  [66128, 61158, 36912, 65196, 15611, 45292, 84119, 65338]
ct = [273896, 179019, 273896, 247527, 208558, 227481, 328334, 179019, 336714, 292819, 102108, 208558, 336714, 312723, 158973, 208700, 208700, 163266, 244215, 336714, 312723, 102108, 336714, 142107, 336714, 167446, 251565, 227481, 296857, 336714, 208558, 113681, 251565, 336714, 227481, 158973, 147400, 292819, 289507]
```

`enc_dist.sage`
```py
from random import randint
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import numpy as np

def get_b(n):
    b = []
    b.append(randint(2**(n-1), 2**n))
    for i in range(n - 1):
        lb = sum(b)
        found = False
        while not found:
            num = randint(max(2**(n + i), lb + 1), 2**(n + i + 1))
            if num > lb:
                found = True
                b.append(num)

    return b

def get_MW(b):
    lb = sum(b)
    M = randint(lb + 1, 2*lb)
    W = getPrime(int(1.5*len(b)))

    return M, W

def get_a(b, M, W):
    a_ = []
    for num in b:
        a_.append(num * W % M)
    pi = np.random.permutation(list(i for i in range(len(b)))).tolist()
    a = [a_[pi[i]] for i in range(len(b))]
    return a, pi


def enc(flag, a, n):
    bitstrings = []
    for c in flag:
        # c -> int -> 8-bit binary string
        bitstrings.append(bin(ord(c))[2:].zfill(8))
    ct = []
    for bits in bitstrings:
        curr = 0
        for i, b in enumerate(bits):
            if b == "1":
                curr += a[i]
        ct.append(curr)

    return ct

def dec(ct, a, b, pi, M, W, n):
    # construct inverse permuation to pi
    pii = np.argsort(pi).tolist()
    m = ""
    U = pow(W, -1, M)
    ct = [c * U % M for c in ct]
    for c in ct:
        # find b_pi(j)
        diff = 0
        bits = ["0" for _ in range(n)]
        for i in reversed(range(n)):
            if c - diff > sum(b[:i]):
                diff += b[i]
                bits[pii[i]] = "1"
        # convert bits to character
        m += chr(int("".join(bits), base=2))

    return m


def main():
    flag = 'uiuctf{I_DID_NOT_LEAVE_THE_FLAG_THIS_TIME}'

    # generate cryptosystem
    n = 8
    b = get_b(n)
    M, W = get_MW(b)
    a, pi = get_a(b, M, W)

    # encrypt
    ct = enc(flag, a, n)

    # public information
    print(f"{a =  }")
    print(f"{ct = }")

    # decrypt
    res = dec(ct, a, b, pi, M, W, n)

if __name__ == "__main__":
    main()
```

`get_b()`, `get_MW()`, `get_a()` and `enc()` may be very confusing but in truth all of it is just an implementation of the [Merkle-Hellman knapsack cryptosystem](https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem). It revolves around the idea of a trapdoor in the form of an 0-1 Knapsack problem. I'd go more in depth into the topic but I could also cite [this website](https://mathweb.ucsd.edu/~crypto/Projects/JenniferBakker/Math187/) which was how I'd learnt about it in the first place (and presumably the intended solution, im guessing)

But in very laymann terms, what we have is an array of 8 coefficients `a`. For each character in the flag, the character is converted into binary (8 1s and 0s), and for every `1`, the corresponding coefficient is added into a sum which is outputted into the `ct` array.

Thus the cheese method comes in. Since every result in `ct` is 1 of 256 possible summations of the coefficients array `a`, you can brute it through to obtain each character of the flag.

As we can see here;
```py
a = ...
ct = ...

lookup = {}
for val in range(0x20, 0x7e):
    ii = [int(i) for i in format(val, "08b")]
    key = sum(x*y for x,y in zip(a, ii))
    lookup[key] = val

flag = bytes([lookup[c] for c in ct])
print(flag)
# b'uiuctf{i_g0t_sleepy_s0_I_13f7_th3_fl4g}'
```

### The Lattice Method!

What I assume the creator had actually intended was to use lattices. I'm not so well versed in lattice theory yet, but from my limited linear algebra knowledge, the general idea goes that;

1. Suppose I know there exist some vector v such that v*M, where M is a lattice, produces a really small result vector.
2. Lattice Reduction takes a lattice M, considers its basis vectors (i.e. its rows or column, depending how you look at it), and then through some math wizardry computes a similar-ish lattice ML, but all of its basis are generally "really small"

We can use lattice reduction, notably the [Lenstra–Lenstra–Lovász lattice basis reduction algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm) to do just that and obtain our "really small" basis vectors. But how does the knapsack problem apply here?

Well, we know that given the vector `a`, and any element `c` in the `ct` array, there exist some vector of 8 `0/1` values such that `v * a == c`. Given `a = {a1, a2, a3, a4, a5, a6, a7, a8}`, we can use the lattice `M` as shown below:

(if it helps with visualising, try and conceptualise the lattice as multiple vertical columns rather than in terms of rows)
```
a1  1   0   ...                 0
a2  0   1                       0
a3  0       1                   0
a4  .           1               .
a5  .               1           .
a6  .                   1       0
a7  0                       1   0
a8  0   0   ...             0   1
-c  0   0   0   0   0   0   0   0
```

Given the vector `u = (v,1)` (where v is the 8 0/1 values we'd discussed earlier, eg. if `v = {1,1,0,0,1,0,1,0}` then `u = {1,1,0,0,1,0,1,0,1}`), when we perform `u*M` (where `M` is our lattice), we'd get the resultant vector `(0, v)`. My mathematical notation is definitely wrong but I hope you all can at least understand what I mean.

Since this resultant vector could be argued as "really small" (in magnitude), chances are it would show up when we apply our lattice reduction algorithm! This allows us to recover `v`, and so we repeat this process for each `c` in `ct` to recover the plaintext.

```py
from sage.all import *

a = ...
ct = ...
flag = ""

M = Matrix([[i] for i in a])
M = M.augment(identity_matrix(8))
for c in ct:
    MM = M.stack(vector([-c] + [0]*8))
    ML = MM.LLL()
    for row in ML:
        if any(i not in [0,1] for i in row):
            continue
        if row[0] != 0:
            continue
        v = ''.join([str(int(i)) for i in row[1:]])
        flag += chr(int(v, 2))
        break
print(flag)
# uiuctf{i_g0t_sleepy_s0_I_13f7_th3_fl4g}
```

### A Similar (and perhaps just as Funny) Story
Unironically at the start of this year I'd made a Cryptography challenge in a CTF competition that also employed knapsack. I thought using 48 bits would be good enough to deter brute forces, but it turns out I was wrong, and people managed to do a 24-bit brute using Meet In The Middle.

Here's the link to the [ctf challenge in question](https://github.com/Lag-and-Crash/2024/tree/main/challenges/crypto/Backpacker) if anyone's interested!
