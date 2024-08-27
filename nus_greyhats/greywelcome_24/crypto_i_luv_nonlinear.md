### I Luv NonLinear 💀 | 4 Solves 1000 Points
```
Now my thing is no longer linear hehe. I wonder why x^p%p isn''t x tho...

Author: Ariana
```

`chal.py`
```py
import random

flag = input().encode()
assert len(flag)==32
assert flag[:5]==b"grey{" and flag[-1:]==b"}"
p = 0xffffffffffffffa4000000000000024600000000000113a4000000000008fa01

def enc(pt):
    random.seed(0)
    pt = int(pt.hex(),16)
    ct = 0
    for _ in range(8):
        ct = (ct*pt+random.randint(0,p-1))%p
    return ct

assert enc(flag) == 920298079715715123160430817753159795737464812507389199436727913012855397002
```

We have a revenge challenge! A similar `enc()` is used with 8 random calls, but instead of xor we have integer multiplication!

A quick look at this tells us that we have a flag and it is put into a polynomial operation, whose coefficients we can recover. Letting `[r0, r1, ..., r7]` be the 8 random values we have;

`f(flag) = (...(((r0 * x + r1) * x + r2) * x + r3) * x + ....) + r7`

We can replicate this function using sage by establishing a polynomial ring modulo p;
```py
F = ZZ['x']; (x,) = F._first_ngens(1)
```

And then recovering the random values and piping them in;
```py
random.seed(0)
rs = [random.randint(0, p-1) % p for _ in range(8)]

f = 0
for r in rs:
    f = f * x + r
```

Thus we now have a polynomial modulo some composite number p and we know that with flag as the input it should output `920298079715715123160430817753159795737464812507389199436727913012855397002`.

We convert this problem of finding x that gives y into a root-finding problem, i.e. find x that gives 0;
```py
f -= 920298079715715123160430817753159795737464812507389199436727913012855397002
```

We will utilise a key observation of sage. When solving for a polynomial's roots under integers modulo a prime p, sage is able to shift it to a finite field `GF(p)` and return the appropriate root. 

Sage however, is not able to do the same for solving for a polynomial's roots modulo a composite number. This is because there is no finite field that can be used to accomodate for composites, and thus the problem is a lot harder. Such a scenario is in fact not implemented in sage.

We do have a method, to given say `x mod p` and `x mod q` for primes `p,q`, find a unique `x mod pq`. This is known as the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem), and the article itself offers a really neat proof behind it too!

We also have a method to given say `f(x) = 0 mod p^(i)`, find a unique `s` s.t. `f(s) = 0 mod p^(i+1)`. This method is known as [Hensel Lifting](https://en.wikipedia.org/wiki/Hensel%27s_lemma) and the scenario I'd raised can be proven using derivatives and the taylor series expansion, which is also featured in the article.

Let's combine all 3 of these insights together. Since our composite modulus p can be factored into prime factorisation `18446744073709551557^2 * 18446744073709551629^2`, letting those primes be `p0` and `p1` respectively,

1. Find `0 < x0 < p0` s.t. `f(x0) == 0 mod p0` and `0 < x1 < p1` s.t. `f(x1) == 0 mod p1`. Notice that `x0 == r % p0` and `x1 == r % p1` where `r` is some root of `f()`. There might be multiple possible roots here, hence various `(x0, x1)` pairs.

2. For every distinct `(x0, x1)` pair, use hensel lifting to find unique `y0`, `y1` such that `f(y0) == 0 mod p0^2` and `f(y1) == 0 mod p1^2`. Similarly `y0 == r % p0^2` and `y1 == r % p1^2` for some root `r` of `f()`

3. For every distinct `(y0, y1)` pair, use the chinese remainder theorem to construct a possible root of `f(x)`. If the bytes representation of the root matches the flag prefix and suffix, we've found the flag!

This leads us into our solve:

`sol.py`
```py
p = 0xffffffffffffffa4000000000000024600000000000113a4000000000008fa01
# p = 18446744073709551557^2 * 18446744073709551629^2
p0, p1 = 18446744073709551557, 18446744073709551629

random.seed(0)
rs = [random.randint(0, p-1) % p for _ in range(8)]

from itertools import product
from sage.all import ZZ, Zmod, crt

def hensel_lift(f, r, p, i):
    # Given f(r) == 0 mod p^i, find s s.t. f(s) == 0 mod p^(i+1)
    fp = f.derivative()
    if int(fp(r)) % p**i == 0:
        # No such value exists
        return 0
    a = pow(fp(r), -1, p)
    s = (r - int(f(r)) * a) % p**(i+1)
    return s

F = ZZ['x']; (x,) = F._first_ngens(1)
f = 0
for r in rs:
    f = f * x + r
f -= 920298079715715123160430817753159795737464812507389199436727913012855397002

r0s = [hensel_lift(f, int(i[0]), p0, 1) for i in f.change_ring(Zmod(p0)).roots()]
r1s = [hensel_lift(f, int(i[0]), p1, 1) for i in f.change_ring(Zmod(p1)).roots()]
print(f'{r0s = }')
print(f'{r1s = }')

for rems in product(r0s, r1s):
    flag = crt(list(rems), [p0**2, p1**2]).to_bytes(32, 'big')
    if flag.startswith(b'grey{'):
        print(flag)

"""
r0s = [80997361592438765063021921683966548383]
r1s = [130261828526514976713518696781655992053, 222557151909502722584561208659211704364]
b'grey{crt_4nd_h4ns31_l1ft1ng_upz}'
"""
```