## GCL

`gcl.py`
```py
from random import getrandbits
from Crypto.Util.number import getPrime
from SECRET import FLAG

BITS = 128
m = getPrime(BITS)
s = getrandbits(BITS - 1)
a = getrandbits(BITS - 1)
b = getrandbits(BITS - 1)

def lcg(s, c):
    return c*(a*s + b) % m

FLAG = 'AKASEC{testflag}'
def enc():
    c = []
    r = s
    for i in FLAG:
        r = lcg(r, ord(i))
        c.append(r)
    return m, c
```

We are given a random value `r`. The custom `enc()` function takes in each character `c`, and updates `r` with `r = c*(a*r + b) % m`. We know `m` and all of the `r`s, but we lack knowledge of `a` and `b`. 

The use of `r -> a*r + b % m` is also known as a `linear congruential generator` (LCG), which generates a sequence of pseudo-random numbers according to some recurrence congruence. The challenge name, `GCL`, is a reverse of the term. 

Generally speaking, the security of `LCG`s lies in the idea that the parameters such as `a`, `b` and `m` are kept secret so that nobody can predict subsequent outputs of the `LCG` from previous outputs. However, this challenge fails to notice an easy way to obtain these secret values...

Consider the `FLAG` value `AKASEC{}`. An encrypted output would be of the form;

`r, ord('K') * (ar + b), ord('A') * (ord('K') * (ar + b)), ...`.

Observe that given these numbers `r0, r1, r2, ...`, we have;
```
r1 = ord('K') * r0 a + ord('K') * b
r2 = ord('A') * r1 a + ord('A') * b
```
This is a system of linear equations! Knowing `r0`, `r1`, we can derive `a` and `b`. From this, we reconstruct our LCG and solve for each character of the flag. While beginners would often use common methods such as gaussian elimination to solve the system of two unknowns, I'd used matrices which functionally does the same; Figured that this could also be a good way to introduce the idea of matrices and linear algebra to newcomers.

`solve.py`
```py
m = 188386979036435484879965008114174264991
c = [139973581469094519216727575374900351861, 72611500524424820710132508411012420565, 140250284171774823110472025667980956543, 32777758636601391326104783245836052689, 93866424818360655182957373584240082579, 171863599957625964609271128026424910780, 79519361871833866309751703823833758895, 157560014678333843523667019607330519198, 124975940725420603096426178838171348774, 3564693226938115115868719960412136082, 171740395033004244209129576880703758137, 92351702560499873288607191820522016910, 150094682983991168941275074808189562445, 85216665671310516224623100332845098274, 16595528649897543867800038656511154165, 19125026372283368463438507438570762609, 176795229245184227193627490600890111381, 12405536363393343486876802251851443164, 21411546298976790262184367895329536928, 182888536880153351183725282563493758721, 138117470020493616013148815568927291737, 32287599436436170232396368906599005001, 163785640221676961026807618948041121515, 73960913430365454320029097511676942987, 15454719718422589834477927328058381231, 187548967342452768771256903662911504220, 159561161576243464490176365717896800999, 68751190791869748062871941359673493536, 121231243784105483671509398006895458898, 14881767206744163076100305953646446453, 175267890044871169868897060667629218625, 147751087332703693307658387948934053643, 144192171120888146499506968416035431150]

from sage.all import *

# s -> CHAR * (a s + b) -> CHAR s a + CHAR b
# m, c = enc()

c0, c1, c2 = c[:3]
k1, k2 = [i for i in b'KA'] # since we know flag starts with AKASEC

# Solve system of equations using matrices
"""
c1 = K * c0 a + K * b
c2 = A * c1 a + A * b
"""
M = Matrix(Zmod(m), [[k1 * c0, k1], [k2 * c1, k2]])
v = vector(Zmod(m), [c1, c2])
a, b = [int(i) for i in M.solve_right(v)]

c_ = c0
flag = b'A'
for cc in c[1:]:
    val = cc * pow(a*c_ + b, -1, m) % m
    c_ = cc
    flag += chr(val).encode()
print(flag)
# b'AKASEC{++see_?!_just_some_math--}'
```