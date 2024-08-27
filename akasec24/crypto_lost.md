## Lost

`lost.py`
```py
from random import getrandbits
from Crypto.Util.number import getPrime, bytes_to_long
from SECRET import FLAG

e = 2
p = getPrime(256)
q = getPrime(256)
n = p * q

m = bytes_to_long(FLAG)
cor_m = m - getrandbits(160)

if __name__ == "__main__":
    c = pow(m, e, n)
    print("n = {}\nc = {}\ncor_m = {}".format(n, c, cor_m))
```

Let the unknown 160 bits be `x`.

We can derive the equation, 
```
(cor_m + x)**2 - c == 0 (mod n)
```

This gives us a quadratic equation under `Zmod(n)`. Since `x` is 160-bits and is very small compared to the 512-bit `n`, as `x < n**(1/e)` this is within bounds for us to apply a well known attack on RSA otherwise known as `Coppersmith's Attack`, which given some function `f(x)`, finds small values `x < n**(1/e)` such that `f(x) = 0 mod n`. In sagemath, we do this using `f.small_roots()`.

Once we recover this value, we derive the flag as `x + cor_m`.


`solve.py`
```py
from sage.all import Zmod

# Given in out.txt
n = 5113166966960118603250666870544315753374750136060769465485822149528706374700934720443689630473991177661169179462100732951725871457633686010946951736764639
c = 329402637167950119278220170950190680807120980712143610290182242567212843996710001488280098771626903975534140478814872389359418514658167263670496584963653
cor_m = 724154397787031699242933363312913323086319394176220093419616667612889538090840511507392245976984201647543870740055095781645802588721

# Solve script
F = Zmod(n)['x']
x = F.gen()
m = ((x+cor_m)**2 - c).small_roots()[0] + cor_m
print(int(m).to_bytes(256,"big").lstrip(b'\x00')) 
# b'AKASEC{c0pp3r5m17h_4774ck_1n_1ov3_w17h_5m4ll_3xp0n3nts}'
```