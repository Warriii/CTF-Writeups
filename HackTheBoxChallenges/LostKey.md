### LostKey
---

#### Files
`encrypt.py`
```py
#!/usr/bin/env python3
from Crypto.Util.number import *
from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import flag, n

class coord:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def __str__(self):
        return f"coord({self.x}, {self.y})"

class EC:
    def __init__(self, p):
        self.p = p
        self.zero = coord(0,0)

    def add(self, P,Q):
        if P == self.zero:
            return Q
        if Q == self.zero:
            return P
        if P.x == Q.x and P.y == -Q.y:
            return self.zero
        if P != Q:
            Lambda = (Q.y - P.y) * inverse(Q.x - P.x, self.p)
        else:
            Lambda = (3*(P.x*Q.x) + 417826948860567519876089769167830531934*P.x + 177776968102066079765540960971192211603) * inverse(P.y+Q.y+3045783791, self.p)
        Lambda %= self.p
        R = coord(0,0)
        R.x = (Lambda**2-P.x-Q.x-208913474430283759938044884583915265967) % self.p
        R.y = (Lambda*(P.x-R.x) - P.y - 3045783791) % self.p
        return R

    def mul(self, P, n):
        Q = P
        R = self.zero
        while n > 0:
            if n % 2 == 1:
                R = self.add(R,Q)
            n >>= 1
            Q = self.add(Q,Q)
        return R

def encrypt(key):
    iv = __import__('os').urandom(16)
    key = sha1(str(key).encode('ascii')).digest()[0:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(flag,16))
    return(ct.hex(),iv.hex())

n = getRandomInteger(70)
assert(n < 38685626227668133590597631)
e = EC(101177610013690114367644862496650410682060315507552683976670417670408764432851)
G = coord(14374457579818477622328740718059855487576640954098578940171165283141210916477, 97329024367170116249091206808639646539802948165666798870051500045258465236698)

print ("G =",G)
print ("Gn =", e.mul(G,n).x)
print(f"{n = }")
enc = encrypt(n)
print ("Ciphertext: {}\nIV: {}".format(enc[0],enc[1]))
```

`output.txt`
```
G = coord(14374457579818477622328740718059855487576640954098578940171165283141210916477, 97329024367170116249091206808639646539802948165666798870051500045258465236698)
Gn = 32293793010624418281951109498609822259728115103695057808533313831446479788050
Ciphertext: df572f57ac514eeee9075bc0ff4d946a80cb16a6e8cd3e1bb686fabe543698dd8f62184060aecff758b29d92ed0e5a315579b47f6963260d5d52b7ba00ac47fd
IV: baf9137b5bb8fa896ca84ce1a98b34e5
```

#### Writeup
What we have here is a flag that's AES encrypted with some number $n$. Alongside this, we are given $G$, and $n*G$, points on an elliptic curve whose parameters we do not know.

What we do know, is the algorithm used to compute $n*G$. It resembles standard elliptic curve point multiplication, so we look into the point addition function instead.

```py
    def add(self, P,Q):
        if P == self.zero:
            return Q
        if Q == self.zero:
            return P
        if P.x == Q.x and P.y == -Q.y:
            return self.zero
        if P != Q:
            Lambda = (Q.y - P.y) * inverse(Q.x - P.x, self.p)
        else:
            Lambda = (3*(P.x*Q.x) + 417826948860567519876089769167830531934*P.x + 177776968102066079765540960971192211603) * inverse(P.y+Q.y+3045783791, self.p)
        Lambda %= self.p
        R = coord(0,0)
        R.x = (Lambda**2-P.x-Q.x-208913474430283759938044884583915265967) % self.p
        R.y = (Lambda*(P.x-R.x) - P.y - 3045783791) % self.p
        return R
```

And that's when we see all the weird numbers inside...But what is Elliptic Curve? To answer that question, I would recommend reading [A (Relatively Easy To Understand) Primer on Elliptic Curve Cryptography](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/), as well as reading Sections 1.2 to 1.4 of [Rational Points on Elliptic Curves](http://ndl.ethernet.edu.et/bitstream/123456789/53787/1/Joseph%20H.%20Silverman.pdf) by Silverman and Tate.

Notably, in the text we know the formula to compute point doubling on a curve (when the point is added to itself). Put simply, we derive the tangent line, then find the point at which the line intersects the curve once more.

We can derive the tangent line's gradient by computing the derivative of the curve equation and substituting in the point coordinates, and we see that this value is computed as

$\frac{3x^2 + 417826948860567519876089769167830531934x + 177776968102066079765540960971192211603}{2y + 3045783791}$

Given the elliptic curve of the long weierstrass form $y^2 + a_1 xy + a_3 y = x^3 + a_2 x^2 + a_4 x + a_6$, we compute the derivative $2y\frac{dy}{dx}+a_1 y+a_1x\frac{dy}{dx} + a_3 \frac{dy}{dx} = 3x^2+2a_2x+a_4$.

Thus

$\frac{dy}{dx} = \frac{3x^2+2a_2x+a_4-a_1y}{2y+a_1x+a_3}$

Comparing coefficients, we can derive all of $a_i$ except for $a_6$. But we can substitute in $Gx, Gy$ into the curve equation to determine the intercept value anyway.

Now that we have restored the "Lost" Curve, we can restore the "Lost" point $n*G$ (as we were only given its x-coordinate). 

All that remains to do is to solve the Elliptic Curve Discrete Logarithm Problem instance. We do this by applying Pohlig Hellman over smaller prime factors in the group order $p-1$, solving the discrete log instance in each of these and then bruting a little bit to check all possible values of $n$.

#### solve.py
```py
from sage.all import EllipticCurve, GF, crt, lcm
from hashlib import sha1
from Crypto.Cipher import AES

a2 = 417826948860567519876089769167830531934 // 2
p = 101177610013690114367644862496650410682060315507552683976670417670408764432851
a4 = 177776968102066079765540960971192211603
a3 = 3045783791
Gx = 14374457579818477622328740718059855487576640954098578940171165283141210916477
Gy = 97329024367170116249091206808639646539802948165666798870051500045258465236698
a6 = 308081941914167831441899320643373035841 # sub Gx, Gy and solve

E = EllipticCurve(GF(p), [0, a2, a3, a4, a6])
G = E(Gx, Gy)
Gn = 32293793010624418281951109498609822259728115103695057808533313831446479788050
Q = E.lift_x(GF(p)(Gn))
Go = 101177610013690114367644862496650410682371882435919767898009148385876141737891 # G.order()

# Gorder = 3^2 * 59 * 14771 * 27733 * 620059697 * 2915987653003935133321 * 257255080924232005234239344602998871
# solve over 3^2 * 59 * 14771 * 27733 * 620059697
# brute 286824*2

mods = [9, 59, 14771, 27733, 620059697]
rems = []
for mod in mods:
    hG = G * (Go//mod)
    hQ = Q * (Go//mod)
    hG.set_order(mod)
    hQ.set_order(mod)
    rem = hQ.log(hG)
    rems.append(rem)
d = crt(rems, mods)
m = lcm(mods)
d_ = -d % m
# either d, -d is the soln

iv = bytes.fromhex("baf9137b5bb8fa896ca84ce1a98b34e5")
ct = bytes.fromhex("df572f57ac514eeee9075bc0ff4d946a80cb16a6e8cd3e1bb686fabe543698dd8f62184060aecff758b29d92ed0e5a315579b47f6963260d5d52b7ba00ac47fd")
while d < 38685626227668133590597631 and d_ < 38685626227668133590597631:
    if (d*G)[0] == Gn:
        key = sha1(str(d).encode('ascii')).digest()[0:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        print(cipher.decrypt(ct))
    if (d_*G)[0] == Gn:
        key = sha1(str(d).encode('ascii')).digest()[0:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        print(cipher.decrypt(ct))
    d += m
    d_ += m
# b'HTB{uns4f3_3ll1pt1c_curv3s_l3d_t0_th3_c0ll4ps3_0f_0u7l4nd1s}\x04\x04\x04\x04'
```