## Twin ()

`twin.py`
```py
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from SECRET import FLAG

e = 5
p = getPrime(256)
q = getPrime(256)
n = p * q

m1 = bytes_to_long(FLAG)
m2 = m1 >> 8

if __name__ == "__main__":
    c1, c2 = pow(m1, e, n), pow(m2, e, n)
    print("n = {}\nc1 = {}\nc2 = {}".format(n, c1, c2))
```

We are given a pair of RSA encrypted messages. The first is an RSA encrypted flag, and the second is the same encrypted flag but without its last character.
Converting the flag into 'base-256', one can observe a relationship between `m2` and `m1`. Since the flag is some `....}`, `m2 * 256 + 125 == m1`.

Thus, we can deduce the following equations;

```
(m2 * 256 + 125)**5 - c1 == 0 (mod n)    (f1)
              m2**5 - c2 == 0 (mod n)    (f2)
```
Observe that both of these equations are satisfied at the right `m2` value. 
Letting `f1(x)` and `f2(x)` represent these two equations, this means that `f1(m2)` and `f2(m2)` equate to 0. Hence, the linear polynomial `(x - m2)` is a factor of both!

We can therefore compute the `gcd`, or greatest common divisor of the two polynomials modulo `n`, which should give us some lower polynomial containing `(x - m2)`, thus allowing us to deduce `m2` and recover the flag from there. We can borrow standard Euclidean gcd for integers over the polynomials, which we do under `Zmod(n)`, or the ring of integers modulo `n`. We'll make use of `sagemath` to handle most of the modulo arithmetic and deduce `m2`. This type of attack is more famously known as the `Franklin-Reiter related message attack` attack on RSA, where given a relationship of two plaintexts and their RSA encrypted outputs, one can recover the plaintext.

Once we get `m2`, we simply convert it back to bytes and add back the `}` to obtain the flag.

`solve.py`
```py
from sage.all import *

# Given in out.txt
n = 6689395968128828819066313568755352659933786163958960509093076953387786003094796620023245908431378798689402141767913187865481890531897380982752646248371131
c1 = 3179086897466915481381271626207192941491642866779832228649829433228467288272857233211003674026630320370606056763863577418383068472502537763155844909495261
c2 = 6092690907728422411002652306266695413630015459295863614266882891010434275671526748292477694364341702119123311030726985363936486558916833174742155473021704
e = 5

# Solve script
# let m = bytes_to_long(FLAG[:-1])
# so we have c1 = (m * 256 + ord('}')) ** e, c2 = m ** e

F = Zmod(n)['m']
m = F.gen()
f1 = (m * 256 + ord('}')) ** e - c1
f2 = (m)**e - c2

def poly_gcd(a, b):
    while b:
        a, b = b, a % b
    return a, b

r1, r2 = poly_gcd(f1, f2)
assert r2 == 0
# we get some r1 of some form a*m + b == 0 mod N. This is equivalent to our (x - m2)
b, a = r1.coefficients()
flag = (-b) * pow(a, -1, n) % n 
# a*x + b = 0 thus x = -b / a (mod n)

print(long_to_bytes(int(flag)) + b'}')
# b'AKASEC{be_on_the_right_side_of_history_free_palestine}'
```