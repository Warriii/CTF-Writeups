![image](Images/grammarnazi.png)

`chall.py`
```py
from Crypto.Util.number import *

FLAG = 'maltactf{???????????????????????????????}'
assert len(FLAG) == 41

p = getPrime(128)
q = getPrime(128)
N = p * q
e = 65537

m = f'The flag is {FLAG}'
c = pow(bytes_to_long(m.encode()), e, N)

# ERROR: Sentences should end with a period.
m += '.'
c += pow(bytes_to_long(m.encode()), e, N)

# All good now!
print(f'{N = }')
print(f'{c = }')

'''
N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
'''
```

We have a fairly simple RSA implementation, with the sum of two encrypted ciphertexts. One is of the plaintext `The flag is ....`, the other the same but ending with a period.

We thus have equations

$c_1 = m^e \bmod n$

$c_2 = (256*m + 46)^e \bmod n$

and we are given $c_1 + c_2 = m^e + (256*m + 46)^e \bmod n$

It takes a while but we can arrive at at 65537-degree polynomial. During this time, we exploit the low bit size of $n$ (256) and derive its prime factors $p, q$. I used [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs) for it, which took about a minute on my computer.

```
> ./cado-nfs.py
... 83839453754784827797201083929300181050320503279359875805303608931874182224243
Info:Generate Factor Base: Total cpu/real time for makefb: 0.08/0.0249407
Info:Quadratic Characters: Total cpu/real time for characters: 0.49/0.171214
Info:Filtering - Singleton removal: Total cpu/real time for purge: 1.34/1.83112
Info:Polynomial Selection (root optimized): Aggregate statistics:
Info:Polynomial Selection (root optimized): Total time: 7.58
Info:Polynomial Selection (root optimized): Rootsieve time: 7.62
Info:Filtering - Duplicate Removal, splitting pass: Total cpu/real time for dup1: 1.06/0.905222
Info:Filtering - Duplicate Removal, splitting pass: Aggregate statistics:
Info:Filtering - Duplicate Removal, splitting pass: CPU time for dup1: 0.6s
Info:HTTP server: Shutting down HTTP server
Info:Complete Factorization / Discrete logarithm: Total cpu/elapsed time for entire Complete Factorization 352.86/68.6544
Info:root: Cleaning up computation data in /tmp/cado.l_3sqqkh
302904819256337380397575865141537456903 276784813000398431755706235529589161781
```

With our 65537 degree polynomial, we note $(x-m)$ is a valid root. As we have factorised $n$, we are able to move the problem from solving polynomial roots over rings to over fields. (if i am not wrong, standard polynomial root finding algorithms over modulo composite factor the modulus into primes and solves over the fields anyway)

Sagemath, however, takes very long when root finding over a degree as big as 65537. So we must simplify it somehow. Considering that polynomials over $\mathbb{F}_p$ is not algebraically closed (as in there'll be polynomials that are irreducible / cannot be reduced to linear factors of form $(x-r)$), one way in which we can lower the degree (and by extension time required to find the roots) would be to remove all irreducible polynomial factors of $x^e + (256*x + 46)^e - c$. 

Since the polynomial $x^p - x$ contains all linear roots $(x-r) \;\forall r\in [0, p-1]$ (apply Fermat's Little Theorem), we can compute the greatest common divisor of $x^e + (256*x + 46)^e - c$ and $x^p - x$. Over $F_p$ and $F_q$ respectively, where $pq = n$, we are left with two degree-2 and degree-3 polynomials:

$x^2 + 246722526070375633751358382828376272499*x + 57896353459370517095908324362868636064$

$x^3 + 257965519644361503084145068120666847329*x^2 + 246001466957115617978590583563883348762*x + 114033658501667769436864955932493349968$

Solving both of them gives us the values of $m \bmod p$ and $m \bmod q$. We use the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) and brute all 6 possible $m \bmod n$ values.

As the flag is of the form `The flag is maltactf{`|`32_BYTE_STRING`, since we have a 256 bit modulus $n$, we have to subtract away the prefix from each $m \bmod n$ values. One of them would contain the 32-byte string that has the rest of the flag.

`solve.py`
```py
N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
e = 65537
p = 302904819256337380397575865141537456903
q = 276784813000398431755706235529589161781

arr = []
for r in [p,q]:
    F.<x> = GF(r)[]
    f = x^e + (256*x+46)^e - c
    arr.append(f.gcd(pow(x,r,f)-x))
fP, fQ = arr
for rp in fP.roots(multiplicities=False):
    for rq in fQ.roots(multiplicities=False):
        mm = crt([int(rp), int(rq)],[p, q])
        mm -= int.from_bytes(b'The flag is maltactf{', "big") * 256**32
        flag_str = (mm % N).to_bytes(64, "big").lstrip(b'\x00')
        if all(i < 0x7f for i in flag_str):
            print(b'maltactf{' + flag_str)
# b'maltactf{Ferm4ts_littl3_polyn0mial_tr1ck}'
```