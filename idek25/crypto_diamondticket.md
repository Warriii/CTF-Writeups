![alt text](Images\image-1.png)

`chall.py`
```py
from Crypto.Util.number import *

#Some magic from Willy Wonka
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381

def chocolate_generator(m:int) -> int:
    return (pow(a, m, p) + pow(b, m, p)) % p

#The diamond ticket is hiding inside chocolate
diamond_ticket = open("flag.txt", "rb").read()
assert len(diamond_ticket) == 26
assert diamond_ticket[:5] == b"idek{"
assert diamond_ticket[-1:] == b"}"
diamond_ticket = bytes_to_long(diamond_ticket[5:-1])
flag_chocolate = chocolate_generator(diamond_ticket)
chocolate_bag = []

#Willy Wonka are making chocolates
for i in range(1337):
    chocolate_bag.append(getRandomRange(1, p))

#And he put the golden ticket at the end
chocolate_bag.append(flag_chocolate)

#Augustus ate lots of chocolates, but he can't eat all cuz he is full now :D
remain = chocolate_bag[-5:]

#Compress all remain chocolates into one
remain_bytes = b"".join([c.to_bytes(p.bit_length()//8, "big") for c in remain])

#The last chocolate is too important, so Willy Wonka did magic again
P = getPrime(512)
Q = getPrime(512)
N = P * Q
e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")
d = pow(e, -1, (P - 1) * (Q - 1))
c1 = pow(bytes_to_long(remain_bytes), e, N)
c2 = pow(bytes_to_long(remain_bytes), 2, N) # A small gift

#How can you get it ?
print(f"{N = }")
print(f"{c1 = }")
print(f"{c2 = }") 

# N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
# c1 = 27062074196834458670191422120857456217979308440332928563784961101978948466368298802765973020349433121726736536899260504828388992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
# c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649
```

Once we've reversed the majority of the python code, we derive that:

$\text{chocolategenerator(160-bit flag)}$ is RSA encrypted with two exponents.

Lets first recover the RSA encrypted data. Because we have

$c_1 = m^{e} \bmod n$

and

$c_2 = m^{2} \bmod n$,

We may apply [Bezout's Identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity) and use the extended euclidean algorithm to find two integers $u, v$ such that $u * e + v * 2 == 1$. $1$ in this case because $e, 2$ are coprime with each other.

We then do $c_1^u * c_2^v = m^{u*e+v*2} = m$ to recover $\text{chocolategenerator(160-bit flag)}$.

```py
p, a, b = ...
N, c1, c2 = ...
e0 = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")
e1 = 2

def gcdExtended(a_, b_): 
    if a_ == 0: 
        return b_,0,1
    gcd,x1,y1 = gcdExtended(b_%a_, a_) 
    x = y1 - (b_//a_) * x1 
    y = x1 
    return gcd,x,y 

_, u, v = gcdExtended(e0, e1)
mm = pow(c1, u, N) * pow(c2, v, N) % N
assert pow(mm, e0, N) == c1 and pow(mm, e1, N) == c2
# print(mm.bit_length()) # this is around 640 bits, which is what we're looking for
```

Let us now focus on inversing $\text{chocolategenerator}$. It receives an integer input and computes $a^m + b^m \bmod p$. Solving such a problem reminds me of the [Discrete Logarithm Problem](https://en.wikipedia.org/wiki/Discrete_logarithm), and a quick check in multiplicative order of $a, b$ tells us that their order is equal to $\frac{p-1}{2}$, which happens to factorise easily into smaller primes. This means we can use algorithms such as [Pohlig-Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) and [Baby Step Giant Step](https://en.wikipedia.org/wiki/Baby-step_giant-step) to trivialise the discrete log. Meaning, given $a^m \bmod p, a, p$, the nature of $a$'s order allows for us to recover $m$ pretty efficiently. Instead of implementing the algorithms, we may use sage's own in-built `.log()` which essentially computes using the above algorithms. Regardless, I leave this here so that the reader may understand when one could use `.log()` to solve certain instances the Discrete Logarithm Problem, that is when the order is factorisable into small-enough prime factors.

However, just because the discrete log is easy does not necessarily mean that we can solve $a^m + b^m$, as the addition step makes things a lot more complicated.

Nevertheless, with some handy intuition I discovered that $b = a^{73331} \bmod p$.

We can thus rewrite the problem as solving $x + (x)^{73331} \equiv c\bmod p$ where $c$ is our recovered $\text{chocolategenerator}$ output and $x = a^{m} \bmod p$

We solve this polynomial equation using a handy trick to find divisors between it and $x^p - x \equiv 0 \bmod p$, which notably contains all $(x-r)$ factors from $0 \le r \le p-1$. I'll leave proof of this as an exercise to the reader. (Hint: [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem))

Notably, this gives us the common factor of $x + 43867895740074151195419905742714908098$, allowing us to recover $a^m \bmod p$. We can then derive $m$, convert to bytes, and...

```py
from sage.all import GF, PolynomialRing, identity_matrix, vector

F = GF(p)
P = PolynomialRing(F, 'x')
x = P.gen()
deg = GF(p)(b).log(GF(p)(a)) # 73331
assert pow(a, deg, p) == b

flag_choc = int.from_bytes(mm.to_bytes(1024//8, "big")[-(p.bit_length()//8):], "big")
# f = x + x**deg - flag_choc
# print("f done")
# g = pow(x, p, f)-x
# print("g done")
# print(f.gcd(g))
f1 = x + 43867895740074151195419905742714908098
am = f1.roots()[0][0]
flag = int(GF(p)(am).log(GF(p)(a)))
print(flag.to_bytes(20, "big"))
```
Output:
```
b'\x00\x00\x00\x00\x03\x9d\xf7\x8a\xec\xb7R\x15+J\xb6\xf3\x13\x81[\r'
```
Hm, that's not right.
```py
diamond_ticket = bytes_to_long(diamond_ticket[5:-1])
flag_chocolate = chocolate_generator(diamond_ticket)
```
`diamond_ticket` is supposed to be 20 bytes of the flag, which should be readable ascii. How is it that our inverse output contains hardly any readable characters?

Recall when I said $a$'s multiplicative order to be $(p-1)/2$. That is, $a^{\frac{p-1}{2}} \equiv 1 \bmod p$.

This means that if I have some solution $m$ for $a^m \equiv c' \bmod p$, then $m + \frac{p-1}{2}$ is also a valid solution; Or rather, any 
$m + k * \frac{p-1}{2}$ for some integer $k$ is a valid solution!

So we did not actually get $\text{diamondticket}$, but rather $r = \text{diamondticket} \bmod \frac{p-1}{2}$.

So, how can we efficiently recover $\text{diamondticket}$? $\frac{p-1}{2}$ is about 128 bits, and we know $\text{diamondticket}$ is around 160 bits. This would mean at least $2^{32}$ worth of brute searching, which while possible, is not so viable, espeically when there's a better solution.

Let's rewrite $\text{diamondticket} = 256^{19} * a_{19} + 256^{18} * a_{18} + ... + 256^{1} * a_1 + a_0$, where $a_0, a_1, ..., a_{19}$ represent our flag in bytes.

We then have:

$256^{19} * a_{19} + 256^{18} * a_{18} + ... + 256^{1} * a_1 + a_0 + (1) * (-r) + (k) * (\frac{p-1}{2}) = 0$

Since this equation is linear, we may express them as a lattice of the form:

```
1                       0   256^19
    1                   0   256^18
        1               0   256^17
            ...
                    1   0   256^0
                        -1  -r
                        0   -modulus
```

And hopefully, it will find our short vector $\lbrace{a_{19}, a_{18}, ..., a_0, -1, 0\rbrace}$. This is not the shortest possible vector however, so we will have to make a few modifications.

First, we scale the last two columns by, say, $2^8$ and $2^{16}$ accordingly so that the lattice reduction algorithm may 'prioritise' vectors ending with $\lbrace .., -256, 0\rbrace$.

We also modify the $\lbrace ..., -1, -r \rbrace$ row in our lattice to be $\lbrace-a, -a, ...., -a, -1, -r\rbrace$ where $a$ is our expected average of the byte characters. In this case, I used the `_` character (ascii 95) as the average. This way, when the lattice outputs the vector, the values for $a_{19}, a_{18}, ..., a_0$ will tend to average around $95$.

After running the [LLL](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm) lattice reduction algorithm, we take the vector ending with 
$\lbrace .., -256, 0\rbrace$, increment all values by $95$, and when we print it, we get a surprisingly readable string,

```
tks_f0r_ur_t1ck3t_xD
```

To double check, we parse it as $diamondticket$ and verify that the derived value post $\text{chocolategenerator}$ is what we have gathered.

```py
modulus = int(GF(p)(a).multiplicative_order())

aa = 95
M = (identity_matrix(20)
    .augment(vector([0]*20))
    .augment(vector([256**i for i in range(19, -1, -1)]))
    .stack(vector([-aa]*20 + [-1, -flag]))
    .stack(vector([0]*20 + [0, -modulus]))
)
M[:,-1] *= 2**16
M[:,-2] *= 2**8
for row in M.LLL():
    if row[-1] != 0:
        continue
    if row[-2] == 2**8:
        row *= -1
    if row[-2] == -2**8:
        try:
            diamond_ticket = b'idek{' + bytes([i+aa for i in row[:-2]]) + b'}'
            break
        except:
            continue
assert len(diamond_ticket) == 26
assert diamond_ticket[:5] == b"idek{"
assert diamond_ticket[-1:] == b"}"
flag_chocolate = chocolate_generator(bytes_to_long(diamond_ticket[5:-1]))
assert flag_chocolate == flag_choc
print(f'{diamond_ticket = }')
```

And voila, we have our flag,
```
diamond_ticket = b'idek{tks_f0r_ur_t1ck3t_xD}'
```