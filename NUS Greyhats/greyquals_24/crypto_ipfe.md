## IPFE (4 Solves, 997 Pts)

Now I know not of what `IPFE` actually is nor of the protocol, but being familiar with the `discrete logarithm problem / DLP` is all you need to solve this challenge! And perhaps knowledge of a certain oracle attack that I was not aware of during the ctf.

If you aren't as well acquainted with `DLP`, I'd recommend reading up a little bit on it. (honestly wikipedia is probably enough) Notably, some familiarity with common algorithms to solve it, such as `baby step giant step`, `pohlig hellman` as well as some understanding of `group theory` as a whole (i'd recommend Chapter 1 of https://venhance.github.io/napkin/Napkin.pdf) would help with digesting this writeup.

This writeup will first analyse the cryptosystem provided in `IPFE.py`, then touch how we can get the flag in `server.py`, as well as an oracle attack that we use in our exploit to obtain said flag. Feel free to jump straight to "The Challenge" if you are already well aware of the cryptosystem used.

`IPFE.py`
```py
from Crypto.Util.number import getPrime, isPrime, inverse
from secrets import randbelow
from gmpy2 import mpz
from typing import List, Tuple

# References:
# https://eprint.iacr.org/2015/017.pdf

def generate_prime():
    while True:
        q = getPrime(512)
        p = 2 * q + 1
        if isPrime(p):
            return mpz(p), mpz(q)
        
def discrete_log_bound(a, g, bounds, p):
    cul = pow(g, bounds[0], p)
    for i in range(bounds[1] - bounds[0] + 1):
        if cul == a:
            return i + bounds[0]
        cul = (cul * g) % p
    raise Exception(f"Discrete log for {a} under base {g} not found in bounds ({bounds[0]}, {bounds[1]})")

class _FeDDH_MK:
    def __init__(self, g, n: int, p: int, q: int, mpk: List[int], msk: List[int]=None):
        self.g = g
        self.n = n
        self.p = p
        self.q = q
        self.msk = msk
        self.mpk = mpk

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeDDH_MK(self.g, self.n, self.p, self.q, self.mpk)
    
class _FeDDH_SK:
    def __init__(self, y: List[int], sk: int):
        self.y = y
        self.sk = sk

class _FeDDH_C:
    def __init__(self, g_r: int, c: List[int]):
        self.g_r = g_r
        self.c = c

    
class IPFE:
    @staticmethod
    def generate(n: int, prime: Tuple[int, int] = None):
        if (prime == None): p, q = generate_prime()
        else: p, q = prime
        g = mpz(randbelow(p) ** 2) % p
        msk = [randbelow(q) for _ in range(n)]
        mpk = [pow(g, msk[i], p) for i in range(n)]

        return _FeDDH_MK(g, n, p, q, mpk=mpk, msk=msk)

    @staticmethod
    def encrypt(x: List[int], pub: _FeDDH_MK) -> _FeDDH_C:
        if len(x) != pub.n:
            raise Exception("Encrypt vector must be of length n")
        
        r = randbelow(pub.q)
        g_r = pow(pub.g, r, pub.p)
        c = [(pow(pub.mpk[i], r, pub.p) * pow(pub.g, x[i], pub.p)) % pub.p for i in range(pub.n)]

        return _FeDDH_C(g_r, c)
    
    @staticmethod
    def decrypt(c: _FeDDH_C, pub: _FeDDH_MK, sk: _FeDDH_SK, bound: Tuple[int, int]) -> int:
        cul = 1
        for i in range(pub.n):
            cul = (cul * pow(c.c[i], sk.y[i], pub.p)) % pub.p
        cul = (cul * inverse(sk.sk, pub.p)) % pub.p
        return discrete_log_bound(cul, pub.g, bound, pub.p)
    
    @staticmethod
    def keygen(y: List[int], key: _FeDDH_MK, c: _FeDDH_C) -> _FeDDH_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        
        t = sum([key.msk[i] * y[i] for i in range(key.n)]) % key.q
        sk = pow(c.g_r, t, key.p)
        return _FeDDH_SK(y, sk)
    
if __name__ == "__main__":
    n = 10
    key = IPFE.generate(n)
    x = [i for i in range(n)]
    y = [i + 10 for i in range(n)]
    c = IPFE.encrypt(x, key)
    sk = IPFE.keygen(y, key, c)
    m = IPFE.decrypt(c, key.get_public_key(), sk, (0, 1000))
    expected = sum([a * b for a, b in zip(x, y)])
    assert m == expected
```

As a brief summary, what we have is a public-private key cryptosystem whereby
```
Public key:
- generator g < q, with order q in the multiplicative group mod p
- range value n
- modulus prime p = 2*q + 1
- prime value q
- mpk[] = [pow(g, msk[i], p) for i in 0...n]

Private key:
- msk[] = [randbelow(q) for i in 0...n]
```
This summarises `IPFE.generate()`

Most of this cryptosystem seem to rely on the `discrete log problem (DLP)`; Given `g`, some modulus `p`, and `g^x mod p`, it is difficult to recover the exponent value `x`. In this case, assuming that the values `g, p, q` are chosen correctly (which in this case they are), it is very, very computationally difficult to recover any of the `msk[]` values from `mpk[]`. 

### Group Theory and g
---

You might notice my conclusion that `g` is chosen with "order `q` in the multiplicative group mod `p`". Let's split this statement up into smaller details and go through what they mean.

`group` - In discrete mathematics, we define a `group` as a set of elements with a group operation satisfying certain properties such as associativeness, inverses, and identity.

In the context of `IPFE` and the `discrete logarithm problem` in general, we have a group that is all elements `{1, 2, ..., p-1}` where `p` is some modulus. Notice that this group does not contain a zero, else it would violate the inverse property of a group. The group operation is `* mod p`, or the multiplication operation modulo `p`. You can derive that this set of elements defined that way satisfies the aforementioned group properties and is thus a group. We call this the `multiplicative group mod p`.

The `order` of a group, refers to the number of elements in it. In our case, we are observing a group with generator `g`. This means our set of elements is `{1, g, g^2, g^3, ...., }`. The next element in this set can be computed with the previous element multiplied by `g`, then modulo-ed `p`, unless said element already exists within the set, which implies that the set is finite as any new element would already be inside it. In our case, Fermat's Little Theorem ensures that there exist some upper bound `x` such that `g^x % p == 1`. 

When it comes to multiplicative integer groups modulo some number, if we let `y` be the order of an element `e` in any group mod `n` (i.e. the order of the subgroup with `e` as its generator), we have an interesting property that `e^y == 1 (mod n)`. Similarly, if we show that `e^y == 1 (mod n)` and `y` is the lowest possible number, then `y` has to be the order.

Notice that I've concluded that the subgroup generated by `g` has order `q`, or `q` elements. I'd like to first cite Lagrange's Theorem which states that,

```
For any finite group say G, the order of subgroup H of group G divides the order of G
```

So `g` can have order of either `1`, `2`, `q` or `2q = p-1`.

In `IPFE.py`, `g = mpz(randbelow(p) ** 2) % p`. 

If `g` has an order of `1`, this means `g` is the identity element, or `1`. Then `randbelow(p)` must give either `1` or `p-1`. In lieu of how large `p` is, we assume we'll never encounter such a case and move on.

If `g` has an order of `2`, then `g` must be the other square root of `1` mod `p`, `p-1`. But `p-1` is a quadratic non-residue mod `p` (it can be shown for any odd prime `p`, `(p-1) ^ ((p-1)/2) == -1 mod p` which implies non-residue by the legendre symbol) so it is not possible for `randbelow(p)**2` to give `p-1`.

This means either `q` or `2q` is the lowest number `x` such that `g^x % p == 1`. We know by Fermat's Little Theorem that `randbelow(p) ^ (p-1) == 1 mod p`, thus `randbelow(p) ^ 2q == 1`

Because `g = randbelow(p)^2`, we rewrite the above to obtain `g ^ q == 1 mod p`. Hence we arrive at `g` having an order of `q`.

We can generalise this result slightly further, actually. In our case where the group of integers mod p has order `p-1 = 2q`, for any primitive element `e` in this group, ignoring edge cases, the order of `e**even_number` will be `q` and that of `e**odd_number` `2q`. We define `primitive element` of a group to be an element where its order is the group order.

This serves as a more rigourous explanation, but if you yourself are well aware of the `pohlig hellman` algorithm, a common algo in `DLP`, you might be able to have derived this intuitively.

This comes into play later on in our exploit.

### Encrypt, Keygen, Decrypt

Onto the three main methods that this cryptosystem provides,
#### encrypt
```py
@staticmethod
def encrypt(x: List[int], pub: _FeDDH_MK) -> _FeDDH_C:
    if len(x) != pub.n:
        raise Exception("Encrypt vector must be of length n")
    
    r = randbelow(pub.q)
    g_r = pow(pub.g, r, pub.p)
    c = [(pow(pub.mpk[i], r, pub.p) * pow(pub.g, x[i], pub.p)) % pub.p for i in range(pub.n)]

    return _FeDDH_C(g_r, c)
```
Given the public key from before, `encrypt()` takes in a list of `n` integers represented in `x[]`, and does the following:

1. Choose random value `r < q`
2. Compute `g^r % p`, but keep `r` secret. `DLP` makes it hard to recover `r` from `g^r`
3. Compute list `c = [ (mpk[i]**r * g**x[i]) % p for i in 0...n]`. Applying what we know about `mpk[i]` equates this to `[ g^(msk[i]*r + x[i]) % p for i in 0...n ]`
4. Return `g^r % p` and `c`

It is implied that `(g^r, c)` in this case is the ciphertext, and the initial input `x` is the plaintext. Recovering `x` from `c` and `g^r` can be done so long as one knows the private key value `msk[i]`.

Consider `n = 1`, and we have plaintext `x0`, and ciphertext `g^r, c = g^(msk0 * r + x0)`. Knowing `msk0`, we can then do `(g^r)^msk0` to obtain `g^(msk0*r)`. Divide `c` by this to obtain `g^x0 mod p`. This is done by computing the modular multiplicative inverse of our divisor (either with custom library functions or using `pow(g^(msk0*r), -1, p)`), which gives us the equivalent of `1/g^(msk0*r)`.

With `g^x0 % p`, provided `x0` is within some small range `[lower_bound, upper_bound]`, we can then test for values within the boundary to obtain `x0`. We can extend this for any arbitrary `n`.

#### keygen
```py
@staticmethod
def keygen(y: List[int], key: _FeDDH_MK, c: _FeDDH_C) -> _FeDDH_SK:
    if len(y) != key.n:
        raise Exception(f"Function vector must be of length {key.n}")
    if not key.has_private_key():
        raise Exception("Private key not found in master key")
    
    t = sum([key.msk[i] * y[i] for i in range(key.n)]) % key.q
    sk = pow(c.g_r, t, key.p)
    return _FeDDH_SK(y, sk)
```

`keygen` serves as another way for one to decrypt the ciphertext without knowing the private key values `msk[]`, by generating a different key that can be used. It takes an input of n integers stored in `y[]`, and returns

`sk = g^(r * (msk0*y0 + msk1*y1 + ... % q) )`

From an application standpoint, we see that this cryptosystem provides this as an avenue for messages to be decrypted by others without the original user having to give them their own private key, so long as they have access to `keygen()`. Notice that only the original user with knowledge of `msk[]` can compute this.

A key thing to note here is that `msk0*y0 + msk1*y1 + ...` is done modulo `q`. This plays a major role in our exploit.

#### decrypt
```py
@staticmethod
def decrypt(c: _FeDDH_C, pub: _FeDDH_MK, sk: _FeDDH_SK, bound: Tuple[int, int]) -> int:
    cul = 1
    for i in range(pub.n):
        cul = (cul * pow(c.c[i], sk.y[i], pub.p)) % pub.p
    cul = (cul * inverse(sk.sk, pub.p)) % pub.p
    return discrete_log_bound(cul, pub.g, bound, pub.p)
```

`decrypt` uses the values provided from `keygen` to decrypt the ciphertext without leaking or using the private `msk[]` values. With all of the values from `encrypt()` and `keygen()`, it computes

`cul = PRODUCT( g^( (msk[i]*r + x[i]) * y[i]) ) / g^(r * (msk0*y0 + msk1*y1 + ...) )`

For now we will assume that `msk0*y0 + msk1*y1 + .... < q`. That way, we can equate this to just `msk0*y0 + msk1*y1 + ...` for simplicity.

The numerator simplifies to `g ^ (y0*msk0*r + y0*x0 + y1*msk1*r + y1*x1 + ...)`, which simplifies `cul` into `g ^ (y0*x0 + y1*x1 + ...)` after considering the denominator.

We see that it computes `discrete_log_bound(cul, pub.g, bound, pub.p)`, which given a boundary that the discrete log is in, tests all values within to obtain the discrete log, which in this case would be `y0*x0 + y1*x1 + ...`. The assumption is that from `y0*x0 + y1*x1 + ...`, one would be able to recover the original plaintext `{x0, x1, ...}`

There is an incredibly straightforward way to do so, especially since we control `y0, y1, ...`, thus we can select certain values such that from `y0*x0 + y1*x1 + ...` we can recover one or more values of `{x0, x1, ...}` without issue. I'll leave this as an exercise to the reader. (Hint: Suppose we can call `keygen() -> decrypt()` multiple times to recover `x[]`)

The solution can be derived from my solve script below anyway.

Regardless, as a brief summary, given any `c` ciphertext, there are two ways to obtain the plaintext `x[]`.

1. Know `msk[]`, allowing us to directly decrypt the ciphertext values as we see in `encrypt()`
2. Gain access to `keygen()`, which computes the secret key `sk` for us to use in `decrypt()`. Note that `keygen()` has to be done by the server for only the server knows `msk[]`. We can perform `decrypt()` on our own end once we know `sk`.

### The Challenge
---

Now we look on the provided `server.py` file, which is what we interact with when we connect to the remote server.
```py
from IPFE import IPFE, _FeDDH_C
from secrets import randbits

FLAG = 'REDACTED'

# Prime from generate_prime()
# To save server resource, we use a fix prime
p = 16288504871510480794324762135579703649765856535591342922567026227471362965149586884658054200933438380903297812918052138867605188042574409051996196359653039
q = (p - 1) // 2

n = 5
key = IPFE.generate(n, (p, q))
print("p:", key.p)
print("g:", key.g)
print("mpk:", list(map(int, key.mpk)))

while True:
    '''
    0. Exit
    1. Encrypt (You can do this yourself honestly)
    2. Generate Decryption Key
    3. Challenge
    '''
    option = int(input("Option: "))
    if (option == 0):
        exit(0)
    elif (option == 1):
        x = list(map(int, input("x: ").split()))
        c = IPFE.encrypt(x, key)
        print("g_r:", c.g_r)
        print("c:", list(map(int, c.c)))
    elif (option == 2):
        y = list(map(int, input("y: ").split()))
        g_r = int(input("g_r: "))
        dummy_c = _FeDDH_C(g_r, [])
        dk = IPFE.keygen(y, key, dummy_c)
        print("s_k:", int(dk.sk))
    elif (option == 3):
        challenge = [randbits(40) for _ in range(n)]
        c = IPFE.encrypt(challenge, key)
        print("g_r:", c.g_r)
        print("c:", list(map(int, c.c)))
        check = list(map(int, input("challenge: ").split()))
        if (len(check) == n and all([x == y for x, y in zip(challenge, check)])):
            print("flag:", FLAG)
        exit(0)
```

Much like our derived understanding of the `IPFE` cryptosystem, we are given `p, g, q, n, mpk[]`, with the private key value `msk[]` kept secret. We have access to `encrypt()` and `keygen()`, and to obtain the flag, we need to show that we can decrypt a ciphertext given challenge plaintext `[randbits(40) for _ in range(n)]` to obtain the flag.

Recall the 2 ways in which we can decrypt a ciphertext. Either we know `msk[]` directly, or we get the server to do `keygen()` for us. We can have it perform `keygen()`, but the moment we initiate the `challenge` we no longer have access to it! Note that in order to `keygen()` we need to give it `g^r % p`, but we only obtain that when we start the `challenge`. This eliminates the `keygen->decrypt` method which leaves us with the former. We'll have to derive `msk[]`, but the `DLP` clearly prevents us from doing so with `mpk[]` and `g`.

### The Exploit - keygen oracle leak
---

When the server calls `encrypt()`, using the public key value `g` with element order `q` as discussed, `g_r = g^r % p` and would therefore also have element order `q`. Because `q` is prime, regardless of where we are on the cycle of `g, g^2, g^3, ...., g^q == 1`, so long as `r != q`, our element would have an order of `q`.

Lets consider what this implies when we move into `keygen()`. Assuming we send a valid `g^r` with element order `q` to the server, the server calls `IPFE.keygen()` which performs `sk = (g^r) ^ (msk0*y0 + msk1*y1 + ... % q) )`. Notice how because `g^r` has order `q`, performing `(msk0*y0 + msk1*y1 + ... % q)` in the exponent would be the same as if we just did `(g^r)^(msk0*y0 + msk1*y1 + ...)`. Since we would always arrive back to `g^r` after `q` iterations, the mod `q` shortens the amount of processing time we'd need when computing it.

But things are different when we input in our own `g^r` (ill refer to this value as `g_r` now). What if this happens to have an order of `2q` instead? We'll assume `n = 1` for now, and show how we can derive `msk0`.

Suppose we input `y0 = 2`.
Then
`sk = g_r ^ (2 * msk0 % q)`

```
Case 1: 0 < msk0 < q/2
1. Then 0 < 2*msk0 < q
2. Therefore sk = g_r ^ (2 * msk0 % q) = g_r ^ (2*msk0)
3. Exponent is even.
4. By "Group Theory and g", g_r^2 and by extension sk would have an order of q.

Case 2: q/2 < msk0 < q
1. Then q < 2 * msk0 < 2q.
2. Therefore sk = g_r ^ (2 * msk0 % q) = (2 * msk0 - q)
3. q is odd, so the exponent 2*msk0 - q is odd.
4. By "Group Theory and g", sk would not have an order of q, but retain g_r's original order of 2q
```

We can then compute `pow(sk, q, p)` and if it returns `1`, then `msk0 < q/2`. Otherwise, `msk0 > q/2`! 

Suppose `Case 2` is true and we now try `y0 = 4`, `sk = g_r ^ (4 * msk0 % q)`. (you can probably derive the same results for when msk0 < q/2 on your own.)
```
Case 2A: q/2 < msk0 < 3q/4
1. Then 2q < 4*msk0 < 3q
2. Then sk = g_r ^ (4 * msk0 % q) = g_r ^ (4 * msk0 - 2q)
3. Exponent is even.
4. By "Group Theory and g", g_r^2 and by extension sk would have an order of q.

Case 2B: 3q/4 < msk0 < q
1. Then 3q < 4*msk0 < 4*q
2. Therefore sk = g_r ^ (4 * msk0 % q) = g_r ^ (4 * msk0 - 3q)
3. Exponent is odd.
4. By "Group Theory and g", sk would not have an order of q, but retain g_r's original order of 2q
```

We can repeat this for ever increasing powers of 2 in y0 to binary search our way to find `msk0`!

Now in the case of `n = 5`, we can simulate a `n = 1` by sending `y = [2^i,0,0,0,0]` to the server during `keygen()`, obtaining `msk0`. We then do `[0,2^i,0,0,0]` to get `msk1`, etc. till we recover `msk[]`.

With `msk[]`, we can then decrypt and obtain the values of `g^x0`, `g^x1`, `g^x2` from the ciphertext. The only issue is to now solve the discrete log problem, and because we know `x0, x1, x2 < 2**40`, we can use algorithms such as `pollard-rho` or `baby step giant step` to solve for the dlog.

```py
from IPFE import IPFE, _FeDDH_C
from secrets import randbits
from pwn import remote

def brute_dlog(g,h,p,lo,hi):
    # brute force discrete log given lower bound and upper bound
    gg = pow(g, lo, p)
    for i in range(lo,hi+1):
        if gg == h:
            return i
        gg = gg * g % p
    return -1

# local testing equivalent
# p = 16288504871510480794324762135579703649765856535591342922567026227471362965149586884658054200933438380903297812918052138867605188042574409051996196359653039
# q = (p - 1) // 2
# n = 5
# key = IPFE.generate(n, (p, q))
# g = key.g
# mpk = key.mpk

r = remote('challs.nusgreyhats.org', 35102)
p = int(r.recvline().rstrip().split(b':')[-1])
q = (p - 1) // 2
n = 5
g = int(r.recvline().rstrip().split(b':')[-1])
mpk = eval(r.recvline().rstrip().split(b':')[-1])

print(f'p = {p}')
print(f'g = {g}')
print(f'mpk = {mpk}')

"""
Use sagemath to find primitive element
p = 16288504871510480794324762135579703649765856535591342922567026227471362965149586884658054200933438380903297812918052138867605188042574409051996196359653039
GF(p).primitive_element() # 7
"""
gr = 7

# Recovering msks values from mpks
recovered_msks = []
for ptr in range(5):
    mpk_val = mpk[ptr]

    # My method uses python integers and with the bit leakage, perform a binary search to recover msk_i.
    # There is a slight issue in that this, on local testing, seems to fail when upper_bound - lower_bound <= 2**16 for some unknown reason. 
    # In that when its really small there's a high chance of mess up. 
    # I have some idea as to why it occurs, but my attempts to patch it have failed lmao

    upper_bound = q
    lower_bound = 0
    bits = 1

    # Sending and waiting from the server 500 times will exhaust the timer. So we batch our payloads and send them in one go.
    payload = b''
    for _ in range(500):
        y = [pow(2,bits,q) if i == ptr else 0 for i in range(n)]
        payload += b'2\n'
        payload += b' '.join([str(i).encode() for i in y]) + b'\n'
        payload += str(gr).encode() + b'\n'
        bits += 1
    r.sendline(payload[:-1]) # ignore last newline char as sendline would add its own newline

    # Recv would be fully automatic now, as the server would be sending us data of ALL 500 sk values
    for _ in range(500):
        r.recvuntil(b's_k: ')
        sk = int(r.recvline().rstrip())
        sk = pow(sk, q, p) 

        # local testing equivalent:
        # y = [pow(2,bits,q) if i == ptr else 0 for i in range(n)]
        # bits += 1
        # sk = IPFE.keygen(y, key, _FeDDH_C(gr, [])).sk   # g ^ (msk * y % q) % p
        # sk = pow(sk, q, p)                              # g ^ (q * (msk*y % q) % (p-1)) % p

        if (sk == 1): 
            upper_bound = (upper_bound+lower_bound)//2 + 1
        else:
            lower_bound = (upper_bound+lower_bound)//2 - 1
    ans = brute_dlog(g,mpk_val,p,lower_bound,upper_bound)
    print(f'Recovered msks[{ptr}] = {ans}')
    recovered_msks.append(ans)


# Preparing functions for the challenge section...
print("Generating lookup for bsgs algorithm...")
gtable = {}
gg = 1
for i in range(2**20):
    gtable[gg] = i
    gg = gg * g % p
print("Lookup generated.")

def bsgs(h,g,p):
    # Implements Baby Step Giant Step algo to find the discrete log
    # This assumes that the exponent in question is within 2**40, which is true in the context of where its used
    # See https://en.wikipedia.org/wiki/Baby-step_giant-step
    m = 2**20
    alpha = pow(g, -m, p)
    beta = h
    for i in range(m):
        if beta in gtable:
            return i*m + gtable[beta]
        beta = beta * alpha % p
    return -1

def decrypt_ctxt(cgr, cc, msks):
    ptxts = []
    ptr = 0
    for c, msk in zip(cc, msks):
        div = pow(cgr, msk, p)
        c *= pow(div, -1, p) % p
        ptxt = bsgs(c,g,p)
        print(f'Recovered c{ptr} = {ptxt}')
        ptr += 1
        ptxts.append(ptxt)
    return ptxts


r.sendline(b'3')
cgr = int(r.recvline().rstrip().split(b':')[-1])
cc = eval(r.recvline().rstrip().split(b':')[-1])

# local testing equivalent
# challenge = [randbits(40) for i in range(n)]
# print(f'challenge = {challenge}')
# c = IPFE.encrypt(challenge, key)
# cgr, cc = c.g_r, c.c

output = decrypt_ctxt(cgr, cc, recovered_msks)
r.sendlineafter(b'challenge: ', b' '.join([str(i).encode() for i in output]))
print(r.recvline().rstrip()) # flag!
r.close()
```

```
[x] Opening connection to challs.nusgreyhats.org on port 35102
[x] Opening connection to challs.nusgreyhats.org on port 35102: Trying 35.198.239.93
[+] Opening connection to challs.nusgreyhats.org on port 35102: Done
p = 16288504871510480794324762135579703649765856535591342922567026227471362965149586884658054200933438380903297812918052138867605188042574409051996196359653039
g = 2676964939920921928399642508727782288697790956026352656348732296276639129254362463847726372149190333848416592417168522150303582850322837038871901289978449
mpk = [10663699396187500113248965012062070299806219380346278179475714238117875255034577944645507102593765832765150568548346175576342744349240112634921162131665827, 14798698814950995574994502847833688245069642825756270198953980320022979510580003935200723834886409562873853806301895782378523036846394077921584424913195708, 1429288834347362142471576846377404166378275983963538608742109802025385975867269135393813410699528193541804026974729083055519024075619562926521368207067375, 7886805335567665728485655639344647998776792964242541735503305533430160171196868425513344288395731869363659550164970332923772707256516426988091214039066826, 15139175003506921923217572114959410245840727113514319315949676531548421035881272375761312705737849047247914623161938105529387066389375613395364154342609906]
Recovered msks[0] = 1363994450155937792022264682414012285537559238796299956943759059524365126448007442848860383518560468749613094326310178303803081655098660379879141148279600
Recovered msks[1] = 4354937585144604389997594106432177851707182815636330126091314716365134314897195927968351662724063047279893613437694148503188238950828182451049533816272948
Recovered msks[2] = 6221476561203681157975234312535006404846341602660940068206081364162543537438575571523001630500574208242150003046713744719616173470661746860092559605102091
Recovered msks[3] = 4061760109462023130647026979386719205897503252259004697809859547573877935143879582699046985750296045956618448138899855757583721785732313409971012295488656
Recovered msks[4] = 3000296672723565880559627095465693845600018178096281778752020723143093360944818197204645356846213307191046829087656997004262764712940576327554106010850568
Generating lookup for bsgs algorithm...
Lookup generated.
Recovered c0 = 869669044919
Recovered c1 = 724509157061
Recovered c2 = 873439740279
Recovered c3 = 908233758333
Recovered c4 = 272819867578
b'flag: grey{catostrophic_failure_7eE37WLLdYgg}'
[*] Closed connection to challs.nusgreyhats.org port 35102
```