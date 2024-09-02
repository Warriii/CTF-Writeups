### Crypto - Ye Olde Radio (0 Solve, 1000 pts)
```
this dusty radio doth work still! a flag resides within, if thou beat its authenticator ere the time is up

nc chal-1.isc2sgyouth.com 10000

nc chal-2.isc2sgyouth.com 10000 (Mirror)

Author: warri
```

`app.py`
```py
#!/usr/bin/python3
from secret import FLAG
from time import time
from random import choices
from Crypto.Util.number import getPrime, bytes_to_long


class Challenge:

    def __init__(self):
        self.reset()
        self.gen()

    def __repr__(self):
        return (self.n, self.c).__repr__()
    
    def reset(self):
        self.m = "".join(choices("abcdefghijklmnopqrstuvwxyz", k=8)).encode()

    def gen(self):
        self.n = getPrime(1024)*getPrime(1024)
        self.e = 0x101
        self.c = pow(bytes_to_long(self.m), self.e, self.n)

    def validate(self, m):
        return m == self.m


if __name__ == "__main__":
    tval = time()
    ch = Challenge()
    while True:
        print("1. authenticate thy own identity")
        print("2. exuent and revisit thee odd radio later")
        ui = input(">> ")
        if ui.startswith('1'):
            curr = time()
            if (curr - tval) > 15:
                print("thy time is long over! resetting mine values")
                ch.reset()
                tval = curr
            ch.gen()
            print(ch)
            resp = str(input(">> ")).encode()
            if ch.validate(resp[:8]):
                print("thou are forsooth worthy of this flag")
                print(FLAG)
                exit(0)
            else:
                print("thou shall not pass! (to mine flag)")
        elif ui.startswith('2'):
            exit(1)
        else:
            print("thou hast entered an invalid input! how dare thou!!")
```

For `ye olde radio` i wanted to make a cryptography challenge involving a well known attack that isn't particular hard to understand, but also desired to make a spin on it such that one ought to understand the logic behind to see that such an attack is feasible.

The challenge code guides one to an authenticator where a 8-byte message `m` is randomly generated. One can then obtain various `(n, c)` pairs where `n` is a 2048-bit modulus involving 2 1024-bit primes and `c = pow(m, 257, n)`. Within 15 seconds, one is supposed to be able to derive the message `m`. The encryption used is standard RSA encryption, which the challenges `saltedRSA` and `its really BIG` made by fellow challenge author `sunshinefactory` should familiarise one with already. That said, to those curious on how the RSA encryption system works, feel free to check out [my writeup on grey welcome ctf 2024 here](../nus_greyhats/greywelcome_24/crypto_intro_to_rsa.md)

### Radio Broadcasting and The Chinese Remainder Theorem
Anyway, the challenge is based off a well known attack on RSA involving an encryption oracle, being [Hastad's Broadcast Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad's_broadcast_attack). The idea lies in that if you have `e` different `m^e % n` for same `m` but different `n`s, you can recover `m^e` and from there deduce `m`.

This works primarily because of the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem), which given a set of remainders `{r0, r1, ..., ri}` modulo a set of moduli `{m0, m1, ..., mi}`, returns a unique value `r` that satisfies all of these remainders modulo the lowest common multiple of the moduli.

Given `e` different `m^e % n`, we have `e` remainders of `e` different `n`s, and the chance of two `n`s having a shared prime factor is pretty low enough to be negligible. (and in such a case, decrypting m would be trivial). The chinese remainder theorem can then compute a unique value satisfying all of these remainders modulo the lowest common multiple, which would be the product of all `e` ns.

Since we also know that `m < n` for all of our `n` values, therefore `m^e < product(e different n)`. Hence, whatever value the chinese remainder theorem returns, it must be equal to `m^e`. From there, we can use inverse root functions such as Python's `gmpy2.iroot()` to derive `m` from `m^e`.

### Optimisations at the Bit Level!

Thus, given `e = 257` in our challenge code, having 257 `(n, c)` pairs would be sufficient to apply our attack. But in a 15 second time limit, we can usually only obtain up to 12 or so pairs at best. So this attack would not work, right?

Not exactly! Consider the fact that `m` is 8 bytes, and we know that the most significant bit of `m` is 0 (due to the way ASCII characters are encoded), meaning `m < 2**64`.

So `m^257 < 2**(64*257) = 2**16448`

Since `n` is 2048 bits, the product of 8 coprime `n` would be `> 2**(2048*8) = 2**16384`. With one more 2048-bit `n`, the output of the Chinese Remainder Theorem would naturally be modulo some number `> 2**16448`, thus it has to be equal to `m^257`

This reduces the number of `(n,c)` pairs we need to only 9 (and in reality we only need 8). All we have to do is to implement Hastad's Broadcast Attack to find `m`, then pass the authenticator just in time to recover our flag.

`sol.py`
```py
from pwn import process, remote
from Crypto.Util.number import long_to_bytes
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from time import time
from tqdm import trange

start = time()
r = process('./app.py') # or remote(...)

def get_data(r):
    r.recvuntil(b'>> ')
    r.sendline(b'1')
    n, ct = eval(r.recvline().rstrip())
    r.recvuntil(b'>> ')
    r.sendline(b'AAAAAAAA')
    return n, ct

ns, cts = [], []
for _ in trange(8):
    n, ct = get_data(r)
    ns.append(n)
    cts.append(ct)
m257, mods = crt(ns, cts)
msg = iroot(m257, 257)[0]

r.recvuntil(b'>> ')
r.sendline(b'1')
r.recvuntil(b'>> ')
r.sendline(long_to_bytes(msg))
print(r.recvline()) # thou are forsooth worthy of this flag
print(r.recvline()) # ISC2CTF{this_is_why_google_authenticator_doesnt_do_challenge_response_rsa}
r.close()
print(time() - start)
# on remote this only takes 11 seconds
```