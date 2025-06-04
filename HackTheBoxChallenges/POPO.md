### LostKey
---

#### Files
`server.py`
```py
from secret import FLAG
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, GCD
from random import randint
from math import lcm

class POPO:
    def __init__(self, m):
        self.m = m
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.n = self.p * self.q
        self.phi = (self.p-1) * (self.q-1)
        self.l = lcm(self.p-1, self.q-1)
        self.n2 = self.n * self.n
        self.g = self.n + 1
        self.gm = pow(self.g, self.m, self.n2)
        self.optim = 0
        while GCD(self.g, self.n) != 1 or \
              GCD(self.g-1, self.n) != 1 or \
              GCD(self.n, (pow(self.g, self.l, self.n2) - 1) // self.n) != 1:
            self.g = randint(self.n, self.n2)
        self.r = randint(self.n, self.n2)

    def anonymize(self, m, r=0):
        if m < 0:
            return {'c': 'No, some mind got you', 'n': self.n}

        if m != self.m and m > 0:
            if self.optim == 0:
                local = pow(self.g, m, self.n2)
            else:
                local = m
        else:
            local = self.gm

        if self.optim == 0:
            self.optim = 1

        if r == 0:
            r = self.r
        
        b = pow(r, self.n, self.n2)
        c = local * b % (self.n2)
        return {'c' : c, 'n' : self.n}

    def encrypt(self, m, r):
        return self.anonymize(m, r)

    def reset_optim(self):
        self.optim = 0

    def test_standard_encryption(self, m1, m2):
        r1 = randint(0, self.n)
        r2 = randint(0, self.n)
        c1 = self.encrypt(m1, r=r1)["c"]
        self.reset_optim()
        c2 = self.encrypt(m2, r=r2)["c"]
        self.reset_optim()
        return {'additive_he' : (c1*c2) % (self.n2), 'res' : (c1*c2) % (self.n2) == self.encrypt(m1 + m2, r1*r2)['c']}

    def validate_role(self, gm):
        if gm == self.gm:
            return {'λ' : self.l}
        else:
            return {"Error": "not enough knowledge provided"}


def menu():
    print("\nPOPO - v.1.0.0. Choose your action:\n")
    print("1. Encrypt")
    print("2. Knowledge proof")
    print("3. Test homomorphic encryption")
    print("4. Reset optimization")

    option = input("\n> ")
    return option

def main():
    popo = POPO(bytes_to_long(FLAG))

    while True:
        choice = int(menu())
        try:
            if choice == 1:
                menu_m = input("\nProvide a message: ").strip()
                print(popo.anonymize(int(menu_m)))
            elif choice == 2:
                menu_gm = input("\nProvide gm: ").strip().encode()
                print(popo.validate_role(int(menu_gm)))
            elif choice == 3:
                menu_multiple_m = input("\nProvide two messages formatted as m1,m2 : ").strip().encode().split(b',')
                print(popo.test_standard_encryption(bytes_to_long(menu_multiple_m[0]), bytes_to_long(menu_multiple_m[1])))
            elif choice == 4:
                popo.reset_optim()
            else:
                print('Nothing to see here.')
                exit(1)
        except Exception as e:
            print("Error during execution")

if __name__ == "__main__":
    main()
```

#### Writeup
We are introduced to a server instance that gives us an oracle to some cryptosystem. It might seem very confusing at first, but we are essentially looking at the [Paillier Cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem). I'd recommend reading the article for familiarity.

Comparing the algorithm with what we are given, we find a few oddities.
```py
        while GCD(self.g, self.n) != 1 or \
            GCD(self.g-1, self.n) != 1 or \
            GCD(self.n, (pow(self.g, self.l, self.n2) - 1) // self.n) != 1:
            self.g = randint(self.n, self.n2)
```
First off, this code block in `init()` always ensure `self.g = self.n + 1` is changed after `self.gm` is computed (do you see why?)

```py
        if m != self.m and m > 0:
            if self.optim == 0:
                local = pow(self.g, m, self.n2)
            else:
                local = m
        else:
            local = self.gm

        if self.optim == 0:
            self.optim = 1
```
Secondly, this addition to the encrypt (`anonymise()`) function, uses some sort of optimisation. I'm guessing the server expects one to send $m$, then %g^m$ after and tries to "optimise" itself to avoid doing the `pow()` operation. This works if the server checks the input, but it doesn't! We can abuse this to encrypt any $m \rightarrow m * r^n \bmod n^2$, whereas standard Paillier performs $m \rightarrow g^m * r^n \bmod n^2$.

```py
def validate_role(self, gm):
        if gm == self.gm:
            return {'λ' : self.l}
        else:
            return {"Error": "not enough knowledge provided"}
```
Thirdly, there is an additional function `validate_role()`, which gives us one half of the private key, $\lambda = \text{lcm}(p-1, q-1)$. With $\lambda$ we can recover the other private key $\mu$, allowing us to decrypt any encrypted message.

We also observe that `self.gm` is $(n+1)^{\text{flag}}$, and we can also, by sending certain inputs and abusing the "optimisation", obtain $g^m r^n \bmod n^2$ which is just the Paillier encrypted flag. If we can find `self.gm`, we can receive $\lambda$, then $\mu$, and then we can decrypt it directly!

The fourth, and final observation, is that when we access the oracle to encrypt a given value, the `r` parameter used is constant. This is significant, as we can then recover `self.gm` using modular arithmetic.

We combine all four observations to derive the flag.

#### solve.py
```py
def solve():
    popo = POPO(bytes_to_long(FLAG))

    # Derive gm, lambda
    _ = popo.anonymize(1) # optim = 0
    ct_1 = popo.anonymize(1) # optim = 1
    ct_2 = popo.anonymize(0) # optim = 1
    rn, n = ct_1["c"], ct_1["n"]
    gm = ct_2["c"] * pow(rn,-1,n**2) % n**2
    lam = popo.validate_role(gm)['λ'] # private key!
    
    # Decrypt encrypted self.m
    L = lambda x:(x-1)//n
    gm_g = n + 1
    mu = pow( L(pow(gm_g, lam, n**2)), -1, n)
    m = L(pow(ct_2["c"], lam, n**2)) * mu % n
    print(long_to_bytes(m)) # FLAG

solve()
```

Modifying the above with pwntools:
```py
from pwn import remote
import json

r = remote("...",...)
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'Provide a message: ')
r.sendline(b'1')
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'Provide a message: ')
r.sendline(b'1')
ct_1 = json.loads(r.recvline().rstrip().decode().replace("'",'"'))
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'Provide a message: ')
r.sendline(b'0')
ct_2 = json.loads(r.recvline().rstrip().decode().replace("'",'"'))

rn, n = ct_1["c"], ct_1["n"]
gm = ct_2["c"] * pow(rn,-1,n**2) % n**2

r.recvuntil(b'> ')
r.sendline(b'2')
r.recvuntil(b'Provide gm: ')
r.sendline(str(gm).encode())
res = json.loads(r.recvline().rstrip().decode().replace("'",'"'))
r.close()

L = lambda x:(x-1)//n
lam = res['λ']
gm_g = n + 1
mu = pow( L(pow(gm_g, lam, n**2)), -1, n)
m = L(pow(ct_2["c"], lam, n**2)) * mu % n
print(m.to_bytes((m.bit_length() + 7) // 8, "big")) # b'HTB{s0_r3p3t1t10n_15_4_p41ll13r_thr34t!}'
```