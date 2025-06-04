### rhome
---

#### Files
`server.py`
```py
from Crypto.Util.number import isPrime, long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randint
from hashlib import sha256

from secret import FLAG


class DH:

    def __init__(self):
        self.gen_params()

    def gen_params(self):
        self.r = getPrime(512)

        while True:
            self.q = getPrime(42)
            self.p = (2 * self.q * self.r) + 1
            if isPrime(self.p):
                break

        while True:
            self.h = getPrime(42)
            self.g = pow(self.h, 2 * self.r, self.p)
            if self.g != 1:
                break

        self.a = randint(2, self.p - 2)
        self.b = randint(2, self.p - 2)

        self.A, self.B = pow(self.g, self.a, self.p), pow(self.g, self.b, self.p)
        self.ss = pow(self.A, self.b, self.p)

    def encrypt(self, flag_part):
        key = sha256(long_to_bytes(self.ss)).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag_part, 16)).hex()
        return f"encrypted = {ct}"

    def get_params(self):
        return f"p = {self.p}\ng = {self.g}\nA = {self.A}\nB = {self.B}"


def menu():
    print("\nChoose as you please\n")
    print("1. Get parameters")
    print("2. Reset parameters!! This can take some time")
    print("3. Get Flag")

    option = input("\n> ")
    return option


def main():
    dh = DH()

    while True:
        choice = int(menu())
        if choice == 1:
            print(dh.get_params())
        elif choice == 2:
            dh.gen_params()
        elif choice == 3:
            print(dh.encrypt(FLAG))
        else:
            print('See you later.')
            exit(1)


if __name__ == "__main__":
    main()
```

#### Writeup

We have access to a server oracle with 3 functionalities. First off, it implements an instance of a Diffie-Hellman key exchange esque, which is based off of the Discrete Logarithm Problem (DLP). The latter describes a scenario where given a modulus $p$, generator $g$ and value $g^k$ mod $p$ for some unknown integer $k$, it is hard to recover $k$. This statement is true, so long as the order, i.e. the smallest value $n$ such that $g^n$ mod $p = 1$, is large enough to deter most attacks.

We see the use of DLP in `gen_params()`:

```py
        self.r = getPrime(512)
        while True:
            self.q = getPrime(42)
            self.p = (2 * self.q * self.r) + 1
            if isPrime(self.p):
                break

        while True:
            self.h = getPrime(42)
            self.g = pow(self.h, 2 * self.r, self.p)
            if self.g != 1:
                break
```
which generates the $g, p$ parameters.

```py
        self.a = randint(2, self.p - 2)
        self.b = randint(2, self.p - 2)

        self.A, self.B = pow(self.g, self.a, self.p), pow(self.g, self.b, self.p)
        self.ss = pow(self.A, self.b, self.p)
```

The remaining code simulates the Diffie-Hellman key exchange. Secret values $a, b$ are generated, then the public values $A = g^a, B = g^b$. The shared secret is done by computing $S = A^b = b^A = g^{ab}$. This is used in public key cryptography to derive some shared secret that can be used as a key for two users to communicate; Both users just need to keep their unknowns $a, b$ private and known only to themselves.

This brings us to the first functionality, which tells us $p, g, A, B$. The second functionality generates a new set of parameters, while the third functionality uses the shared secret $S$ to encrypt the flag.

It suffices to recover $S$ to decrypt the flag, meaning we must either solve the DLP instance $(p, g, A)$ or $(p, g, B)$. We just need to find any $a, b$ modulo $g$'s order to recover the shared secret $S$.

The DLP instances here are actually very solvable, due to the way $p$ and $g$ are generated.

We first use Fermat's Little Theorem, which tells us for prime $p$, for all values $0 < g < p$, $g^{p-1} == 1$ mod $p$. So the order of the DLP instances is either $p-1$ (too big), or a factor of $p-1$.

We observe that $p-1 = 2*q*r$, where $q$ is a 42-bit prime and $r$ is some large prime. Even more interestingly, $g = h^{2r}$ mod $p$ where $h$ is some prime number.

There can only be 3 possibilities, here.

1. $h$ has order $2, r$ or $2r$. In any case we have $g = 1$, and the DLP instance $(g, p, A)$ is trivial. (this is incredibly unlikely to happen, so we'll ignore this case)
2. $h$ has order that includes $q$ as a factor. Thus, $h^{kq} = 1$ mod $p$ with $k \in \lbrace 0, 2, r, 2r\rbrace$. In any of these cases, it can be shown that $(h^{2r})^q == 1$ mod $p$, thus we can take $g = h^{2r}$ as order $q$. (in fact, for any $h$, $g$ will always have order $q$ except for Case 1!)

Thus it suffices to solve the DLP instance $(p, g, A)$ over $q$. We can use an algorithm such as Baby-Step-Giant-Step, which reduces a naive brute force over $2^{42}$ to just $2^{21}$. Implement the algorithm from wikipedia or any other source and we can recover the private $a$ value. Note we can recover $q$ by just factoring $p-1$. Since $q$ is relatively small, algorithms such as ECM can be used to get $q$ quickly. (or use online tools such as Alpertron)

We can then recover $S = B^a$ mod $p$, thus getting the key to decrypt the flag.

#### solve.py
```
> ncat 83.136.249.253 39948

Choose as you please

1. Get parameters
2. Reset parameters!! This can take some time
3. Get Flag

> 1
p = 65419228347452449679593509233244397883327844865514519799685152866065876582623961265606792801888196452821919734951852993599464235556143280359616200765243924359675233439
g = 62961245303364006413331321824365528006655388178414215022223367881737273266613380045189034724303322496958068429469380280259998515274649344287004080417909956693366970687
A = 24754329036283544027937684187251670314642495849877933600016934134637776481392085436792332497292611629194033663948263821253997031633028928551725078806750294011968797003
B = 8115180076991847432455979843205818897965998231097448436980885912096212171023700524387431726062621851669584961045345044321057695237350515703918553146644147702607938507

Choose as you please

1. Get parameters
2. Reset parameters!! This can take some time
3. Get Flag

> 3
encrypted = 0b4650adec9db1755000b044427aa332db9a41fbe62bc76c84ba68330ddb7408

Choose as you please

1. Get parameters
2. Reset parameters!! This can take some time
3. Get Flag

> ^Z
```
```py
p = ...
g = ...
A = ...
B = ...
q = 2580472736267
encrypted = bytes.fromhex("...")

# Use Wikipedia's pseudocode for bsgs
from math import ceil, sqrt
def bsgs(g, p, A, q): # fun fact this code runs in less than 5 seconds!
    m = ceil(sqrt(q))
    g_ = 1
    l1 = []
    ls = set() # much faster lookup
    for j in range(0, m):
        l1.append(g_)
        ls.add(g_)
        g_ = g_ * g % p
    gm = pow(g, -m, p)
    y = A
    for i in range(0, m):
        if y in ls:
            return i*m + l1.index(y)
        y = y * gm % p
    return -1

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

a = bsgs(g, p, A, q)
print(a) # 403522366855 in our case
S = pow(B,a,p)
key = sha256(long_to_bytes(S)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
pt = cipher.decrypt(encrypted)
print(pt) # b'HTB{00ps_wh4t_4_sm411_0rd3r}\x04\x04\x04\x04'
```