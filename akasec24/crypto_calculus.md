## My Calculus Lab

`chall.py`
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import sympy as sp
import random

FLAG = b'REDACTED'

key = random.getrandbits(7)

x = sp.symbols('x')

f = "REDACTED"
f_prime = "REDACTED"
f_second_prime = "REDACTED"

assert(2*f_second_prime - 6*f_prime + 3*f == 0)
assert(f.subs(x, 0) | f_prime.subs(x, 0) == 14)

def encrypt(message, key):
    global f
    global x
    point = f.subs(x, key).evalf(100)
    point_hash = hashlib.sha256(str(point).encode()).digest()[:16]
    cipher = AES.new(point_hash, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return iv.hex() + ciphertext.hex()

encrypted = encrypt(FLAG, key)

print(f"Key: {key}")
print(f"Encrypted: {encrypted}")

# Key: 60
# Encrypted: 805534c14e694348a67da0d75165623cf603c2a98405b34fe3ba8752ce24f5040c39873ec2150a61591b233490449b8b7bedaf83aa9d4b57d6469cd3f78fdf55
```

Did not expect to revisit calculus and differential equations when looking at a cryptography challenge. We are given three unknown functions, `f`, `f_prime`, `f_second_prime`. Now the term "f prime" is often used in spoken language to mean the derivative of some function f.

We also have these two givens;
```py
assert(2*f_second_prime - 6*f_prime + 3*f == 0) # 2 f'' - 6 f' + 3 f = 0
assert(f.subs(x, 0) | f_prime.subs(x, 0) == 14) # f(0) | f'(0) = 14
```
From here, we are expected to derive `f(x)` so as to compute `f(key)`, where `key` is a known value. This value is taken up to 100 decimal places and then hashed with `sha256` to be used as an `AES` key to encrypt the flag.

From the two givens, we can brute possible solutions to `f(x)`, and then plug each possible function in and run it through the decryption process to see if we obtain the flag.

A funny thing to note is that the challenge itself was programmed incorrectly. I'm guessing from the use of `.subs()` in the challenge code that the creator had relied on sagemath to initialise the functions, which uses `^` for exponentiation. The creator then used the `sympy` python library, evaluated the function as is and plugged in `key` as the value, even though this would get the mathematically incorrect output; Python and its sympy library treats `^` as the xor operation instead of exponentiation, thus incorrectly computing `f(key)`.

`solve.py`
```py
from sage.all import *
import hashlib
import sympy as sp
from Crypto.Cipher import AES

key = 60
encrypted = bytes.fromhex("805534c14e694348a67da0d75165623cf603c2a98405b34fe3ba8752ce24f5040c39873ec2150a61591b233490449b8b7bedaf83aa9d4b57d6469cd3f78fdf55")
iv = encrypted[:16]
ct = encrypted[16:]

for v0 in range(2**4):
    for v1 in range(2**4):
        if v0 | v1 != 14:
            continue

        # Set up and solve the differential equation
        x = var('x')
        y = function('y')(x)
        yp = diff(y, x)
        ypp = diff(yp, x)
        f = desolve(2*ypp - 6*yp + 3*y == 0, y, ics=[0,v0,v1], ivar=x)

        fp = derivative(f, x)
        assert int(fp(x=0)) == v1 and int(f(x=0)) == v0
        
        # Test for flag
        point = f(x=key)
        # point = str(point).replace('^', '**') 
        # # The challenge is flawed here, to get the flag we need sympy to derive the wrong/incorrect answer as it mistakes sage's exponentiation for xor.

        val = sp.N(point, 100)
        point_hash = hashlib.sha256(str(val).encode()).digest()[:16]
        cipher = AES.new(key=point_hash, iv=iv, mode=AES.MODE_CBC)
        msg = cipher.decrypt(ct)
        if b'AKA' in msg:
            print(msg) # b'AKASEC{d1d_y0u_3nj0y_c41cu1u5_101?}\r\r\r\r\r\r\r\r\r\r\r\r\r'
```