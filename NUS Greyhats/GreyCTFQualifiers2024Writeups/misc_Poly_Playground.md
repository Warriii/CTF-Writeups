### Poly Playground (120 Solves, 100 Pts)
The premise is simple. We have an ncat link that puts us through 100 levels where we are given X numbers, and are expected to output a polynomial with exactly these numbers as its roots.

We can use sagemath to simplify the polynomial building and get the flag without issue.

`polyplayground.sage`
```py
from pwn import *

r = remote('challs.nusgreyhats.org', int(31113),level='debug')
F.<x> = ZZ['x']
while True:
    r.recvuntil(b'Roots: ')
    nums = eval(b'[' + r.recvline().rstrip() + b']')
    f = 1
    for num in nums:
        f *= (x - num)
    coeffs = list(f)[::-1]
    r.sendline(b','.join([str(i).encode() for i in coeffs]))
```

```sh
[DEBUG] Received 0x6e bytes:
    b'--------------------\n'
    b'Level 99:\n'
    b'Roots: -753,324,584,166,610\n'
    b'Present the coefficients of your amazing equation: '
[DEBUG] Sent 0x36 bytes:
    b'1,-931,-272968,510522556,-160638086928,14427489156480\n'
[DEBUG] Received 0x6f bytes:
    b'--------------------\n'
    b'Level 100:\n'
    b'Roots: 12,-284,255,-86,-100\n'
    b'Present the coefficients of your amazing equation: '
[DEBUG] Sent 0x2d bytes:
    b'1,203,-61006,-12519608,-464163360,7473744000\n'
[DEBUG] Received 0xa8 bytes:
    b'--------------------\n'
    b"Congratulations you have succeeded in the treacherous Polynomial Playground! Here's your flag!\n"
    b'grey{l0oks_lik3_sOm3one_c4n_b3_a_po1ynomia1_w1z4rd}\n'
```