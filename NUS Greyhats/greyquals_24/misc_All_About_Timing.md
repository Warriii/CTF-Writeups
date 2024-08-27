### All About Timing (165 Solves, 100 Pts)
`chall.py`
```py
import time
import random

random.seed(int(time.time()))

print("Guess the number I'm thinking of? It's all about the timing")
x = input("Your guess:")

n = random.randint(1000000000000000, 10000000000000000-1)

if int(x) == n:
    with open("flag.txt") as f:
        print(f.readline())
else: 
    print(f"Wrong answer! The number I was thinking of was {n}\nRemember it's all about the timing!")
```

Trivial time challenge. Ran it a few times to get a good offset and got the flag!
```py
from pwn import *

import time
import random

r = remote('challs.nusgreyhats.org', 31111)
t = int(time.time())
random.seed(t+3)
n = random.randint(1000000000000000, 10000000000000000-1)
r.sendlineafter(b"Your guess:", str(n).encode())
ans = int(r.recvline().rstrip().split(b' ')[-1])
r.close()

print(n, ans)
for i in range(-1000,1000):
    random.seed(t+i)
    if random.randint(1000000000000000, 10000000000000000-1) == ans:
        print("Offset by ", i)
"""
[x] Opening connection to challs.nusgreyhats.org on port 31111
[x] Opening connection to challs.nusgreyhats.org on port 31111: Trying 35.240.207.208
[+] Opening connection to challs.nusgreyhats.org on port 31111: Done
Traceback (most recent call last):
  File "c:\......\client.py", line 11, in <module>
    ans = int(r.recvline().rstrip().split(b' ')[-1])
ValueError: invalid literal for int() with base 10: b'grey{t1m3_i5_a_s0c1al_coNstRucT}'
[*] Closed connection to challs.nusgreyhats.org port 31111
"""
```