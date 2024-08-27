## Magic

We're only given a single ncat link. Blackboxing it we find that it gives us some `n`, `e`, and asks for magic numbers. Inputting numbers from `0` to `302` gives us various `c = ...` outputs with `303` and above giving us `c = 0`. I found that at magic number `302`, `c = 1`.

In addition, inputting `-1` as a magic number gives an error string; `"can't shif... Nevermind"`

From this, the first thing I'd guessed was bit shifting. After some testing with magic numbers `301` and `302`, I've managed to construct the source code of the challenge as below;

`possible_source.py`
```py
from Crypto.Util.number import getPrime

n = getPrime(512)*getPrime(512)
e = 65537 
m = 8312884801970423563923630354880850246936953016337466382247876358746442082740980087131367805 # recovered after solving the challenge

print(f'{n = }')
print(f'{e = }')
print()

while True:
    val = input("give your magic number: ")
    try:
        val = int(val)
        if val < 0:
            print("can't shif... Nevermind")
        c = pow(m >> val, e, n)
        print(f'{c = }')
    except:
        print("Are sure about that ...")
```

Getting back the message becomes rather trivial;

`solve.py`
```py
from pwn import *

r = remote("20.80.240.190", 4455)
n = eval(r.recvline().rstrip().split(b' = ')[1])
e = eval(r.recvline().rstrip().split(b' = ')[1])

cs = []

pload = b''
for i in range(303):
    pload += str(i).encode() + b'\n'
r.sendline(pload)
for i in range(303):
    r.recvuntil(b'c = ')
    cs.append(eval(r.recvline().rstrip()))

flag = 0
for c in cs[::-1]:
    flag *= 2
    if pow(flag, e, n) == c:
        continue
    flag += 1
    assert pow(flag, e, n) == c
print(flag.to_bytes(64, "big").lstrip(b'\x00'))
# AKASEC{7alawa_ayayay_tbt_m3ana_asa7bi}
```