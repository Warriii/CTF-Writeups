## imrul_kaes (25 Solves, 338 Pts)
```
Imrul Kayes may not always be in the playing XI, but somehow, he's found himself inside an AES encryption scheme. We don't know how. He doesn't know how. But he's in. And he’s trolling hard.

Instead of swinging the bat, Imrul is now swinging bytes, and dropping more blocks than a DJ with Parkinson’s.
```
`chall.py`
```py
#!/usr/local/bin/python
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

print('Yo welcome to my sign as a service...')

p, q = getPrime(512), getPrime(512)
e = 12389231641983877009741841713701317189420787527171545487350619433744301520682298136425919859970313849150196317044388637723151690904279767516595936892361663
n = p * q
d = pow(e, -1, (p - 1) * (q - 1))

k = get_random_bytes(16)
cipher = AES.new(k, AES.MODE_ECB)

flag = open('flag.txt', 'rb').read()
assert len(flag) <= 50 # flag < 400 bits
ct = pow(bytes_to_long(flag), e, n)

print(f'{ct = }')

while 1:
	try:
		i = int(input("Enter message to sign: "))
		assert(0 < i < n)
		print(cipher.encrypt(pad(long_to_bytes(pow(i, d, n) & ((1<<512) - 1)), 16)).hex())
	except:
		print("bad input, exiting")
```

We have a RSA/AES style challenge! We start with an RSA encrypted flag, $ct$, and we are tasked with recovering the flag using an RSA decryption oracle that encrypts the result under AES-ECB with some unknown key.

The nature of AES means key recovery is not an option. So we will have to find another way to derive the flag.

Having $ct$ alone feels like too little information, so let's try to recover something else. Perhaps the value of $n$, the unknown modulus. We notice that the oracle takes an integer input and checks that the input is smaller than $n$. We can thus integrate a binary search algorithm to recover our 1024-bit $n$ in 1024 queries.

Now onto finding the flag. We first consider the homomorphic property of RSA.

Given $c_i = m_i^e \bmod n$, $c_j = m_j^e \bmod n$, $m_i*m_j = (c_i*c_j)^d \bmod n$.

While we may only know $c_i = ct$ and not $m_i = \text{FLAG}$, if we can compute $(m_j)^e \bmod n$, we can have the decryption oracle perform $\text{AES-ECB}(\text{FLAG} * m_j)$ for some $m_j$ that we control. This is especially helpful when we notice that:

```py
long_to_bytes(pow(i, d, n) & ((1<<512) - 1))
```

The input fed into the AES cipher is the 512 lower signficant bits of $\text{FLAG} * m_j$.

Consider the flag, say, `DEAD{.....test}`, and let its RSA encrypted ciphertext be $c_0$. We can perform $c_0 * 256^e \bmod n$ and send this into the oracle, causing it to encrypt the lower significant bits of `DEAD{.....test}\x00`. If we chain enough `\x00`s, we will eventually push the entire flag to beyond the 512 lower bits! And if we do it just right, we could get the AES encrypted output of `}\x00\x00....\x00`.

Then, we simply run payloads of the form `<CHAR>\x00...\x00` till we find a match with `}\x00....\x00`. This tells us the last character of the flag.

We can repeat the process by reducing the `\x00` chain to recover `t}\x00...\x00`, then `st}\x00...\x00`, ...  until we recover the entire flag, one byte at a time. I optimised this process in my solve, where I submitted 4 character guesses per oracle query. This is because AES-ECB only encrypts data in 16 byte blocks, thus I have `512 / 8 / 16 = 4` full blocks to work with.

`solve.py`
```py
def oracle(i, dbg=False):
    global r, cnt
    cnt += 1
    r.recvuntil(b'Enter message to sign: ')
    r.sendline(str(i).encode())
    res = r.recvline()
    if b'bad input' in res:
        return -1
    return bytes.fromhex(res.rstrip().decode())

from pwn import remote
from time import time

START = time()
e = ...
r = remote("nc.deadsec.quest", 30312)
r.recvline()
ct = int(r.recvline().rstrip().decode())
print(f'{ct = }')

# binsearch to find n
lo, hi = 0, 2**1024
cnt = 0
while hi - lo > 1:
    med = (lo + hi) // 2
    print(f"{cnt}/1024", end='\r')
    if oracle(med) == -1: # med is too high
        hi = med
    else:
        lo = med
rec_n = hi if hi % 2 == 1 else lo
print(f'{rec_n = }')

_256 = pow(256, e, rec_n)
exp = oracle(pow(bytes_to_long(b'}' + b'\x00'*15), e, rec_n))[:16]
for i in range(14, 50):
    recv = oracle(pow(_256, i, rec_n) * ct % rec_n)
    if exp in recv:
        break
index = recv.index(exp)
i += index
print(f'{i = }')

flag = b'}' + b'\x00'*15
alphabet = bytes(list(range(0x20, 0x7f))).decode()
for ptr in range(50):
    i -= 1
    to_match = oracle(pow(_256, i, rec_n) * ct % rec_n, True)[:16]
    for j in range(0, len(alphabet), 4): # 4 * 16 = 64, 64*8 = 512
        chars = alphabet[j:j+4]
        msg = b''
        for char in chars:
            msg += (char.encode() + flag)[:16]
        to_send = pow(bytes_to_long(msg), e, rec_n)
        recv = oracle(to_send,  dbg=True)
        if to_match in recv:
            offset = recv.index(to_match) // 16
            flag = alphabet[j+offset].encode() + flag
            break
    print(flag, cnt)
    if flag.startswith(b'DEAD{'):
        break
r.close()

print(f'Time taken: {round(time() - START,2)} seconds')
"""
ct = 61314949874086786812895024233862444511045040094047375224079915376228124760437238202762248628819285789379307406056109054008807143806734540694377578593478884514027300794248663566096749289547035593754068677508239887777625179477895064099593134409540183309495734001612258388296444584086756392166572774169690538925     
rec_n = 79362311321678881118151696040891966515932691480130792668398369372485703222548040782993448252995981315081503676807081136994324111862270537203899992065601518040832979492679489373216850740532441922783231869137702748206235879470787020833794935383547485789469397862863162781461598213556943978879118968538099675031  
i = 63
b'b}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 1061
b'4b}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 1068
...
b'AD{p4ddin6_04aC13_477aCk!_645a9d30d301d94b}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 1545
b'EAD{p4ddin6_04aC13_477aCk!_645a9d30d301d94b}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 1556
b'DEAD{p4ddin6_04aC13_477aCk!_645a9d30d301d94b}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 1567
[*] Closed connection to nc.deadsec.quest port 30312
Time taken: 357.11 seconds
"""
```
And this gets us the flag, `DEAD{p4ddin6_04aC13_477aCk!_645a9d30d301d94b}` in 1567 oracle queries, taking about 6 minutes in total.