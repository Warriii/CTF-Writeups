### Filter Plaintext (39 Solves, 481 Pts)
`chall.py`
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
import os

with open("flag.txt", "r") as f:
    flag = f.read()

BLOCK_SIZE = 16
iv = os.urandom(BLOCK_SIZE)

xor = lambda x, y: bytes(a^b for a,b in zip(x,y))
key = os.urandom(16)

def encrypt(pt):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
    tmp = iv
    ret = b""
    for block in blocks:
        res = cipher.encrypt(xor(block, tmp))
        ret += res
        tmp = xor(block, res)
    # c0 = E(b0 ^ iv)
    # c1 = E(b1 ^ c0 ^ b0)
    # c2 = E(b2 ^ c1 ^ b1) 
    return ret

    
def decrypt(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    tmp = iv
    ret = b""
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp) 
        if (res not in secret):
            ret += res
        tmp = xor(block, res)
        # p0 = D(c0) ^ iv
        # p1 = D(c1) ^ c0 ^ b0
        # p2 = D(c2) ^ c1 ^ b1
    return ret
    
secret = os.urandom(80)
secret_enc = encrypt(secret)

print(f"Encrypted secret: {secret_enc.hex()}") # key=key, iv=iv

secret_key = md5(secret).digest()
secret_iv = os.urandom(BLOCK_SIZE)
cipher = AES.new(key = secret_key, iv = secret_iv, mode = AES.MODE_CBC)
flag_enc = cipher.encrypt(pad(flag.encode(), BLOCK_SIZE)) 

print(f"iv: {secret_iv.hex()}")
print(f"ct: {flag_enc.hex()}")

print("Enter messages to decrypt (in hex): ")

while True:
    res = input("> ")
    try:
        enc = bytes.fromhex(res)
        dec = decrypt(enc)
        print(dec.hex()) 
    except Exception as e:
        print(e)
        continue
```

The encryption and decryption outputs remain similar to that we have already derived in `Filter Ciphertext`. Given a ciphertext input of `c0 | c1 | c2` where `c0, c1, c2` are 16 byte long ciphertext blocks, with `p0 | p1 | p2` as their custom AES decrypted counterparts, we obtain,

`AES_CUSTOM_DEC`
`p0 = ECB_DECRYPT(c0) ^ IV`
`p1 = ECB_DECRYPT(c1) ^ p0 ^ c0`
`p2 = ECB_DECRYPT(c2) ^ p1 ^ c1`

Now, there are a few other things to note here. Most importantly, there are two new key-ivs being used here, and the flag is obtained differently. In fact, we never get the flag directly at all!

But how does this work? Let's try and summarise everything here. Most of the time when dealing with Cryptography there can be lots of variables and items denoted and scattered about, so it's always a good idea to compartmentalise and digest them. A good technique I've found is to not just separate the variables by the context they're used in but also whether or not they are made private or public, i.e. whether or not we know or would not know them from the start.

We'll let the custom `encrypt()` and `decrypt()` be `AES_CUSTOM_ENC` and `AES_CUSTOM_DEC` respectively.

We have: (AES_CUSTOM)
- `key`, random 16 byte string, unknown.
- `iv`, random 16 byte string, unknown.
- `AES_CUSTOM_ENC()`, `AES_CUSTOM_DEC()` uses these `key` and `iv` params.
- A decryption oracle that runs `AES_CUSTOM_DEC()` on our ciphertext inputs, printing us the decrypted output each time.

We also have: (AES_CBC)
- `secret`, random 80 byte string, unknown.
- `secret_enc`, output of `AES_CUSTOM_ENC(secret)`, known.
- `secret_key`, `MD5` hash of `secret`, unknown.
- `secret_iv`, random 16 byte string, known.
- `flag_enc`, `AES_CBC_ENC(flag)` using `secret_key` and `secret_iv` as key and iv params. Known.

Okay, so now we can come up with a sort of roadmap. Intuitively our access to the decryption oracle should let us derive something in (AES_CUSTOM). To get the flag, we need to decrypt `flag_enc`, meaning we must be able to derive `secret_key` somehow (note that `secret_iv` is public).

The only way to obtain `secret_key` is by obtaining `secret`, which implies finding a way to derive `AES_CUSTOM_DEC(secret_enc)`. We also have access to the oracle for `AES_CUSTOM_DEC()`, and `secret_enc` is public anyway.

However, the now modified filter for `AES_CUSTOM_DEC()`
```py
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp) 
        if (res not in secret):
            ret += res
        tmp = xor(block, res)
```
patches out the vulnerability in `Filter Ciphertext`, and prevents us from being able to directly get away with putting in `secret_enc` and expecting us to obtain the decrypted output. Or does it? Let's first write some equations of what we know.

Given the decrypted `secret` blocks, `s0, s1, s2, s3, s4`, and the `secret_enc` blocks `se0, se1, se2, se3, se4`, we have:

```py
se0 = AES_ECB_ENC(s0 ^ iv)
se1 = AES_ECB_ENC(s1 ^ se0 ^ s0)
se2 = AES_ECB_ENC(s2 ^ se1 ^ s1)
...
s0 = AES_ECB_DEC(se0) ^ iv
s1 = AES_ECB_DEC(se1) ^ se0 ^ s0
s2 = AES_ECB_DEC(se2) ^ se1 ^ s1
...
```
Notice that the new check in `Filter Plaintext`, only filters if the result happens to be `s0, s1, s2, ...`. Just because it prevents us from directly knowing `AES_ECB_DEC(se0) ^ iv` or `AES_ECB_DEC(se1) ^ se0 ^ s0` doesn't mean it prevents us from knowing the most crucial piece of information - `AES_ECB_DEC(se0)`, `AES_ECB_DEC(se1)`, etc. 

Why is this the most crucial piece of information? Simple! Because `key` and `iv` are both private, and the fact that `AES_ECB` is more or less secure unless we can derive the `key`, the only thing stopping us from being able to recover `s0 s1 s2` is `AES_ECB_DEC()`. Once we know this, we can easily recover `s0`, then `s1` with knowledge of `se0` and `s0`, and then `s2` with knowledge of `se1` and `s1`, so on and so forth.

In fact, recognising that only `s0, s1, s2, ` is forbidden comes in pretty handy in allowing us to recover the decrypted secret. We can do it using a single payload too!

```
Send NULL|NULL|se1|se2|se3|se4|se0 to the server (the first 2 NULL blocks are there to recover the private IV value)

The server will decrypt them as,
pt_0 = AES_ECB_DEC(NULL) ^ IV 
pt_1 = AES_ECB_DEC(NULL) ^ NULL ^ pt_0
pt_2 = AES_ECB_DEC(se1) ^ NULL ^ pt_1
pt_3 = AES_ECB_DEC(se2) ^ se1 ^ pt_2
pt_4 = AES_ECB_DEC(se3) ^ se2 ^ pt_3
pt_5 = AES_ECB_DEC(se4) ^ se3 ^ pt_4
pt_6 = AES_ECB_DEC(se0) ^ se4 ^ pt_5

(Notice that these pt values are neither s0, s1, s2, s3 nor s4!! The filter would not act on them!!)
```

And here we can easily manipulate the xor equations to derive `secret`.
First off, we recover `IV` by doing 

`IV = pt_0 ^ AES_ECB_DEC(NULL) = pt_0 ^ (pt_1 ^ pt_0) = pt_1`

We then recover `AES_ECB_DEC(se0)` by doing `pt_2 ^ NULL ^ pt_1`, and likewise for the remaining `AES_ECB_DEC(se1,2,3,4)`

Because we know that 
```py
s0 = AES_ECB_DEC(se0) ^ IV
s1 = AES_ECB_DEC(se1) ^ s0 ^ se0
s2 = AES_ECB_DEC(se2) ^ s1 ^ se1
s3 = AES_ECB_DEC(se3) ^ s2 ^ se2
s4 = AES_ECB_DEC(se4) ^ s3 ^ se3
```

We can then recover `s0, s1, s2, s3, s4`, giving us `secret` to then derive `secret_key` and thus, decrypt the flag!

`sol.py`
```py
from Crypto.Cipher import AES
from hashlib import md5
from pwn import remote

r = remote('challs.nusgreyhats.org', 32223)
secret_enc = bytes.fromhex(r.recvline().rstrip().split(b': ')[-1].decode())
flag_iv = bytes.fromhex(r.recvline().rstrip().split(b': ')[-1].decode())
flag_enc = bytes.fromhex(r.recvline().rstrip().split(b': ')[-1].decode())

def decrypt_r(pload):
    r.sendlineafter(b'> ', pload.hex().encode())
    return bytes.fromhex(r.recvline().rstrip().decode())

xor = lambda x, y: bytes(a^b for a,b in zip(x,y))

pload = b'\x00'*32 + secret_enc[16:] + secret_enc[:16]
pload_blocks = [pload[i:i+16] for i in range(0,len(pload),16)]
output = decrypt_r(pload)
r.close()
# NULL|NULL|se0|se1|se2|se3|se4 would fail. Proof will be left to the reader
# AAAA|AAAA|se0|se1|se2|se3|se4, where AAAA is 16 As, would fail as well. Proof left to reader

pt_blocks = [output[i:i+16] for i in range(0,len(output),16)]
IV = pt_blocks[1]
print(f'Recovered IV = {IV}')
secret = [b''] * 5
for i in range(5):
    secret_block = xor(xor(pt_blocks[2+i], pload_blocks[1+i]), pt_blocks[1+i])
    secret[(i+1) % 5] = secret_block
tmp = IV
for i in range(5):
    secret[i] = xor(secret[i], tmp)
    tmp = xor(secret[i], secret_enc[i*16:i*16+16])
secret = b''.join(secret)
print(f'Recovered Secret = {secret}')

secret_key = md5(secret).digest()
cipher = AES.new(key = secret_key, iv = flag_iv, mode = AES.MODE_CBC) 
print(cipher.decrypt(flag_enc))

"""
[x] Opening connection to challs.nusgreyhats.org on port 32223
[x] Opening connection to challs.nusgreyhats.org on port 32223: Trying 35.198.239.93
[+] Opening connection to challs.nusgreyhats.org on port 32223: Done
[*] Closed connection to challs.nusgreyhats.org port 32223
Recovered IV = b"1\xc0m'c\x8e\xe9j\x13\x81\xbd\x9e\x10W\x16\xb6"
Recovered Secret = b"=E\xcfnn\xbe\xc7\xb4\xfed<\x8d\xb4\x91n8\xb9\xb6\xf8Y\xc37/\x0b\x8eU\x1e\x13rm\xc4\xebN+2o\xb5|\xaf\xb3\xe6+\xaa\xb1\xc1`IX\xd4\x05\xa2\xc5B@d[E.\xd1J\xaa\nO.'\x1dtXi\x96F\x17\xe9\xda\xcb-\r\xd3$\x17"
b'grey{pcbc_d3crypt10n_0r4cl3_3p1c_f41l}\n\t\t\t\t\t\t\t\t\t'
"""
```