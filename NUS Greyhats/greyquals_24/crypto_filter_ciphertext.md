### Filter Ciphertext (82 Solves, 100 Pts)
`chall.py`
```py
from Crypto.Cipher import AES
import os

flag = "test{flag}"
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
    return ret
    
def decrypt(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    for block in blocks:
        if block in secret_enc:
            blocks.remove(block)
    tmp = iv
    ret = b""
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        ret += res
        tmp = xor(block, res)
    return ret

secret = os.urandom(80)
secret_enc = encrypt(secret)
print(f"Encrypted secret: {secret_enc.hex()}")

print("Enter messages to decrypt (in hex): ")
while True:
    res = input("> ")
    try:
        enc = bytes.fromhex(res)
        if (enc == secret_enc):
            print("Nice try.")
            continue
        dec = decrypt(enc)
        if (dec == secret):
            print(f"Wow! Here's the flag: {flag}")
            break
        else:
            print(dec.hex())
    except Exception as e:
        print(e)
        continue
```

It is definitely hard to understand for newcomers to Crypto, but what this code does is that it implements the `AES ECB` block cipher operation, and provides a `Decryption Oracle` - Given any input by the player, it attempts to decrypt and sends it to the player. Notably, we get the flag if we are able to get the oracle to decrypt `secret_enc`.

There are some key findings we can deduce, mainly how for say, a ciphertext input of `c0 | c1 | c2` where `c0, c1, c2` are 16 byte long ciphertext blocks, with `p0 | p1 | p2` as their custom AES decrypted counterparts, we obtain,

`p0 = ECB_DECRYPT(c0) ^ IV`
`p1 = ECB_DECRYPT(c1) ^ p0 ^ c0`
`p2 = ECB_DECRYPT(c2) ^ p1 ^ c1`

This won't matter as much, but it summarises the encryption and decryption algorithms neatly. Notably, `ECB_DECRYPT()` is one to one. Thus, there really isn't a good way to spoof in a decrypted secret block by putting in a different encrypted input that happens to decrypt to secret...because the only possible one would be `secret_enc`.

Or is there? 

Notice the checker used in the decryption oracle to prevent us from just putting in `secret_enc`, which in any other case the oracle would decrypt to `secret`.

```py
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    for block in blocks:
        if block in secret_enc:
            blocks.remove(block)
```

Suppose we put in the payload `senc_0 | senc_0 | senc_1 | senc_1`, where `senc_i` is the ith ciphertext block of `secret_enc`.

`Decrypt()` would result in `blocks = [senc_0, senc_0, senc_1, senc_1]`.

Let's analyse the for loop in greater detail.

`for block in blocks:` <-  `block` = `senc_0`, or `blocks[0]`

`if block in secret_enc`: <- `block = blocks[0]` is in fact in `secret_enc`

`blocks.remove(block)` <- `blocks` removes `blocks[0]` or the first instance of `senc_0`, leading to `blocks = [senc_0, senc_1, senc_]`

Notice that when it iterates to the next `block`, it would be pointing at `blocks[1]` i.e. `senc_1`. That's the vulnerability! By modifying itself within the loop, we can get the iterating point to "skip" over blocks within. In fact, you'd notice that the payload `senc_0 | senc_0 | senc_1 | senc_1` will become `senc_0 | senc_1` by the end of the for loop, which would logically decrypt back into `secret_0 | secret_1`!

And so we put that into our solve script and obtain the flag as follows:

`solve.py`
```py
from pwn import *
r = remote('challs.nusgreyhats.org', 32222)
r.recvuntil(b'Encrypted secret: ')
s_enc = bytes.fromhex(r.recvline().rstrip().decode())
print(s_enc, len(s_enc))
s_blocks = [s_enc[i:i+16] for i in range(0, len(s_enc), 16)]
pload = b''
for i in s_blocks:
    pload += i
    pload += i
r.sendline(pload.hex().encode())
r.interactive()
# grey{00ps_n3v3r_m0d1fy_wh1l3_1t3r4t1ng}
```
