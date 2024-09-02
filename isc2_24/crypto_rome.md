### Crypto - Rome (16 Solves, 933 pts)
```
I was told AES (Advanced Encryption Standard) is super secure, and I like Ancient Rome. This should be secure, right?

Author: warri
```

`chall.py`
```py
from Crypto.Cipher import AES
import random

flag = b"ISC2CTF{???????????}"

j = random.randint(1, 9999999999999999999999999999999999999999999999999999999999999)
key = random.randbytes(16)
nonce = random.randbytes(8)

key_enc = [(i+j) % 256 for i in key]

cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(flag).hex()
nonce = nonce.hex()
print(f'{nonce = }')
print(f'{key_enc = }')
print(f'{ciphertext = }')
"""
nonce = '8c4c033113dbe0d9'
key_enc = [252, 154, 160, 50, 132, 1, 20, 168, 204, 57, 173, 91, 46, 15, 107, 111]
ciphertext = '2886c787049a22c57afbcd56ccfa8581ad49caa7'
"""
```

This was designed to be a very beginner friendly challenge! The idea is that the flag is encrypted using `AES` with a `key` and `nonce`. We have the `nonce` but we lack the `key`. Instead, we have a `key_enc` which is every byte of the key, caesar-shifted by some amount.

What this means is that if our key is `ABCdef123`, a caesar shift of say, 10 will cause it to become `KLMnop;<=`

```py
>>> k = b"ABCdef123"
>>> bytes([i+10 for i in k])
b'KLMnop;<='
```

Now this caesar shift offset is some random number between 1 and a super massive number. But the truth is, the offset can only take 256 unique values, as the caesare shift is done modulo 256! We brute for possible key values and decrypt the ciphertext to recover the flag.

Fun fact, I set this challenge mainly to ensure one would have some familiarity with a kind of cryptography challenge whereby some item is being encrypted using a different algorithm which would later be used as a key, typical in AES to encrypt the flag. The reason why such challenges don't just encrypt the flag directly is often times due to the fact that the item being encrypted might not have the size for a flag, or that the item itself could be some object (say a polynomial, a quartenion, point on an elliptic curve etc.) that might not support fitting a flag into.

`sol.py`
```py
from Crypto.Cipher import AES

nonce = bytes.fromhex('8c4c033113dbe0d9')
key_enc = [252, 154, 160, 50, 132, 1, 20, 168, 204, 57, 173, 91, 46, 15, 107, 111]
ciphertext = bytes.fromhex('2886c787049a22c57afbcd56ccfa8581ad49caa7')

# Brute caesar key
for j in range(0, 256):
    
    key = []
    for key_val in key_enc:
        key.append((key_val - j) % 256)
    key = bytes(key) # convert key from list to bytes

    cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
    flag = cipher.decrypt(ciphertext)
    if flag.startswith(B"ISC2CTF{"):
        print(flag) # b'ISC2CTF{eT_tu_brut3}'
```