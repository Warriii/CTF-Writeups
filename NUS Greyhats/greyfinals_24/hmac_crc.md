### HMAC-CRC - 15 Solves, 304 Pts, 🩸
```
I came up with a new HMAC algorithm. How has no one thought of this before?

Author: hadnot
```

`hmac-crc.py`
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import crc32
import os

with open("flag.txt", "r") as f:
    flag = f.read().encode()

def CRC32(x):
    return int.to_bytes(crc32(x), 4, 'big')

key = os.urandom(16)
iv = os.urandom(8)
num_encryptions = 0

def encrypt(pt):
    global num_encryptions
    num_encryptions += 1
    if (num_encryptions > 200):
        # no more for you...
        return b""

    cipher = AES.new(key, mode=AES.MODE_CTR, nonce=iv)
    hmac = CRC32(key + pt + key)
    ct = cipher.encrypt(pad(pt + hmac, 16))
    return ct

def decrypt(ct):
    cipher = AES.new(key, mode=AES.MODE_CTR, nonce=iv)
    tmp = unpad(cipher.decrypt(ct), 16)
    pt, hmac_check = tmp[:-4], tmp[-4:]

    hmac = CRC32(key + pt + key)
    if (hmac_check == hmac):
        return pt

    return None


menu = """
Enter an option:
[1] Encrypt message
[2] Challenge
[3] Exit
> """

while True:
    option = input(menu).strip()
    
    if option == "1":

        message = input("Enter a message (in hex): ")
        try:
            message = bytes.fromhex(message)
            enc = encrypt(message)
            print(enc.hex())
            
        except Exception as e:
            print("Error!", e)
            exit(0)
        
    elif option == "2":

        for i in range(10):
            test = os.urandom(16)
            print(f"Encrypt {test.hex()}")

            enc = input("Answer (in hex): ")
            enc = bytes.fromhex(enc)
            
            if test != decrypt(enc):
                print("You failed!")
                exit(0)

        print(f"Wow! Here's the flag: {flag}")

    else:
        exit(0)
```

We're given the ability to encrypt 200 chosen messages, which uses the following "HMAC" scheme:

`msg -> AES_CTR(MSG + CRC32(KEY+MSG+KEY))`

where `KEY` used in the CRC32 checksum is the same `key` used in the `AES_CTR` encryption.

The idea of a `hmac` is relatively simple. In cryptography, a `hmac` is a type of message authentication code usually involving a cryptograqphic hash function and a secret key. The idea is by computing `Hash(Key, Msg)` and appending this to the encrypted message, or by encrypting it with the message, any recipient who has the key and decrypt, view the message while also verifying the message with the hash. As only the receiver or the sender would have the key used to hash the message, any third party should not be able to make that valid hash, thus ensuring that the encrypted message was not altered during transit. (this can happen for when the encryption algorithm is malleable, which applies to AES CTR).

In this case, `CRC32` is selected as the "Hash" in the `hmac`.

Returning to the challenge, the goal is to show that this `hmac` is flawed. That is, we'd receive 10 messages and be tasked with figuring out what their respective encrypted outputs would be. In essence, given any `m`, we're supposed to deduce `AES_CTR(MSG + CRC32(KEY+MSG+KEY))`, even though we do not know what this `KEY` is. (alternatively, if we could find a way to recover `KEY` then we can easily spoof a valid hmac, but thats not possible here)

Now since we have an encryption oracle, we can bypass `AES_CTR` very easily. As `AES_CTR` operates by using the AES algorithm with `key` and `nonce` to generate a keystream to xor with the message, the keystream will always be constant. We can recover this keystream by sending a bunch of `b'\x00'` null bytes for the server to encrypt, as anything xored with 0 is, simply, whatever it was before the xor. Then to spoof any valid `AES_CTR` encrypted message, we just xor the message with our recovered keystream.

To bypass the `CRC32()`, even though we do not know the key, there is a specific property of the checksum that indicates why it would not be a secure hashing function for a `hmac`. It is linear.

More specifically, given two messages `A, B` of the same length, there is a property that;

```js
CRC32(A ^ B) == CRC32(A) ^ CRC32(B) ^ c
```
for some constant `c`.

So, in order to figure out `CRC32(KEY + MSG + KEY)` for any 16 byte message `MSG`, we:

```js
1. Recover CRC32(KEY + NULL + KEY) via oracle, where NULL is 16 b'\x00' bytes
2. Recover any CRC32(KEY + MSG + KEY) via oracle where MSG is 16 bytes long and can be anything (eg. b'A' * 16)
3. Compute CRC32(NULL + MSG + NULL)
4. Recover c = CRC32(KEY + MSG + KEY) ^ (CRC32(KEY + NULL + KEY) ^ CRC32(NULL + MSG + NULL)) using the linear relation described earlier
```

Now, to obtain any CRC32(KEY + PT + KEY) for any 16 byte PT, we perform:

```js
CRC32(KEY + PT + KEY) = CRC32(KEY + NULL + KEY) ^ CRC32(NULL + PT + NULL) ^ c
```

This leads us to our solve script,

`solve.py`
```py

from Crypto.Util.strxor import strxor
from pwn import remote

r = remote('challs.nusgreyhats.org', 32000, level='debug')

r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'Enter a message (in hex): ')
msg = b'0' * 256
r.sendline(msg)
xorstream = bytes.fromhex(r.recvline().rstrip().decode())[:-16]
print(f'{xorstream = }')

r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'Enter a message (in hex): ')
msg = b'0' * 32
r.sendline(msg)
ct = bytes.fromhex(r.recvline().rstrip().decode())
check1_hmac = strxor(ct, xorstream[:len(ct)])[-16:-12]
print(f'{check1_hmac = }')

r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'Enter a message (in hex): ')
msg = b'41' * 16
r.sendline(msg)
ct = bytes.fromhex(r.recvline().rstrip().decode())
check2_hmac = strxor(ct, xorstream[:len(ct)])[-16:-12]
print(f'{check2_hmac = }')

A_crc = CRC32(b'\x00'*16 + b'A'*16 + b'\x00'*16)
c_crc = strxor(strxor(A_crc, check2_hmac), check1_hmac)
print(f'{c_crc = }')

r.recvuntil(b'> ')
r.sendline(b'2')
for _ in range(10):
    r.recvuntil(b"Encrypt ")
    test = bytes.fromhex(r.recvline().rstrip().decode())
    test_crc = strxor(strxor(CRC32(b'\x00'*16 + test + b'\x00'*16), c_crc), check1_hmac)
    spoof_ct = strxor(test + test_crc + b'\x0c'*0xc, xorstream[:32])
    r.sendline(spoof_ct.hex())
r.interactive()
```

which prints out the flag, 
`grey{everything_is_linear_algebra_a0945v832q}`