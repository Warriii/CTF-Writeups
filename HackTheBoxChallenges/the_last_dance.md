### The Last Dance
---

#### Files
`source.py`
```py
from Crypto.Cipher import ChaCha20
from secret import FLAG
import os


def encryptMessage(message, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def writeData(data):
    with open("out.txt", "w") as f:
        f.write(data)


if __name__ == "__main__":
    message = b"Our counter agencies have intercepted your messages and a lot "
    message += b"of your agent's identities have been exposed. In a matter of "
    message += b"days all of them will be captured"

    key, iv = os.urandom(32), os.urandom(12)

    encrypted_message = encryptMessage(message, key, iv)
    encrypted_flag = encryptMessage(FLAG, key, iv)

    data = iv.hex() + "\n" + encrypted_message.hex() + "\n" + encrypted_flag.hex()
    writeData(data)
```

`out.txt`
```
c4a66edfe80227b4fa24d431
7aa34395a258f5893e3db1822139b8c1f04cfab9d757b9b9cca57e1df33d093f07c7f06e06bb6293676f9060a838ea138b6bc9f20b08afeb73120506e2ce7b9b9dcd9e4a421584cfaba2481132dfbdf4216e98e3facec9ba199ca3a97641e9ca9782868d0222a1d7c0d3119b867edaf2e72e2a6f7d344df39a14edc39cb6f960944ddac2aaef324827c36cba67dcb76b22119b43881a3f1262752990
7d8273ceb459e4d4386df4e32e1aecc1aa7aaafda50cb982f6c62623cf6b29693d86b15457aa76ac7e2eef6cf814ae3a8d39c7
```
#### Writeup

We are given a similar scenario with `sekur julius`. A source code that encrypts some message, and then the encrypted ciphertext in `out.txt`.

`encryptMessage()` is a simple function that performs `ChaCha20` encryption on a given message using some `(key, nonce)` pair. 

Looking into `__main__`, we note that the code generates a 32-byte `key`, 12-byte `nonce`, then gives us the `nonce`, some encrypted output of `message` (which the code gives us) and the encrypted flag, all in hexadecimal.

It is quite clear that the 32-byte key is too big to be bruted. A google search implies that the `ChaCha20` algorithm seems very complicated, so how can this be a "very easy" challenge?

In cryptography, a common technique many players often use is blackboxing. You don't always need to know EVERYTHING when doing a challenge. Sometimes you can treat entire algorithms or functions as a "blackbox". So long as one knows what this "box" does (what it takes as input, what it outputs, how the input and output is related etc.), that's all one might need!

This is the case here. You don't need to know what ChaCha20 does under the hood, but you just need to know what kind of cipher ChaCha20 is -- a Stream Cipher.

A Stream Cipher, essentially takes a key, a nonce, and then uses the two to deterministically generate a pseudorandom sequence. This sequence, which we call a keystream, is then used to encrypt a message. Typically, the bitwise-xor operation is used, which is what `ChaCha20` uses.

As an example, suppose with key `abcd` and nonce `123`, my Stream Cipher spits some keystream `a1b2c3d1a2b3...`. To encrypt a message `testing123`, for example, I can just xor `a1b2c3d1a2b3...` with `testing123`, getting some output.

What this means, is that if I take the output, and xor it back with `testing123`, I get back the keystream `a1b2c3d1a2b3...` without needing to know the key nor the nonce!

And because any other message will also be encrypted with the exact same keystream (if the key-nonce pair used is the same), from our derived keystream, we can decrypt any other ciphertext! This is actually a common attack on poorly implemented stream ciphers, wherein the key and nonce pair used does not change between encryptions.

Hence, we simply follow the above, xor to recover our keystream from a known (plaintext-ciphertext) pair, and then use the keystream to directly decrypt the flag.

#### solve.py
```py

message = b"Our counter agencies have intercepted your messages and a lot "
message += b"of your agent's identities have been exposed. In a matter of "
message += b"days all of them will be captured"
c0 = "7aa34395a258f5893e3db1822139b8c1f04cfab9d757b9b9cca57e1df33d093f07c7f06e06bb6293676f9060a838ea138b6bc9f20b08afeb73120506e2ce7b9b9dcd9e4a421584cfaba2481132dfbdf4216e98e3facec9ba199ca3a97641e9ca9782868d0222a1d7c0d3119b867edaf2e72e2a6f7d344df39a14edc39cb6f960944ddac2aaef324827c36cba67dcb76b22119b43881a3f1262752990"
c1 = "7d8273ceb459e4d4386df4e32e1aecc1aa7aaafda50cb982f6c62623cf6b29693d86b15457aa76ac7e2eef6cf814ae3a8d39c7"

c0, c1 = bytes.fromhex(c0), bytes.fromhex(c1)

def xor(a, b):
    return bytes([i^j for i,j in zip(a,b)])

keystrem = xor(c0, message)
flag = xor(keystrem[:len(c1)], c1)
print(flag)
# b'HTB{und3r57AnD1n9_57R3aM_C1PH3R5_15_51mPl3_a5_7Ha7}'
```