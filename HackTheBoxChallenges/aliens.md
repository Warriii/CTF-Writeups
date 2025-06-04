### AliEnS
---

#### Files
`server.py`
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

from secret import FLAG

class AAES():
    def __init__(self):
        self.padding = "CryptoHackTheBox"

    def pad(self, plaintext):
        return plaintext + self.padding[:(-len(plaintext) % 16)] + self.padding

    def encrypt(self, plaintext):
        cipher = AES.new(os.urandom(16), AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, 16))


def main():
    aaes = AAES()

    while True:
        message = input("Message for encryption: ")
        plaintext = aaes.pad(message) + aaes.pad(FLAG)
        print(aaes.encrypt(plaintext.encode()).hex())


if __name__ == "__main__":
    main()
```

#### Writeup
We have access to a seemingly simple looking AES-ECB oracle. We can enter messages, which it then pads using a custom pad function, then encrypts. Interestingly, it pads as decoded string, then calls Crypto.Util.Padding.pad which pads the string again at a byte level.

AES is a block cipher, and is mostly secure. One does not simply reverse an AES encrypted message without knowing the key, which is some random 16 bytes. One thing that we do know is that AES-ECB simply encrypts every block of 16 bytes, thus the same 16 byte block encrypts to the same 16 byte output.

```py
FLAG = "flag{testing123}"
toblks = lambda y : [y[i:i+(16 if type(y) == bytes else 32)] for i in range(0, len(y), 16 if type(y) == bytes else 32)]

aaes = AAES()
while True:
    message = input("Message for encryption: ")
    plaintext = aaes.pad(message) + aaes.pad(FLAG)
    ct = aaes.encrypt(plaintext.encode()).hex()
    plaintext = pad(plaintext.encode(), 16)
    for i, j in zip(toblks(ct), toblks(plaintext)):
        print(i, j)
```
With ad-hoc scripting I began playing around with the oracle, splitting the ciphertext and plaintext (before AES encryption) into their 16 byte blocks and comparing them.

```
Message for encryption: hi
838a429090bc5121cd1417c602c7f6e4 b'hiCryptoHackTheB'
29baa358ca630fec4bfb58e0e3ab86dd b'CryptoHackTheBox'
81f6d3fbebff8403323166a769fa886f b'flag{testing123}'
29baa358ca630fec4bfb58e0e3ab86dd b'CryptoHackTheBox'
993b8766ccd0ca013ff0428cc4f058c3 b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
Message for encryption: 123
8e9762382d0d7fda47e2744450325872 b'123CryptoHackThe'
970ec7432883b0b3f5c7240737808bb7 b'CryptoHackTheBox'
0c02206e3a77b8269b53b1be5d24ba06 b'flag{testing123}'
970ec7432883b0b3f5c7240737808bb7 b'CryptoHackTheBox'
9c681b7bc95426307373a913dbd9ab1b b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
Message for encryption: a
8b30c14e26c6a873a65153e9e1559f26 b'aCryptoHackTheBo'
32821a4d39e96d1dcea4ab4bcebdb7df b'CryptoHackTheBox'
3c8be4359bac54bfe4b3d646b1508624 b'flag{testing123}'
32821a4d39e96d1dcea4ab4bcebdb7df b'CryptoHackTheBox'
727ffac328f2fb538815a2d55ff4d941 b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
```
Notice that every 16 byte block that is the same (i.e. `CryptoHackTheBox`) has the same encrypted hex output. Additionally, we note that the output blocks differ as we use the oracle more. This is expected, as a random 16 byte key is generated every time.

While playing around with the system, I made the flag 17 bytes instead, and noticed that:
```
Message for encryption: testing
af702559923d920ef04cb88e406531b4 b'testingCryptoHac'
beb7e00623c7e13f4e00747e32422995 b'CryptoHackTheBox'
3aa704771080fcd472d956b28f1c8e09 b'flag{testing123A'
90db3c02d60e0c45fe3b992caa8cdc5e b'}CryptoHackTheBo'
beb7e00623c7e13f4e00747e32422995 b'CryptoHackTheBox'
fc2853a9c7f9b80bb7a50c7c95d9bbe0 b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
Message for encryption: }
0739cedbe5ce6a41ea5765c037dac8c0 b'}CryptoHackTheBo'
8f3afbfd3dc5566daa52ba0ebede29a6 b'CryptoHackTheBox'
82b159ede5db22f03bb1a1dcff8eca9e b'flag{testing123A'
0739cedbe5ce6a41ea5765c037dac8c0 b'}CryptoHackTheBo'
8f3afbfd3dc5566daa52ba0ebede29a6 b'CryptoHackTheBox'
7a33662568601bd1ba238148d37292b0 b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
Message for encryption:
```

The `}` overrides into the `}CryptoHackTheBo` block. This means I can modify my input above until I find the right `<char>CryptoHackTheBo`, and I can confirm whether or not the two ciphertext blocks are equal!

So, if the flag has length $1 \bmod 16$, we can derive the last character of the flag. But how do we derive the next character? The way `AAES.pad()` is done almost always ensures your input message does not push the flag 1 byte to the right, which we require...

I was stuck for a while, but when reading the Discussion Forum for the challenge, I noticed a cryptic hint. Something about Unicode.

Then I realised what I was missing. While normally we stick to the ASCII range of characters, there always exist other characters that cannot fit in 8 bits of data.

Words like `κ`, currency symbols such as `₱`, even mathematical symbols like `⊉` exist and are sometimes used in certain contexts. But when all 256 values are used to encode various data, how can these symbols be encoded?

Xerox employee Joe Becker and Apple employees Lee Collins and Mark Davis solved this problem way back in 1988. Coined as Unicode, the universal encoding simply allowed these symbols to exist, but uses multiple bytes to store them instead.

We can see this via a Python Interpreter:
```
>>> s = "⊉"
>>> len(s)
1
>>> s.encode()
b'\xe2\x8a\x89'
>>> len(s.encode())
3
```

The unicode character `⊉`, as a string, is interpreted to be of length 1. When in reality after encoding it, it requires 3 bytes! This is key to solving the challenge.

Using `κ` for example, when we send it to the oracle, `AAES.pad()` pads it as if it were a string. Because of this, when the entire plaintext string is encoded and then encrypted in AES, the "additional" bytes used in Unicode pushes everything to the right by one.
```
Message for encryption: κ
9490a498b89685c67db4777466aafb2e b'\xce\xbaCryptoHackTheB'
4c6efa2614841cae2cca7b9a902d2431 b'oCryptoHackTheBo'
c07db3b012afb9e6d512e0e7ad6d9df6 b'xflag{testing123'
089a11f016d1cdfc96d3f7c446bc6ba7 b'A}CryptoHackTheB'
4c6efa2614841cae2cca7b9a902d2431 b'oCryptoHackTheBo'
7c6dd1e221b4affd927d92a9a339a484 b'x\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

As you can see here, our block has gone from `}CryptoHackTheB` to `A}CryptoHackTheB`.

```
Message for encryption: κaaaaaaaaaaaaaa?}
842f88c4c22c3be328e00e96d2187d45 b'\xce\xbaaaaaaaaaaaaaaa'
dcc9f21cec616889bb59a044a44b70e2 b'?}CryptoHackTheB'
5ec5be00e67020a71beaba4ba33a8e05 b'oCryptoHackTheBo'
80f1d6a86d0f92d6d87134a2492ee98d b'xflag{testing123'
9156519161972f10ffb98c560c33d3df b'A}CryptoHackTheB'
5ec5be00e67020a71beaba4ba33a8e05 b'oCryptoHackTheBo'
8bd5157dc96d8ad90863dd6f847abc14 b'x\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```
With some manipulation, now we can repeatedly query the `?` till we find the right value that matches with the `A}CryptoHackTheB` block.

We repeat the process and recover the rest of the flag, byte by byte. We start with a proof of concept with a random FLAG of random length, and after that we replace our local oracle with the remote oracle provided by the challenge.

One last thing that I'd failed to cover here was determining the length of the flag modulo 16. We can deduce this by determining how much `κ` we must send to get a `}CryptoHackTheBo` block, which we can then verify by ending the 16 byte padded `κ` string with an additional `}`.

When connecting to the remote, I learnt that the flag characters were just hexadecimal values, thus a quick modification of the brute range allows for quicker flag extraction.

#### solve.py
```py
import random
FLAG = 'HTB{' + ''.join(chr(random.randint(0x20, 0x7e)) for _ in range(random.randint(16, 32))) + '}'
toblks = lambda y : [y[i:i+(16 if type(y) == bytes else 32)] for i in range(0, len(y), 16 if type(y) == bytes else 32)]

def oracle(message):
    aaes = AAES()
    pt = aaes.pad(message) + aaes.pad(FLAG)
    return aaes.encrypt(pt.encode()).hex()

def roracle(message, r):
    r.recvuntil(b"Message for encryption: ")
    r.sendline(message.encode())
    return r.recvline().rstrip().decode()

from pwn import remote
def solve():
    r = remote("...",...)
    uni = "κ"

    # Derive init num of uni to leak last flag byte
    success = False
    for ii in range(16):
        padstr = uni*ii + 'a' * (-2*ii % 16)
        # res = toblks(oracle(padstr + '}'))
        res = toblks(roracle(padstr+'}', r))
        if res[(ii+7)//8] == res[-2 - (1 if ii == 0 else 0)]:
            success = True
            break
    assert success
    rptr = -3 if ii == 0 else -2

    # Begin oracle
    print(f'{FLAG = }')
    flag = '}'
    ii += 1
    while not flag.startswith('HTB{'):
        success = False
        for a in "0123456789abcdefHTB{}": # range(0x20, 0x7f):
            padstr = uni*ii + 'a' * (-2*ii % 16)
            # res = toblks(oracle(padstr + chr(a) + flag))
            res = toblks(roracle(padstr + chr(a) + flag, r))
            if res[(ii+7)//8] == res[rptr - ii//16]:
                success = True
                flag = chr(a) + flag
                print(f'{flag = }')
                break 
        assert success
        ii += 1
        print(flag)
    r.close()
solve()
```