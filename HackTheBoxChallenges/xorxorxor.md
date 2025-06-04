### xorxorxor
---

#### Files
`challenge.py`
```py
#!/usr/bin/python3
import os
flag = open('flag.txt', 'r').read().strip().encode()

class XOR:
    def __init__(self):
        self.key = os.urandom(4)
    def encrypt(self, data: bytes) -> bytes:
        xored = b''
        for i in range(len(data)):
            xored += bytes([data[i] ^ self.key[i % len(self.key)]])
        return xored
    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

def main():
    global flag
    crypto = XOR()
    print ('Flag:', crypto.encrypt(flag).hex())

if __name__ == '__main__':
    main()
```

`output.txt`
```
Flag: 134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9
```
#### Writeup

`main()` initialises a `XOR` object, then uses it to encrypt the flag which it gives in `output.txt`. A quick analysis tells us that `XOR` simply encrypts the flag with a four byte xor key that it randomly generates upon initialisation.

From the output data, we could theoretically brute through all possible four-byte xor values until we find one that seems to be the flag. But thats way too inefficient.

Instead, we use the fact that the flag starts with `HTB{`. Since we have `HTB{ XOR key == CT[:4]` where `CT[:4]` represents the first four bytes of the ciphertext `CT`, we can do `CT[:4] XOR HTB{` to recover our key. Then we can just reverse the xor encryption by xoring the encrypted flag back with the same key! 

This works because an element xored by itself equals 0, thus 

`ct ^ key = (flag ^ key) ^ key = flag ^ key ^ key = flag ^ 0 = flag`

#### solve.py
```py
def xor(ct, key):
    return bytes([val ^ key[ptr % len(key)] for ptr,val in enumerate(ct)])

flag = bytes.fromhex("134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9")
xorkey = xor(flag[:4], b'HTB{')
decrypted_flag = xor(flag, xorkey)
print(decrypted_flag)
# HTB{rep34t3d_x0r_n0t_s0_s3cur3}
```