### RC4 Signing Scheme - 3 Solves, 986 Pts, 🩸
```
1024-bit (secure!) signing algorithm with RC4 (fast!)

Author: hadnot
```

`rc4-signing-scheme.py`
```py
import os

with open("flag.txt", "r") as f:
    flag = f.read().encode()


def keyschedule(key):
    S = list(range(256))
    j = 0
    for i in range(256):
         j = (j + S[i] + key[i%len(key)])%256
         t = S[i]
         S[i] = S[j]
         S[j] = t
    return S

def encrypt(S, pt):
    ct = bytes([])
    i = 0
    j = 0
    for x in pt:
        i = (i+1)%256
        j = (j+S[i])%256
        t = S[i]
        S[i] = S[j]
        S[j] = t
        t = (S[i] + S[j])%256
        ct += bytes([S[t] ^ x])
    return ct

def sign(msg):

    global num_encryptions
    num_encryptions += 1
    if (num_encryptions > 20):
        # no more for you...
        return b""
    
    iv = os.urandom(128)
    USED_IVS.append(iv)
    key = iv + priv_key 
    S = keyschedule(key)
    ct = encrypt(S, msg)
    return iv + ct

def verify(msg, sig):

    iv, ct = sig[:128], sig[128:]
    
    if iv in USED_IVS:
        # thats too easy...
        return False

    key = iv + priv_key
    S = keyschedule(key)
    pt = encrypt(S, ct)
    return msg == pt

menu = """
Enter an option:
[1] Sign secret
[2] Submit signature
[3] Exit
> """

num_encryptions = 0
USED_IVS = []
priv_key = os.urandom(128)
secret_msg = os.urandom(256)

while True:
    option = input(menu).strip()

    if option == "1":

        sig = sign(secret_msg)
        
        print(sig.hex())
                    
    elif option == "2":

        sig = bytes.fromhex(input("Signature (hex): "))
        
        if verify(secret_msg, sig):
            print(f"Wow! Here's the flag: {flag}")
            
        else:
            print("Wrong...")
            
    else:
        exit(0)
```

This time we have the server implementing an RC4 signature oracle. The oracle implements a standard RC4 encryption algorithm to sign its messages, using an iv and a private key.

With each instance that we ask for a signature, it signs a constant unknown `secret_msg` with a different 128 byte `iv` and a constant 128 byte `priv_key`. The RC4 key used in question is determined by concatenating the `iv` with `priv_key`, forming a 256-bit key used in key scheduling and subsequently generating the RC4 keystream.

To get the flag, we must be able to somehow obtain a valid signature of `secret_msg`, but we must give it an `iv` that is different from the ones the server has shown to us thus far. We can't compute `priv_key` meaning we can never really obtain a `iv + priv_key` key to custom RC4 encrypt a message, and we don't even have `secret_msg` to begin with!

It was quite an interesting journey when I'd solved this. I went off tangent looking at cryptographic papers on key collisions in RC4, and tried to implement one but to no success. But after a quick lunch and some time staring at the code I found the solution;

The trick is to realise that `RC4` is a stream cipher. Much like `AES-CTR` it generates a keystream that is initialised by the input key given. This keystream is primarily generated from the result of a state array `S` that is initialised by the RC4 key (`iv + priv_key`), which occurs in the key scheduling algorithm.

```py
def keyschedule(key):
    S = list(range(256))
    j = 0
    for i in range(256):
         j = (j + S[i] + key[i%len(key)])%256
         t = S[i]
         S[i] = S[j]
         S[j] = t
    return S
```

Notice how our 256-byte key winds up modifying the initial `S` array by swapping values within with each byte in the key. Since we know the `iv`, even though we don't have the `iv + priv_key` key, we can trace through `iv` and see what the `S` array would look like right before it gets affected by the `priv_key`.

So for any given `iv`, we can trace through `S` to get to some partial `S'`. Now, to gain a valid signature, all we need to do is to find some other 128-byte `iv'` that would preserve the same mapping that `iv` does from `S` to `S'`.

From `S` and `S'`, notice that we can deduce where every `i` value `S` is mappedto in `S'`. If we're lucky (i.e. around 50% of the time), the `S'` array would only have exactly `128` of its bytes moved. We use these same `128` bytes to construct another `iv'` that accomplishes the same movement by reversing through the key scheduling algorithm.

There is a near negligible chance of us deriving the same `iv` value as what we have, and by submitting this new `iv` value as well as the same signature, we spoof a valid signature and thus obtain our flag.

`solve.py`
```py
from Crypto.Util.number import *

def sim_keyschedule(key):
    S = list(range(256))
    j = 0
    for i in range(len(key)):
        j = (j + S[i] + key[i])%256
        t = S[i]
        S[i] = S[j]
        S[j] = t
    return S


def construct_key(iv):
    S_ = sim_keyschedule(iv)
    key = []
    j = 0
    i = 0
    S0 = list(range(256))
    for ptr, dst in enumerate(S_):
        if S0[ptr] == dst:
            continue
        j_dst = S0.index(dst)
        ki = (j_dst - S0[i] - j) % 256
        key.append(ki)

        t = S0[i]
        S0[i] = S0[j_dst]
        S0[j_dst] = t
        j = j_dst
        i += 1

    if i != 128:
        return -1
    return key


from pwn import *

r = remote('challs.nusgreyhats.org', 32001)

for _ in range(20):
    print(f"Test {_}")
    r.recvuntil(b'> ')
    r.sendline(b"1")
    signature = bytes.fromhex(r.recvline().rstrip().decode())
    iv, ct = signature[:128], signature[128:]
    key = construct_key(iv)
    if key != -1:
        break

if key == -1:
    print("No luck")
    r.close()

print(len(key))
print(bytes(key).hex())
print(iv.hex())
r.recvuntil(b'> ')
r.sendline(b'2')
sig = bytes(key).hex() + ct.hex() # this works 50% of the time for some reason
r.sendline(sig.encode())
print(r.recvline())
r.close()
```

I ran this about 4 times and then managed to get the flag,
`grey{rc4_more_like_rcgone_amirite_q20v498n20}`