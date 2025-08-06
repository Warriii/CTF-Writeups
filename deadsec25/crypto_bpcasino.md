## BPCasino - Kouhen (20 solves,399 Pts)
```
Let's test your luck, win BP Casino and you will get the flag.
```
`chall.py`
```py
from hashlib import md5
import random
from Crypto.Util.number import long_to_bytes

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

class Feistel:
    def __init__(self, key: bytes, rounds=10, block_size=16) -> None:
        assert len(key) == block_size // 2
        assert block_size % 4 == 0
        self.rounds = rounds
        self.block_size = block_size
        self.S = list(range(256))
        random.shuffle(self.S)
        self._expand_key(key)
    
    @staticmethod
    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))
    
    @staticmethod
    def _pad(m: bytes, n: int) -> bytes:
        x = n - len(m) % n
        return m + bytes([x] * x)
    
    @staticmethod
    def _unpad(m: bytes, n: int) -> bytes:
        x = m[-1]
        if not 1 <= x <= n:
            raise ValueError("invalid padding")
        return m[:-x]
   
    def permutation(self, a: bytearray) -> bytearray:
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ (xtime(xtime(u ^ a[3])) ^ xtime(a[1]))
        a[1] ^= t ^ u ^ xtime(u ^ a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)
        return a

    def sbox(self, x: bytearray):
        return bytearray(self.S[y] for y in x)

    def _expand_key(self, key: bytes) -> None:
        self._round_keys = []
        H = self._pad(key, self.block_size)
        empty = 0
        for i in range(self.rounds):
            self._round_keys.append(int.from_bytes(H[:4], "big"))
            
            if not empty:
                H = md5(H).digest()[:4]
            else:
                H = H[4:]
                if (len(H) == 0):
                    empty = 1
                    H = key

        assert len(self._round_keys) == self.rounds
    
    def _f(self, l: int, r: int, key: int) -> int:
        a = bytearray(int(r ^ key).to_bytes(4, "big"))
        return l ^ int.from_bytes(self.permutation(self.sbox(a)), "big")
    
    def _encrypt_block(self, pt: bytes) -> bytes:
        assert len(pt) == self.block_size
        blocks = [int.from_bytes(pt[(self.block_size // 4) * i : (self.block_size // 4)*(i + 1)], "big") for i in range(4)]
        
        for i in range(self.rounds):
            blocks[1] = self._f(blocks[1], blocks[0], self._round_keys[i])
            blocks = blocks[1:] + [blocks[0]]
        ct = bytearray() 
        for l in blocks:
            ct += l.to_bytes(self.block_size // 4, "big")
        return ct

    def _decrypt_block(self, ct: bytes) -> bytes:
        assert len(ct) == self.block_size
        blocks = [int.from_bytes(ct[(self.block_size // 4) * i : (self.block_size // 4)*(i + 1)], "big") for i in range(4)]

        for i in reversed(range(self.rounds)):
            blocks = [blocks[-1]] + blocks[:-1]
            blocks[1] = self._f(blocks[1], blocks[0], self._round_keys[i])
        pt = bytearray() 
        for l in blocks:
            pt += l.to_bytes(self.block_size // 4, "big")
        return pt
    
    def encrypt(self, pt: bytes) -> bytes:
        counter = 1
        ct = b''
        for i in range(0, len(pt), self.block_size):
            ct += self.xor(self._encrypt_block(int.to_bytes(counter, length=16)), pt[i:i + self.block_size])
            counter += 1
        return ct


for i in range(3*37):
    key = long_to_bytes(random.randint(0, 2**64))
    cipher = Feistel(key, rounds=7, block_size=16)
    
    pt = bytes.fromhex(input("Plaintext (hex) "))
    if len(pt) > 1000:
        print("Too long")
        exit()
    pt = cipher._pad(pt, cipher.block_size)

    ct = cipher.encrypt(pt)
    c = random.randint(0, 1)
    if c == 0:
        print(random.randbytes(len(ct)).hex())
    else:
        print(ct.hex())
    
    player = int(input("Guess what? "))
    if player != c:
        print(f"May you be lucky next time, {player} != {c}")
        exit()

print("Congrats, here is flag DEAD{redact}")
```

This challenge uses a custom Feistel-style cipher that derives a keystream via some counter mode, where it encrypts the 16 byte string $0,0,...,\text{COUNTER}$, the last value being the counter value encoded as a byte. We note that the Feistel encryption works by splitting the 16 byte string into an array of 4 32-bit integers, i.e. $[0, 0, 0, \text{COUNTER}]$. $\text{COUNTER}$ increments for every new 16-length block. This encrypted output is then xored with the user's plaintext to obtain the ciphertext.

We have $3*37 = 111$ rounds, in which we send a single plaintext and receive either the encrypted ciphertext or just random bytes, and we need to be able to distinguish between the two. Each round initialises a new Feistel cipher with a randomised key, used to generate round keys $k_0, k_1, ..., k_6$

Because the cipher uses a xorstream, we can send a plaintext of all null bytes and obtain the keystream directly. The problem is now deriving whether or not the byte sequence we have is a valid keystream, or not!

We probably do not have sufficient information to distinguish random from valid keystream from just 1 block's worth, so let's put multiple blocks (i.e. increasing $\text{COUNTER}$ values in the keystream) and observe what happens.

Inserting some print statements into the Feistel object, we are able to represent the state of the 4 int32 array at each round as follows (let C denote $\text{COUNTER}$)

$[0, 0, 0, C]$ \<at the start>

$[F_0 = f(0,0,k_0), 0, C, 0]$ \<after round 1>

$[F_1 = f(0,F_0,k_1), C, 0, F_0]$ \<after round 2>

$[F_2 = f(C,F_1,k_2), 0, F_0, F_1]$ \<after round 3>

$[F_3 = f(0,F_2,k_3), F_0, F_1, F_2]$ \<after round 4>

$[F_6, F_3, F_4, F_5]$ \<after round 7>

Thus we wind up with $[F_6, F_3, F_4, F_5]$ for every block. $F_3$ is the oldest, and a quick analysis tells us that across multiple 16 byte blocks, the computed $F_0, F_1$ values are the same.

Since $f(C,F_1,k_2)$ performs $C \oplus \text{Perm}(\text{Sub}(F_1 \oplus k_2))$, we observe that the first 3 bytes of $F_2$ is consistent across all blocks in the keystream, with only the last byte differing.

This brings us into $F_3 = 0 \oplus \text{Perm}(\text{Sub}(F_2 \oplus k_3))$. Since xor and $\text{Sub}$ work at the byte level, the first 3 bytes of $\text{Sub}(F_2 \oplus k_3)$ must be consistent across all blocks in the keystream.

This presents an opportunity. Across multiple keystream blocks, if we can find some observable relation in $F_3$ leveraging constant values in the first 3 bytes of $\text{Sub}(F_2 \oplus k_3)$, we might be able to derive a distinguisher.

Let the bytes of $\text{Sub}(F_2 \oplus k_3)$ at the i'th block be represented as $b_0, b_1, b_2, d_i$, and let the function $\text{xtime}$ be represented as $x()$.

From
```py
def permutation(self, a: bytearray) -> bytearray:
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ (xtime(xtime(u ^ a[3])) ^ xtime(a[1]))
    a[1] ^= t ^ u ^ xtime(u ^ a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a
```
We find that:

$a_0 = b_1 \oplus b_2 \oplus d_i \oplus x(x(b_0 \oplus d_i)) \oplus x(b_1)$ 

$a_1 = b_2 \oplus d_i \oplus x(b_0 \oplus b_1 \oplus b_2)$ 

$a_2 = b_0 \oplus b_1 \oplus d_i \oplus x(b_2 \oplus d_i)$

$a_3 = b_0 \oplus b_1 \oplus b_2 \oplus x(d_i \oplus b_0)$

Of which given

```py
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
```
We can rewrite $x(a) = (a \ll 1)\oplus(\text{0x1B} * (a\gg 7))$.

 Notice that the bitwise shift left/shift right operations distribute over xor, meaning:

$x(a \oplus b)$ 

$= ((a\oplus b) \ll 1)\oplus(\text{0x1B} * ((a\oplus b) \gg 7))$

$= (a \ll 1)\oplus(b \ll 1) \oplus (\text{0x1B} * ((a \gg 7) \oplus (b \gg 7)))$

Since $a, b < 256$, testing on the 4 possible $(a \gg 7, b \gg 7)$ pairs allows us to rewrite the above as

$= (a \ll 1)\oplus(b \ll 1) \oplus \text{0x1B} * (a \gg 7) \oplus \text{0x1B} * (b \gg 7)$

$= x(a) \oplus x(b)$

We can thus rewrite $a_1, a_2, a_3$ in $F_3$ as

$a_1 = b_2 \oplus d_i \oplus x(b_0) \oplus x(b_1) \oplus x(b_2)$ 

$a_2 = b_0 \oplus b_1 \oplus d_i \oplus x(b_2) \oplus x(d_i)$

$a_3 = b_0 \oplus b_1 \oplus b_2 \oplus x(d_i) \oplus x(b_0)$

$\rightarrow a_1 \oplus a_2 \oplus a_3 = x(b_1)$

(we ignore $a_0$ because it uses nested xtimes and we do not want to deal with that)

We know from earlier that $b_1$ is constant across all blocks. This gives us our distinguisher.

Hence, for each round, we send say, a 48 byte plaintext. From the keystream, at every 16-byte block we check the corresponding $F_3 = a_0||a_1|| a_2||a_3$ value, notably whether $a_1 \oplus a_2 \oplus a_3$ is constant. If so, then we know it must be a valid keystream, otherwise it is a string of random bytes. (there is a rough 1/65536 chance it turns out to be a string of random bytes, but its unlikely we'll face it in 111 rounds).

One quick ad hoc remote script later, we get the flag!

`solve.py`
```py
from pwn import remote
from tqdm import trange

r = remote("nc.deadsec.quest", 31341)
for round in trange(3*37):
    r.recvuntil(b'Plaintext (hex) ')
    r.sendline(b'0' * 96)
    challenge = bytes.fromhex(r.recvline().rstrip().decode())
    blocks = []
    for k in range(0, len(challenge), 16):
        blocks.append([int.from_bytes(challenge[4*j+k:4*j+k+4], "big") for j in range(4)])    
    X0, X1, X2 = blocks[0][1], blocks[1][1], blocks[2][1]
    get_id = lambda X : X & 0xff ^ (X >> 8) & 0xff ^ (X >> 16) & 0xFF 
    player = 0
    if get_id(X0) == get_id(X1) == get_id(X2):
        player = 1
    r.sendline(str(player).encode())
r.interactive()
"""
[x] Opening connection to nc.deadsec.quest on port 31341
[x] Opening connection to nc.deadsec.quest on port 31341: Trying 34.60.81.56
[+] Opening connection to nc.deadsec.quest on port 31341: Done
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 111/111 [01:01<00:00,  1.81it/s]
[*] Switching to interactive mode
Guess what? Congrats, here is flag:
DEAD{0ba24bf1624717efe_your_h4ve_m4ths_for_PRF_d7db71b419f4985a}

[*] Got EOF while reading in interactive
[*] Interrupted
[*] Closed connection to nc.deadsec.quest port 31341
"""
```