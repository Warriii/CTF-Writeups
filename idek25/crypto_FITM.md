
This writeup was written by Mono from slightsmile! A few edits were made here and there by warri.

![alt text](Images\image-6.png)

`chall.py`
```py
from Crypto.Util.number import *
import random
import os

class idek():

	def __init__(self, secret : bytes): 

		self.secret = secret
		self.p = None	

		self.poly = None 

	def set_p(self, p : int):

		if isPrime(p):
			self.p = p

	def gen_poly(self, deg : int):

		s = bytes_to_long(self.secret)
		l = s.bit_length()
		self.poly = [random.randint(0, 2**l) for _ in range(deg + 1)]
		index = random.randint(deg//4 + 1, 3*deg//4 - 1)
		self.poly[index] = s
		print([i%self.p for i in self.poly])

	def get_share(self, point : int):

		if not self.p or not self.poly:
			return None

		return sum([coef * pow(point, i, self.p) for i, coef in enumerate(self.poly)]) % self.p

	def get_shares(self, points):

		return [self.get_share(point) for point in points]

def banner():

	print("==============================================")
	print("=== Welcome to idek Secret Sharing Service ===")
	print("==============================================")
	print("")

def menu():

	print("")
	print("[1] Oracle")
	print("[2] Verify")
	print("[3] Exit")
		
	op = int(input(">>> "))
	return op

if __name__ == '__main__':

	S = idek(os.urandom(80))
	deg = 16
	seen = []

	banner()

	for _ in range(17):

		op = menu()
		if op == 1:
			p = int(input("What's Your Favorite Prime : "))
			assert p.bit_length() == 64 and isPrime(p) and p not in seen
			seen += [p]
			S.set_p(p)
			S.gen_poly(deg)
			L = list(map(int, input("> ").split(",")))
			assert len(L) <= 3*deg//4
			print(f"Here are your shares : {S.get_shares(L)}")
		elif op == 2:
			print(S.secret.hex())
			if S.secret.hex() == input("Guess the secret : "):
				with open("flag.txt", "rb") as f:
					print(f.read())
			else:
				print("Try harder.")
		elif op == 3:
			print("Bye!")
			break
		else:
			print("Unknown option.")

```

In essence, the challenge is the following;

- At the start of the server instance, a 80 byte secret `S` is generated, which we wish to find out. 
- We are allowed to query for information by doing the following (16 times): 
	- We provide a 64-bit prime `p` (All primes provided must be distinct)
	- Server generates a random degree 16 polynomial $Q(x)$ with `s` as the coefficient of $x^i$, $4\le i\le 11$ 
	- We provide up to 12 values $x_1, x_2, \cdots, x_{12}$
	- We are given $Q(x_i) \pmod{p}$
- Then, we need to provide the server with `s`. 


Our first goal is to try and reconstruct the polynomial from some values of $x$ under mod $p$. However, by [Lagrange Interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial), we know that we simply do not have enough information to construct the full polynomial. So, we need to be more... sinister about what we input into the server. 

Trying consecutive values of $x_i$ doesn't seem to produce anything fruitful. The reader is encouraged to see what happens (Try inputting $x_i = i$). It also seems quite nice that: 
- $s$ must appear in the first 12 / last 12 positions
- We can provide exactly 12 values. 

Huh. Wouldn't it be nice if we could convert it into a degree 12 polynomial? 

However, by providing the server with the 12-th [roots of unity](https://en.wikipedia.org/wiki/Root_of_unity_modulo_n), we can do this, as $x^{12} =1 \pmod{p}$. This pretty much "collapses" the first and last 4 coefficients, and keeps the coefficients of $x^i$, $4\le i\le 11$ the same. 

```py
primes = []
residues = []

for i in range(16): 
    while True:
        p = getPrime(64)
        assert p.bit_length() == 64
        if (p in primes): continue
        if (p%12 == 1): 
            primes.append(p)
            break
    prim = 2
    pow_ = (p-1)//12
    residueP = []
    while True:
        for j in range(12): 
            redisue = pow(prim, pow_ * j, p)
            if redisue not in residueP:
                residueP.append(redisue)
        if len(residueP) == 12:
            residues.append(residueP)
            break
        prim += 1

io = remote("fitm.chal.idek.team", 1337) 

validSecResidues = []

for i in range(16):
    io.sendlineafter(b'>>> ', b'1')
    io.sendlineafter(b'Prime : ', str(primes[i]).encode())
    print("Sending prime", str(primes[i]).encode())
    io.sendlineafter(b'> ', ( str(residues[i])[1:-1] ).encode())
    print("Sending residues", ( str(residues[i])[1:-1] ).encode())
    io.recvuntil(b'shares : ')
    share_line = io.recvline().strip()
    share = eval(share_line.decode())
    print(f"Share {i}: {share}")

    Zp = Zmod(primes[i])
    Marr = [[] for _ in range(12)]
    for j in range(12): 
        for k in range(12): 
            Marr[j].append(Zp(residues[i][j]) ** k)
    vec = vector(Zp, share)
    M = matrix(Zp, Marr)
    sol = M.solve_right(vec)

    print(sol)
    print(list(sol[5:12]))
    print()

    residuesSecret = list(sol[5:12])
    validSecResidues.append([int(i) for i in residuesSecret])
```
---
Now, we have 7 different options for $s \pmod{p_i}$ across all $p_i$. We shall refer to the sets of these values as $S_i$. But what other information do we have to allow us to find out the possible values of $s$? Is it possible to pick $p_i$ well so that we can eliminate options quickly? 

The answer is, not really. The only way which we can extract information is via CRT, which does not provide us with much information whatsoever. In fact, the only help we seem to have is that $s$ is small (640 bits, compared to $\prod p_i$, which should be $\approx 64*16 = 1024$ bits)

Seems like a problem for LLL. But how do we go about expressing it in a matrix?

##### Observation 1: CRT can be expressed in a knackscap format. 
In brief, because of [Bezouts](https://en.wikipedia.org/wiki/Bézout%27s_identity), we can express CRT as an... addition of sorts. Specifically, by inducting on the traditional 2 value case of Bezouts, we get that there exists $c_i$ and a $k$ such that: 
$$
\left( \sum_{i=1}^{16} c_i\prod_{j\neq i} p_j \right) \;\;- \;\; k\left( \prod p_j \right) = \gcd(p_1, \cdots p_{16}) = 1
$$
Note that specifically, under mod $p_i$, we have that: 
$$c_i\prod_{j\neq i} p_j \equiv 1 \pmod{p_i}$$
So, to represent the condition $X \pmod{p_i}$, we may use the term: 
$$f(X, i) = Xc_i\prod_{j\neq i} p_j \pmod{\prod p_j }$$
In fact, lets refer to these values as set $V_i = \{f(X,i) | X \in S_i\}$.
##### Observation 2: We can express "picking a number from a set" with a variable. 
We have now reduced the question to us "choosing" 1 number from each $V_i$, summing them up, and taking it mod $\prod p_i$. However, this is still not that easy to model under LLL. We wish to encode this information in our target vector somehow. 

To do this, we may simply.... add a column representing the number of times elements from $S_i$ were used. 

So, our matrix should be of the following form:
![[Pasted image 20250811034529.png]]
Here, target is.... 0. After all, we wish to find the smallest possible vector. 

For obvious reasons, this doesnt.... work. We more or less get outputs which do not... use target, instead opting to settle itself and compare against $p_i$. We can try and fix this in a few ways. 

Lets try and: 
- Add another column to trace which row uses target
- Combine $\prod p_i$ and target=0 together. After all, that row seems to be the one which is causing issues. We can just iterate how many copies of $\prod p_i$ we need to add. 

```py
primeMult = 1
for i in range(16):
    primeMult *= primes[i]

for ooohooohaaaahaaah in range(16):
    print("Round", ooohooohaaaahaaah)
    Marr = [[0 for __ in range(7*16+16+2)] for _ in range(7*16+1)]
    scalSumPrime = primeMult
    valScal = 2**660
    for i in range(7*16):
        Marr[i][i] = 2*valScal
        Marr[-1][i] = -valScal

    for i in range(16):
        currVal = primeMult // primes[i]
        currVal = currVal * pow(currVal, -1, primes[i])
        assert currVal % primes[i] == 1
        for j in range(7):
            Marr[7*i+j][7*16 + i] = -scalSumPrime
            Marr[7*i+j][-1] = (currVal * validSecResidues[i][j]) % primeMult

    for i in range(16):
        Marr[-1][7*16 + i] = scalSumPrime
    Marr[-1][-1] = -primeMult*ooohooohaaaahaaah
    Marr[-1][-2] = 1



    M = matrix(Marr)
    ML = M.LLL()

    for nrow in ML:
        if (int(nrow[-1]).bit_length() > 640): continue
        works = True
        row = []
        for j in range(16):
            if nrow[7*16+j] != 0: 
                works = False
                break
        
        for j in range(7*16):
            if abs(int(nrow[j])//valScal) != 1: 
                works = False
                break

        if works:
            for i in range(16): 
                toPrint = []
                for j in range(7): 
                    toPrint.append(int(nrow[7*i+j])// valScal)
                print(toPrint)
            print(nrow[7*16:7*16+16])
            print("Secret:", int(nrow[-1]), "with length", int(nrow[-1]).bit_length())
            io.sendlineafter(b'>>> ', b'2')
            io.sendlineafter(b'Guess the secret : ', str(hex(int(nrow[-1]))[2:]).encode())
            io.interactive()
```

![alt text](Images\image0.jpg)

Running the code, we get:
```
idek{meet_the_flag_in_the_middle!}
```


Huh, strange. A meet in the middle attack. 

In hindsight, this is the easier solution. After all, to we just need to compute $7^8 \approx 5.7 \text{ Million}$. $n\log n$ is viable for such an $n$. 