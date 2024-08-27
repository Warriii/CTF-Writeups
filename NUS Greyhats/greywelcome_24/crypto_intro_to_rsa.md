### Intro to RSA 🍼 | 66 Solves 620 Points
```
Let's implement RSA together!

Author: Ariana
```

`chal.py`
```py
from Crypto.Util.number import isPrime,GCD # pip install pycryptodome
import random
import sys
from hashlib import sha256

MAGIC1 = "ff20b341f8bd54837ba6a7d68a01bfb6922c9ab3f86f7a24cd4376277f77fa00"
MAGIC2 = "66200057048904561310773450754513118682872987215243475408580973598511850449092621163958665485940959549116143328863633485610674754281932357951581747279569555286557989465547173185431765053999599204779436658547634756129524189103394473610686233103699165808690574337593176117530396663309220705224502578368073507606"
t = open(sys.argv[0],"r").read().replace(MAGIC1,"").replace(MAGIC2,"")
random.seed(t) # please dont modify this file!
assert sha256(t.encode()).hexdigest()==MAGIC1 # please dont modify this file!

def newPrime(nbits):
    t = 4
    while not isPrime(t):
        t = random.randint(2**(nbits-1),2**nbits-1)
    return t

p = newPrime(512)
q = newPrime(512)
e = 65537
N = p*q

print("Let's see if you know RSA!")
print("-"*16+"[parameters]---"+"-"*16)
print(f"{p = }")
print(f"{q = }")
print(f"{e = }")
print("")
print("-"*16+"[setup]---"+"-"*16)
c = random.randint(2**1023,2**1024-1)-int(MAGIC2)
print("Here is the ciphertext, which is computed by c=m^e mod N where m is the message")
print(f"{c = }")
print("")
print("-"*16+"[step 1]---"+"-"*16)
print("To recover m, we first compute the private key d.")
print("d must satisfy the following equation: e*d = 1 mod [(p-1)(q-1)]")
print("Hint: look up modular inverse")
d = int(input(f"d = "))
assert (e*d)%((p-1)*(q-1)//GCD(p-1,q-1))==1

print("-"*16+"[step 2]---"+"-"*16)
print("Now, compute m=c^d mod (pq)")
print("Hint: look up modular exponentiation")
m = int(input(f"m = "))
assert pow(m,e,p*q) == c

print("-"*16+"[flag]---"+"-"*16)
print("Now convert m to a string and submit it as a flag!")
print("Hint: pycryptodome long_to_bytes")

print("-"*16+"[why does it work]---"+"-"*16)
print("Notice that x^(p-1) mod p = 1 and x^(q-1) mod q = 1 for any x (coprime to N)")
print("Hence x^[k*(p-1)(q-1)+1]=x mod (pq) for any k")
print("Hence (x^e)^d=x mod N for any x where N=pq")
```

Evidently what we have here is standard RSA encryption. The challenge itself generates a prime `p`, `q` and public exponent `e`. We are given these exacvt parameters and are told to recover `d`, the private key. Following which it decrypts a ciphertext `c` into a output, being our flag in the form of an integer, `m`.

The challenge code itself hints towards how one can do this and guides you along the way. Let's also go on a similar tangent and look at how RSA Cryptography functions!

### RSA Cryptography, Explained

(this segment is definitely not plagiarised off of my WelcomeCTF23 Writeup)

RSA Cryptography works by converting your message into a very large number, then performing e number of multiplications of itself onto said number, modulo it by a large number n, then output the encrypted result.

What one generally needs to know is that in the cyclic multiplicative group of Integers Modulo some value `n`, usually a product of two primes `p` and `q`, with a generator `m`, we have a sequence of `m, m**2 % n, m**3 % n` etc. This cycle does return back to m at some point, and the number of times that we need to multiply m by itself to get there is the `order + 1`. (The order is actually defined as the number of times you need to multiply m by itself to get 1, modulo n). The security in RSA comes from making it hard to compute the order, but with the prime factorisation of n we can do:

`order = (p-1)*(q-1)` whereby `p*q == n`. Now the reason why this value happens to be the `order` is explained in the challenge, actually, as we see when we run `chal.py` and get to the end.

From there, we find the modular multiplicative inverse of `e` modulo `n`. Letting this value be `d`, this means that we find d such that `e*d == 1 mod order(n)`.

With this private key, given `c = m**e % n`, we have;

```py
c**d == (m**e)**d 
     == m**ed mod n 
     == m**(k*order(n) + 1) 
     == m**((order(n))*k) * m mod n
     == 1                 * m mod n 
     == m mod n
```
where `k` is some positive non-zero integer. Notice that as we have established the order such that `m**order == 1 mod n`, `m**((order(n))*k) mod n == 1**k mod n == 1 mod n`

### Solving the Challenge

So, we run the python script and obtain our parameters.
```
Let's see if you know RSA!
----------------[parameters]-------------------
p = 10918311508953460494712654527779080336321393782191731265090553157872794490868081977616381704507764350624871787735778119076851518302788040369052752258947443
q = 13275551522486616735703446932912517581753633626519470930436586509196008502354746481220757134944626046803204486283771742983058840097159145430953539904641457
e = 65537

----------------[setup]-------------------
Here is the ciphertext, which is computed by c=m^e mod N where m is the message
c = 61226191959841950045593716714957920903275614998708269477340360680366946740283888881387574625517952478635163607888097067352357022416351774332376038367624778277846665884495960669358666648683563209730395154465529191828062452080845088668801418575950931935586241660354948285141585860605256948441228236614466025674

----------------[step 1]-------------------
To recover m, we first compute the private key d.
d must satisfy the following equation: e*d = 1 mod [(p-1)(q-1)]
Hint: look up modular inverse
d =
```

We compute d using `d = pow(e, -1, (p-1)*(q-1))`, which we obtain to be `36589966977516346764375097952735197743969044262822125012495310835826761500264847089690866782274159568729451028295614769885536904984425569082540017876351868797447108183025174789916129327741822068618357854162185047029437708206901151183900602254316950608109486279721876125084536485295608578180893156014624029697`.

```
Hint: look up modular inverse
d = 36589966977516346764375097952735197743969044262822125012495310835826761500264847089690866782274159568729451028295614769885536904984425569082540017876351868797447108183025174789916129327741822068618357854162185047029437708206901151183900602254316950608109486279721876125084536485295608578180893156014624029697
----------------[step 2]-------------------
Now, compute m=c^d mod (pq)
Hint: look up modular exponentiation       
m =
```

We then compute `m = pow(c, d, p*q)` to get
`4481624626718542717349837486688775099814995281362698048681549428000637959668628458054185647086618565781516614589000946128017437565`

```
----------------[step 2]-------------------
Now, compute m=c^d mod (pq)
Hint: look up modular exponentiation       
m = 4481624626718542717349837486688775099814995281362698048681549428000637959668628458054185647086618565781516614589000946128017437565
----------------[flag]-------------------
Now convert m to a string and submit it as a flag!
Hint: pycryptodome long_to_bytes
----------------[why does it work]-------------------
Notice that x^(p-1) mod p = 1 and x^(q-1) mod q = 1 for any x (coprime to N)
Hence x^[k*(p-1)(q-1)+1]=x mod (pq) for any k
Hence (x^e)^d=x mod N for any x where N=pq
```

A neat way to show why the `(p-1)*(q-1)` gives a valid order for RSA!

We also obtain our flag by converting it to bytes;
```py
from Crypto.Util.number import long_to_bytes
flag = long_to_bytes(4481624626718542717349837486688775099814995281362698048681549428000637959668628458054185647086618565781516614589000946128017437565)
print(flag)
# b'grey{c0ngr4tz_u_c4n_d0_RSA_04728642737968273931467983}'
```