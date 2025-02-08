CyberLeague is a cybersecurity movement fronted by N0H4TS and aims to provide a competitive platform for all students and professionals alike to hone their cybersecurity skillsets in Singapore.

The local CTF had 3 rounds, qualifiers, playoffs, and finals. While my team of three washed crypto mains failed to qualify into playoffs as we wound up being skill issued in web and pwn, I was granted the opportunity to help set challenges for the second round. I submitted 4 Cryptography challenges (5 actually, but one of them felt too hard thus was omitted), 1 RE challenge and 1 Web challenge. As much as I'd have wanted to make difficult challenges, I was reminded of the fact that:

- The qualifier CTF is only 4 hours long
- The 10 qualified teams playing may not have strong crypto mains

Thus I made sure the challenges were solvable and not as obfuscated or difficult. Hopefully, that is. The intention was to set them such that even a non-crypto main might be able to solve with one's intuition, familiarity with algebra or other mathematic concepts, or with some googling.

This post covers my own writeups to all of them - 

Challenge Name | Gauged Difficulty | Challenge Category
---|---|---
[Wasted Oracle](#wasted-oracle)|Easy|Crypto
[ezc](#ezc)|Medium|Crypto
[Shamshir](#shamshir)|Medium|Crypto
[L-RSA](#l-rsa)|Medium|Crypto
[Whomp](#whomp)|Medium|RE
[Beep Boop](#beep-boop)|Medium|Web

Fun fact, there was supposed to be another challenge named `ezz`, which would revolve around a much harder concept! Ultimately I chose not to bring it into this CTF as I thought the shorter time and scope of it (only 10 teams) would not be a good setting for it. Stay tuned for whenever it appears in a future CTF!

## Wasted Oracle
```
I wasted a single decryption oracle opportunity...or did I?
```

`chall.py`
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import os

key = os.urandom(16)
iv = os.urandom(16)
FLAG = open("flag.txt", "rb").read().strip()
assert all(i in b'0123456789abcdef' for i in FLAG.rstrip(b'}').split(b'_')[-1])

FHSH = sha256(FLAG).hexdigest()
print(f"Hsh: {FHSH}")

cipher = AES.new(key=key, iv=iv, mode=AES.MODE_CBC)
ct = cipher.encrypt(pad(FLAG, AES.block_size))
print(f'ct = {ct.hex()}')

# My one decryption opportunity- oops! I got the ciphertext blocks all mixed up D:
cct = ct[64:80] + ct[48:64] + ct[32:48] + ct[16:32] + ct[0:16]
cipher = AES.new(key=key, iv=iv, mode=AES.MODE_CBC)
pt = cipher.decrypt(cct)
print(f'pt = {pt.hex()}')
"""
Hsh: d9a51f84f566d3ffed30737bb7fa3d22516979dc8d971a9aa22002581479fcbf
ct = 0d729e453ebcec60a78320fe06eaf143943a627f96dba8ec972c0f059aa30753763abacd1ba15b77038423fd6b4bd42e4f448a87e09935d39867d872d23ab7a55b136b4fa110f8d6847ebc0f81577400
pt = 4fe868ea40a4a6d848774f758f5cc6f14447b2e7e5839391b6a5aec08f7ac316b81c8ba7062efc56613fb20f3ceaef85152f7be75069e878c2586c7109c45732e0fea03202981d91615cb84b87ce796f
"""
```

This challenge revolves around the idea of a decryption oracle attempt supposedly "wasted". Instead of sending in the ciphertext to the decryption oracle to get the flag, we have the decrypted output of the ciphertext, but with its AES blocks in reverse instead. Nevertheless, this is in fact sufficient to obtain the flag!

The key here is in knowing how AES CBC works, at a layman level.

![alt text](image.png)

After spliting the plaintext into blocks of size 16, each plaintext is first xored with the IV, then parsed through the AES_ECB() block function. The new ciphertext is then used as the new IV for the next plaintext block. AES CBC decryption is the same thing, but in reverse.

Thus, in treating AES_ECB() as some blackbox function f(), we have:

```
    p0      p1      p2      p3      p4
iv  X    c0 X    c1 X    c2 X    c3 X
    f0      f1      f2      f3      f4
ENC()
    c0      c1      c2      c3      c4


    a0      a1      a2      a3      a4
iv  X    c4 X    c3 X    c2 X    c1 X
    f4      f3      f2      f1      f0
ENC()
    c4      c3      c2      c1      c0
```

with $p_0, p_1, ..., p_4$ as the plaintext (flag) blocks and $c_0, c_1, ..., c_4$ as the ciphertext blocks. $a_0, ..., a_4$ represents the oracle output that we have access to. $X$ here denotes the xor function. A key characteristic of the xor function is that if $a \wedge b == c$, then $c \wedge b == a$.

In letting $f_0, f_1, ..., f_4$ be the output of the AES_ECB() function, we use the aforementioned characteristic to get a series of xor equations of which we can derive the middle flag blocks:

```
c2 ^ a3 ^ c0 == p1
c3 ^ a2 ^ c1 == p2
c4 ^ a1 ^ c2 == p3
```

Additionally, we also have
```
iv ^ p4 == c3 ^ a0
iv ^ p0 == c1 ^ a4
p0 ^ p4 == c3 ^ a0 ^ c1 ^ a4
```

Giving us `p0 ^ p4`. Knowing the flag format, by guessing the padding we can derive majority of the `p0` and `p4` flag blocks. Following which we either do a simple brute force or just derive the flag.

### solve.py
```py
Hsh = "d9a51f84f566d3ffed30737bb7fa3d22516979dc8d971a9aa22002581479fcbf"
ct = bytes.fromhex("0d729e453ebcec60a78320fe06eaf143943a627f96dba8ec972c0f059aa30753763abacd1ba15b77038423fd6b4bd42e4f448a87e09935d39867d872d23ab7a55b136b4fa110f8d6847ebc0f81577400")
pt = bytes.fromhex("4fe868ea40a4a6d848774f758f5cc6f14447b2e7e5839391b6a5aec08f7ac316b81c8ba7062efc56613fb20f3ceaef85152f7be75069e878c2586c7109c45732e0fea03202981d91615cb84b87ce796f")

from hashlib import sha256
from Crypto.Util.strxor import strxor
a0, a1, a2, a3, a4 = [pt[i:i+16] for i in range(0, len(pt),16)]
c0, c1, c2, c3, c4 = [ct[i:i+16] for i in range(0, len(ct),16)]
p1 = strxor(strxor(a3, c2), c0)
p2 = strxor(strxor(a2, c3), c1)
p3 = strxor(strxor(a1, c4), c2)

p0p4 = strxor(strxor(c3, a0), strxor(c1, a4))

# for i in range(15):  # checking last few bytes of some_p1 from the guessed paddings will reveal that its is \x01
i = 1
known_p3 = p0p4[:16-i-1] + b'}' + chr(i).encode() * i
known_p0 = b'CYBERLEAGUE{' + p0p4[12:]
some_p4 = strxor(b'\x00' * (16-i-1) + b'}' + chr(i).encode() * i, strxor(known_p0, p0p4))
some_p0 = strxor(b'CYBERLEAGUE{' + b'\x00' * 4, strxor(known_p3, p0p4))
print(some_p0, p1, p2, p3, some_p4)

# either guess 'xoring' in p1, or brute through the 16 hex digits in some_p3's unknown to recover the flag

test_p0 = b'CYBERLEAGUE{xori'
test_p4 = strxor(test_p0, p0p4)
test_flag = test_p0 + p1 + p2 + p3 + test_p4
flag = test_flag[:-test_flag[-1]]
print(f'{flag = }')
assert sha256(flag).hexdigest() == Hsh
```

## EZC
```
I've learnt how to link Elliptic Curve Points to numbers! Made a super duper secure authentication system for it, it even generates authcodes!

nc 34.87.163.49 20001 
```

`src.py`
```py
from sage.all import EllipticCurve, Zmod, ZZ
from base64 import b64decode, b64encode
from secret import flag
import random

P =	ZZ(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
Gx = ZZ(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296) 

E = EllipticCurve(Zmod(P),[0,7])
G = E.lift_x(Gx)
d = random.randint(1, P)
table = []

def int2b64(x):
    return b64encode(x.to_bytes((x.bit_length() + 7) // 8, "big")).decode()

def b642int(x):
    return int.from_bytes(b64decode(x), "big")

def getAuthCode(id):
    try:
        point = E.lift_x(id)
    except ValueError:
        return -1
    if (point[0] == Gx):
        return -1
    res = int((d*point)[0])
    table[res] = id
    return res


def verify(x):
    userPoint = E.lift_x(x)
    altPoint = E.point([x, -userPoint[1]])
    if (d*G == userPoint or d*G == altPoint):
        return 1, 0
    if userPoint[0] in table:
        return 2, table[userPoint[0]]
    return 0, 0
    

print("""
                     ___   ____   ___ 
                    / _ \ |_  /  / __|
                   |  __/  / /  | (__ 
                    \___| /___|  \___|
      """)
print("Welcome to my super duper secure EzC Authentication system!")
while True:
    print('-' * 100)
    a = ZZ(input("Would you like to get an auth code [0] or attempt to verify? [1]\n>> "))


    if (a == 1):
        b = ZZ(b642int(input("Enter auth code: ")))
        res, user = verify(b)
        if res == 1:
            print(f"Welcome admin! {flag}")
            break
        elif res == 2:
            print(f"Welcome user {user}!")
            break
        else:
            print("[ERROR] Authentication failed. Invalid user.")
    elif a == 0:
        b = ZZ(input("Enter your id:\n>> "))
        res = getAuthCode(b)
        if res == -1:
            print("[ERROR] Code Invalid.")
        else:
            print("[AUTHCODE] Code successful. Authcode is:", int2b64(res))
    else:
        print("[ERROR] Initial option invalid.")
```

The challenge simulates some sort of authentication oracle.

We can give it inputs, in the form of an x coordinate of a point on an Elliptic Curve. The oracle then computes a point $P$ on the curve from the x coordinate, then provides us with a corresponding authentication token by performing $d*P$ with $d$ as the private multiplier. The curve in question is actually the [secp256k1](https://neuromancer.sk/std/secg/secp256k1) curve which is actually used in Bitcoin's own public key cryptography.

To get the flag, we must show that we are a valid user by showing the authentication token of $G$, where $G$ is some point of, probably some user that can access the flag.

Ideally from an insecure authenticator we can submit $G$ directly to the oracle, and perhaps we can acquire $d*G$. But it appears the source code already covers that:

```py
def getAuthCode(x):
    try:
        point = E.lift_x(x)
    except ValueError:
        return -1
    if (point[0] == Gx):
        return -1
    ...
```

Conceptually, the security relies on the difficulty of the [Elliptic Curve Discrete Logarithm Problem (ECDLP)](https://link.springer.com/referenceworkentry/10.1007/978-1-4419-5906-5_246) - given points $G$, $d*G$ on a given Elliptic Curve, it is hard to recover $d$. Without being able to recover $d$, in theory this means we can never be able to spoof our own $d*G$.

The latter statement, however, is untrue. This system has a gaping hole in that the `+` (Curve Point Addition) and `*` (Curve Point Scalar Multiplication) operations on an elliptic curve is distributive. Or rather, $a * (B + C) = a * B + a * C$ with $a$ a scalar and $B, C$ as points.

Thus, we fool the oracle by obtaining the authentication tokens of two points $P, Q$ such that $P + Q = G$. We do this by setting $P$ as any point on the curve and computing $Q = G - P$.

After we get $d*Q$ and $d*P$, we can then do $d*Q + d*P = d * (P+Q) = d*G$, allowing us to pose as an admin and obtain the flag.

It should be noted that due to the symmetry of curve points about the x-axis, it is possible that $d*Q - d*P$ gives us the correct x coordinate of $d*G$ instead. This should not be an issue however as we can attempt to spoof our token multiple times.

### solve.py
```py
from sage.all import ZZ, Zmod, EllipticCurve
from base64 import b64decode, b64encode

def int2b64(x):
    return b64encode(x.to_bytes((x.bit_length() + 7) // 8, "big")).decode()

def b642int(x):
    return int.from_bytes(b64decode(x), "big")

P =	ZZ(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
Gx = ZZ(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)

E = EllipticCurve(Zmod(P),[0,7])
G = E.lift_x(Gx)

P = E.lift_x(ZZ(1))
Pd = E.lift_x(ZZ(b642int(input("Send result of sending 1 to oracle: "))))

P_ = E.point([P[0],-P[1]]) 
assert P_ == -1 * P

Q = G + P_
assert Q + P == G

Qd = E.lift_x(ZZ(b642int(input(f"Send result of sending {Q[0]} to oracle: "))))

Gds = [Pd + Qd, Pd - Qd]

print(f"Try these:")
print([int2b64(int(i[0])) for i in Gds])
```

Aside from exploiting the distributive-like nature, there exists another method that exploits the known order of the elliptic curve. Do you see it?

## Shamshir
```
FlagIsland introduces Shamshir, a totally original secret sharing scheme! 18 shares will be delivered to everyone. The secret will only be given IF you and someone else agree to share shares! Except...you can't communicate with any of the 17 other folks. LOL!

nc 34.87.163.49 20002
```

`shamshir.py`
```py
from Crypto.Util.number import inverse, getRandomRange
from math import prod
from shamshir_confidential import FLAG

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N_SHARES = 18


def f(poly, x):
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= P
    return accum


def make_shares(secret):
    poly = [secret] + [getRandomRange(1,P-1) for i in range(N_SHARES - 1)]
    xs = []
    while len(xs) < N_SHARES:
        num = getRandomRange(1, P-1)
        if num not in xs:
            xs.append(num)
    return [(x, f(poly, x)) for x in xs]


def recover_secret(shares):
    x_s, y_s = zip(*shares)
    k = len(x_s)
    nums = []
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(prod( - o for o in others))
        dens.append(prod(cur - o for o in others))
    den = prod(dens)
    num = sum([nums[i] * den * y_s[i] * inverse(dens[i], P) % P for i in range(k)])
    return (num * inverse(den, P) + P) % P


def main():
    print(r"""BANNER""")

    secret = getRandomRange(1,P-1)
    shares = make_shares(secret)
    
    xs = [i[0] for i in shares]
    print(f"Shares are initialised at:\n{xs = }")

    your_share = shares[0]
    print(f'Your share: {your_share}')
    x = int(input('Enter share x coordinate that ISNT yours: ')) % P
    y = int(input('Enter share y coordinate that ISNT yours: ')) % P
    print(f"Recovered Secret: {recover_secret(shares[1:] + [(x,y)])}")
    print(f"[AUTH] Enter secret to obtain flag: ")
    user_secret = int(input('>> ')) % P
    if (user_secret == secret):
        if x == your_share[0] and y == your_share[1]:
            print("[AUTH] TAMPERING DETECTED")
            return
        print(f"[AUTH] {FLAG}")
        return
    print("[AUTH] Authentication Failed.")


if __name__ == '__main__':
    main()
```

What we have here is essentially an implementation of [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) scheme. The scheme typically works by generating shares, which are just points on some polynomial curve generated from some secret value. Depending on the exponent of the polynomial, a certain number of shares is needed to be known for one to derive the polynomial, and thus recover the secret. This derivation method is known as [Lagrange Interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial), a variation of which is implemented in `recover_secret()` to derive the secret value, which is really the $x^0th$ coefficient of the polynomial.

The scheme here provides 18 shares, and we are provided with one. We only need to show that we know the knowledge of one other share / point aside from ours, in which case the system will recover the secret. We just need to re input the secret to recover the flag.

The problem is, we only have 1 point, and the server prevents us from just entering our own point to recover secret and the flag. Inputting any other random point is sure to mess up the lagrange interpolation, giving some useless secret value.

Not really. Lagrange's Interpolation can essentially be reduced to the following:

$y_0 * f_0 + y_1 * f_1 + ... + y_i * f_i + ... + y_n * f_n$ 

where $f_0, ..., f_n$ are functions that involve the $x_0, ..., x_n$ values, which are publicly known.

Thus, given our own $(x_i, y_i)$ share, we can send $(x_i, y_i - 1)$ to the server. This gives us:

$y_0 * f_0 + y_1 * f_1 + ... + (y_i * f_i - f_i)+ ... + y_n * f_n$ 

We can then compute $f_i$ on our end, and add it back to recover the secret $S$, thus allowing us to recover the flag after.

### solve.py
```py
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
from Crypto.Util.number import inverse

def lagrange_coeff(xs, x):
    res = 1
    for xi in xs:
        if xi == x:
            continue
        res *= xi
        res *= inverse(xi - x, P)
        res %= P
    return res

xs = [7580133114823494824772972037546618759907391863246475865347937008768961451007, 53259453479359834528037573839579659638735299411396345643800031974917251779506, 77239464635336853672884950722468061613663992474015377399535840216360117954754, 94510965810719821034360960244798064176416952264091744115433529429351284245413, 86840990514261653569195393332202194843767800304886524410568848216032474977650, 74237232617532856545256405234820303286010305566478529239245425350843691695430, 4688363888947365176495787635240065722157080934798145532058153441772285402306, 58432227523949367809088605221694106297178316318139310265956981511024144116666, 30817533276316412520910349708014923665077047865090235551398748561780024284157, 54927578519591925531527647716877703341331793867883267234922654336739011898105, 15952656779740073431045123511172344987770762399787130447089435259974350110988, 96196628690104048295496824109466540544126577219678181996837821121262619545042, 21982415821605718231666396741110400476472430601153348996429976397472256766924, 105012246378930634933357112770970743338434365085800663728977956380500457967062, 36696426418446811958777568612206645846715780481685202369373884165548563665488, 113173458891628507809247328686955253427859576645691220878850991044573143449603, 69698833512343584374628570818498586223762840663529393962006798664023125864549, 13592399275652014539401713513314321072108554941366788543669484580107878683197]
# input your (x, y-1) into the recovery

S = 21501642562824431022242585947690849916127463674516191047518768410608682018866

print((S + lagrange_coeff(xs, xs[0])))

"""
Shares are initialised at:
xs = [7580133114823494824772972037546618759907391863246475865347937008768961451007, 53259453479359834528037573839579659638735299411396345643800031974917251779506, 77239464635336853672884950722468061613663992474015377399535840216360117954754, 94510965810719821034360960244798064176416952264091744115433529429351284245413, 86840990514261653569195393332202194843767800304886524410568848216032474977650, 74237232617532856545256405234820303286010305566478529239245425350843691695430, 4688363888947365176495787635240065722157080934798145532058153441772285402306, 58432227523949367809088605221694106297178316318139310265956981511024144116666, 30817533276316412520910349708014923665077047865090235551398748561780024284157, 54927578519591925531527647716877703341331793867883267234922654336739011898105, 15952656779740073431045123511172344987770762399787130447089435259974350110988, 96196628690104048295496824109466540544126577219678181996837821121262619545042, 21982415821605718231666396741110400476472430601153348996429976397472256766924, 105012246378930634933357112770970743338434365085800663728977956380500457967062, 36696426418446811958777568612206645846715780481685202369373884165548563665488, 113173458891628507809247328686955253427859576645691220878850991044573143449603, 69698833512343584374628570818498586223762840663529393962006798664023125864549, 13592399275652014539401713513314321072108554941366788543669484580107878683197]
Your share: (7580133114823494824772972037546618759907391863246475865347937008768961451007, 62498913670317975349686452207044704776423433228110417399420346826725882722695)
Enter share x coordinate that ISNT yours: 7580133114823494824772972037546618759907391863246475865347937008768961451007
Enter share y coordinate that ISNT yours: 62498913670317975349686452207044704776423433228110417399420346826725882722694
Recovered Secret: 21501642562824431022242585947690849916127463674516191047518768410608682018866
[AUTH] Enter secret to obtain flag:
>> 137257525893111338113440821856831802679445916973982093913430080608002527130906
[AUTH] CYBERLEAGUE{0n3_stEp_furth3r_4nd_y0u_c4n_st@rt_f0rg1ng_s3creT5!}
"""
```

## L-RSA
```
Wonder what the L stands for...
```

`chall.py`
```py
from Crypto.Util.number import *
from secret import flag


def keygen():
    p,q = getPrime(512), getPrime(512)
    x = getRandomInteger(512)
    a,b = getRandomNBitInteger(500), getRandomNBitInteger(500)
    a,b = a*x, b*x
    c = a*p + b*q
    return (a,b,c), (p,q)


def encrypt_priv(m, priv):
    p, q = priv
    n = p*q
    assert m < n
    return pow(m, 0x10001, n)


pub, priv = keygen()
ct = encrypt_priv(bytes_to_long(flag), priv)
print(f'{ct = }')
print(f'{pub = }')
"""
ct = 62818049451844130066544084308842540071082488863680727760560794334193284759945284282361022467248427723833976899284847446503158710281544666599641088998964239393887837688101457039795257255252789272980753628158669503135043170249505518090485617464855136135375695470949478575808638991395487049265670382803283262979
pub = (20315220434888286087957078448040648285679641923331653574408879032284326288770810098150865087384202009797089937209857758711663674898432795988148111174304173198020225322150395384891995060460199145895730461888713113394938220227918441775459478532347086762571253317271173257132689464294879580824559762495058178, 18987398555188829872832660674905173126514411243473432571589490787862487855073182736281358074297777231507149256938589989939623604918436111709491869451460290233271116401163561915506155481066746423535398790065413451407718918126684998928790819813608615111743556839174248067344033363588749740318947090798169060, 415438593861346977962916899465014430021182425691306152459339944883974199339883734334744495037358168720809989963968471594468534650401092296177163149232810386114259763005672076477251490166110860507628632265270901760495355239000886211129565050763052595865391121407447009493030272204905951742442254629082936518488767153422813023101105487828422574040626809330697681794839022998934631271553777264336843240863666401394891817368783144540271659460631237766994802368574)
"""
```

This deceptively simple challenge involves one round of RSA, with an RSA encrypted flag. We are given the RSA modulus $n$, as well as some hint value $a = a' * x, b = b' * x, c = a * p + b * q$, with $p, q$ as the prime factors in $n$, and knowing that there exists some 512-bit value $x$, and 500 bit values $a$ and $b$.

A lattice-based approach would be to use the equation $a * p + b * q - c == 0$, and then generate the lattice:

```
1   0   0       a
0   1   0       b
0   0   2^512   c
```

whereby in theory, the vector $(p, q, -1)$ will multiply with the lattice to generate a possible basis $(p, q, -2^{512}, 0)$ which might be small enough for us. We use $2^{512}$ in order to scale the lattice and ensure the first 3 values remain consistent with each other, bit wise.

After LLL we might recover some 
$10914411941744234397459063579665753522407903867122722342626027045455400592964347386793605447675921975006386858842526865411535050834581702873326610475365533$ and $10202024715739650329058891324278358460397288293000728975734924587099648188799042255295773148189947778485078406043734792905065401772146962533732292029324745$ as our possible $p, q$ pair, but these values arent primes.

We'll have to find a way to generate other possible pairs, or to find other solution pairs from this. I believe one way to do this would be via lattice enumeration, but there is a much simpler approach.


The truth is, the `L` in `L-RSA` doesn't stand for Lattices, but for [Linear Diophantine Equation](https://en.wikipedia.org/wiki/Diophantine_equation), of which there exists a neat little theorem,

```
The Linear Diophantine equation ax + by = c has a solution (where x and y are integers) if and only if c is a multiple of the greatest common divisor of a and b. Moreover, if (x, y) is a solution, then the other solutions have the form (x + kv, y − ku), where k is an arbitrary integer, and u and v are the quotients of a and b (respectively) by the greatest common divisor of a and b.
```

This is provable using [Bezout's Identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity). From our current existing valid $(p', q')$ pair, we can use this theorem and expand it to cover other possible pairs. Because the gcd $x$ is 512 bits, knowing $p$ and $q$ also being 512 bits, there is a very brutable range of $2^{12}$ to recover our primes. We can even bypass the initial lattice approach, and apply this theorem immediately. By getting any valid solution pair (which can be trivially done with [Extended GCD](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)) we can get a similar estimate which our lattice has already done!

Regardless, after recovering $p$, $q$, we can then perform RSA decryption with little difficulty.

### solve.py
```py
from sympy.core.numbers import igcdex
from Crypto.Util.number import isPrime, long_to_bytes
from math import gcd

ct = 62818049451844130066544084308842540071082488863680727760560794334193284759945284282361022467248427723833976899284847446503158710281544666599641088998964239393887837688101457039795257255252789272980753628158669503135043170249505518090485617464855136135375695470949478575808638991395487049265670382803283262979
pub = (20315220434888286087957078448040648285679641923331653574408879032284326288770810098150865087384202009797089937209857758711663674898432795988148111174304173198020225322150395384891995060460199145895730461888713113394938220227918441775459478532347086762571253317271173257132689464294879580824559762495058178, 18987398555188829872832660674905173126514411243473432571589490787862487855073182736281358074297777231507149256938589989939623604918436111709491869451460290233271116401163561915506155481066746423535398790065413451407718918126684998928790819813608615111743556839174248067344033363588749740318947090798169060, 415438593861346977962916899465014430021182425691306152459339944883974199339883734334744495037358168720809989963968471594468534650401092296177163149232810386114259763005672076477251490166110860507628632265270901760495355239000886211129565050763052595865391121407447009493030272204905951742442254629082936518488767153422813023101105487828422574040626809330697681794839022998934631271553777264336843240863666401394891817368783144540271659460631237766994802368574)

a,b,c = pub

# Use extended euclidean algorithm to find a solution pair
uu,vv,g = igcdex(a,b)
assert g == gcd(a,b)
assert uu*a + b*vv == g

# Derive a valid solution pair to the linear diophantine eqn
cg = c // g
pp, qq = cg*uu, cg*vv
assert pp*a + qq*b == c

# swap values for sign
if pp < 0 and qq > 0: 
    tmp = pp
    pp = qq
    qq = tmp
    tmp = b
    b = a
    a = tmp

# The equation ap + bq == c with unknowns p,q is a linear diophantine equation
# if (p,q) is a soln, then (p - kv), (q + ku) is a solution if a == u*g and b == v*g
u,v = a // g, b // g
k = (2**512 - qq) // u
pp, qq = pp - k*v, qq + k*u # get a rough solution pair where both pp and qq are about 512 bits.
# we can also get to a more closer approximation using LLL, primarily the lattice
#   [1  0   0       a]
#   [0  1   0       b]
#   [0  0   2**512  c]
# which after LLL we can recover some 
# t1 = 10914411941744234397459063579665753522407903867122722342626027045455400592964347386793605447675921975006386858842526865411535050834581702873326610475365533
# t2 = 10202024715739650329058891324278358460397288293000728975734924587099648188799042255295773148189947778485078406043734792905065401772146962533732292029324745
# we'll still need u and v to find other solution pairs however. In theory lattice enumeration could work(?), but I got stuck implementing it lol

# Notice that u, v are 500 bits. For pp, qq to remain 512 bits, there can only be about 2**13 valid solution pairs, else pp or qq may be 513 or 511 bits.
for k in range(-2**13, 2**13):
    p,q = pp - k*v, qq + k*u
    if p.bit_length() != 512 or q.bit_length() != 512:
        continue
    if isPrime(p) and isPrime(q):
        print(f'Found at {k = }\n{p = }\n{q = }')
        n = p*q
        phi = (p-1) * (q-1)
        d = pow(0x10001, -1, phi)
        m = pow(ct, d, n)
        print(long_to_bytes(m))
        
    t1 = 10914411941744234397459063579665753522407903867122722342626027045455400592964347386793605447675921975006386858842526865411535050834581702873326610475365533
    t2 = 10202024715739650329058891324278358460397288293000728975734924587099648188799042255295773148189947778485078406043734792905065401772146962533732292029324745
    if (p == t1 and q == t2) or (q == t1 and p == t2):
        print("Sanity checked", k)
```

## Whomp

Opening the binary in IDA we obtain the following:

```cpp
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // eax
  char v5; // [rsp+3h] [rbp-CDh]
  int i; // [rsp+4h] [rbp-CCh]
  int v7; // [rsp+8h] [rbp-C8h]
  int v8; // [rsp+Ch] [rbp-C4h]
  int j; // [rsp+10h] [rbp-C0h]
  int v10; // [rsp+14h] [rbp-BCh]
  int k; // [rsp+18h] [rbp-B8h]
  int m; // [rsp+1Ch] [rbp-B4h]
  int n; // [rsp+20h] [rbp-B0h]
  int ii; // [rsp+24h] [rbp-ACh]
  signed int jj; // [rsp+28h] [rbp-A8h]
  signed int kk; // [rsp+2Ch] [rbp-A4h]
  int mm; // [rsp+30h] [rbp-A0h]
  int v18; // [rsp+34h] [rbp-9Ch]
  BYTE **ptr; // [rsp+38h] [rbp-98h]
  _QWORD v20[2]; // [rsp+40h] [rbp-90h] BYREF
  int v21; // [rsp+50h] [rbp-80h]
  char s[88]; // [rsp+60h] [rbp-70h] BYREF
  unsigned __int64 v23; // [rsp+B8h] [rbp-18h]

  v23 = __readfsqword(0x28u);
  v5 = 1;
  ptr = (BYTE **)malloc(0x50uLL);
  for ( i = 0; i <= 9; ++i )
    ptr[i] = (BYTE *)malloc(0xAuLL);
  printf(
    "UGRH!! The Whomp boldly announces his presence as the imposing wall stands between you and the flag.\n"
    "The Whomp seems to only understand binary.\n"
    "What do you say to the Whomp?\n"
    ">> ");
  fgets(s, 87, stdin);
  if ( strlen(s) > 0x56 )
    s[86] = 0;
  v7 = 0;
  v8 = 0;
  for ( j = 0; j <= 85; ++j )
  {
    if ( s[j] != '1' && s[j] != '0' )
      v5 = 0;
    if ( s[j] == '1' )
      ++v7;
  }
  v10 = 0;
  for ( k = 0; k <= 9; ++k )
  {
    for ( m = 0; m <= 9; ++m )
    {
      if ( (unsigned int)sub_1401(10 * k + m) )
      {
        ptr[k][m] = '0';
      }
      else
      {
        v3 = v10++;
        ptr[k][m] = s[v3];
      }
    }
  }
  for ( n = 0; n <= 8; ++n )
  {
    for ( ii = 0; ii <= 8; ++ii )
    {
      if ( ptr[n][ii] == '1' && ptr[n + 1][ii] == '1' && ptr[n][ii + 1] == '1' && ptr[n + 1][ii + 1] == '1' )
        v5 = 0;
    }
  }
  for ( jj = 0; jj <= 9; ++jj )
  {
    for ( kk = 0; kk <= 9; ++kk )
    {
      v18 = sub_1401(10 * jj + kk);
      if ( v18 )
      {
        sub_138B((__int64)ptr, jj, kk, 'C', '0');
        v8 += dword_409C;
        if ( v18 != dword_409C )
          v5 = 0;
      }
    }
  }
  sub_138B((__int64)ptr, 7u, 3u, 'D', '1');
  if ( v7 != dword_409C )
    v5 = 0;
  if ( v7 + v8 != 100 )
    v5 = 0;
  if ( v5 )
  {
    puts("UGRH. The Whomp grunts and steps aside. You get the flag:");
    v20[0] = 0LL;
    v20[1] = 0LL;
    v21 = 0;
    SHA1(s, 86LL, v20);
    sub_1462(v20, &byte_4060, 47LL);
    puts(&byte_4060);
  }
  else
  {
    puts("UGRH! The Whomp crushes you as you try to get the flag.\nBetter luck next time!");
  }
  for ( mm = 0; mm <= 9; ++mm )
    free(ptr[mm]);
  free(ptr);
  return 0LL;
}
```

We see that:
the binary expects an 86 length input that are either `1` or `0`.

```cpp
__int64 __fastcall sub_1401(int a1)
{
  unsigned int v2; // [rsp+18h] [rbp-18h]
  int i; // [rsp+1Ch] [rbp-14h]

  v2 = 0;
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( a1 == s[i] )
      ++v2;
  }
  return v2;
}
```

`sub_1401()` reads a global, constant string `s` and returns the count of number of occurrences of the input `a1`.

```cpp
__int64 __fastcall sub_138B(__int64 a1, unsigned int a2, unsigned int a3, char a4, char a5)
{
  __int64 result; // rax

  dword_409C = 0;
  result = *(unsigned __int8 *)(*(_QWORD *)(8LL * (int)a2 + a1) + (int)a3);
  if ( a5 == (_BYTE)result )
    return sub_1229(a1, a2, a3, (unsigned int)a4, (unsigned int)a5);
  return result;
}
```

`sub_138B()` on the other hand calls `sub_1229()`, which,

```cpp
__int64 __fastcall sub_1229(__int64 a1, unsigned int a2, unsigned int a3, char a4, unsigned int a5)
{
  __int64 result; // rax
  char v6; // [rsp+8h] [rbp-18h]

  result = a5;
  v6 = a5;
  if ( a2 <= 9 && a3 <= 9 )
  {
    result = *(unsigned __int8 *)(*(_QWORD *)(8LL * (int)a2 + a1) + (int)a3);
    if ( (_BYTE)a5 == (_BYTE)result )
    {
      result = *(unsigned __int8 *)(*(_QWORD *)(8LL * (int)a2 + a1) + (int)a3);
      if ( a4 != (_BYTE)result )
      {
        *(_BYTE *)((int)a3 + *(_QWORD *)(8LL * (int)a2 + a1)) = a4;
        ++dword_409C;
        sub_1229(a1, a2 + 1, a3, (unsigned int)a4, (unsigned int)(char)a5);
        sub_1229(a1, a2 - 1, a3, (unsigned int)a4, (unsigned int)v6);
        sub_1229(a1, a2, a3 + 1, (unsigned int)a4, (unsigned int)v6);
        return sub_1229(a1, a2, a3 - 1, (unsigned int)a4, (unsigned int)v6);
      }
    }
  }
  return result;
}
```

while slightly hard to tell, is in essence a [flood fill](https://en.wikipedia.org/wiki/Flood_fill)! This gives us the impression that the input is being interpreted as a 2-dimensional graph, which on closer inspection is a 10 by 10 grid.

Looking at `main()` closely, we find:

```cpp
  for ( j = 0; j <= 85; ++j )
  {
    if ( s[j] != '1' && s[j] != '0' )
      v5 = 0;
    if ( s[j] == '1' )
      ++v7;
  }
  v10 = 0;
  for ( k = 0; k <= 9; ++k )
  {
    for ( m = 0; m <= 9; ++m )
    {
      if ( (unsigned int)sub_1401(10 * k + m) )
      {
        ptr[k][m] = '0';
      }
      else
      {
        v3 = v10++;
        ptr[k][m] = s[v3];
      }
    }
  }
```
These two for loops interpret our input string and fills a 10 by 10 table with either `"1"` or `"0"`

```cpp
  for ( n = 0; n <= 8; ++n )
  {
    for ( ii = 0; ii <= 8; ++ii )
    {
      if ( ptr[n][ii] == '1' && ptr[n + 1][ii] == '1' && ptr[n][ii + 1] == '1' && ptr[n + 1][ii + 1] == '1' )
        v5 = 0;
    }
  }
```

This for loop makes sure that there's no 2 by 2 square of all `"1"`s

```cpp
  for ( jj = 0; jj <= 9; ++jj )
  {
    for ( kk = 0; kk <= 9; ++kk )
    {
      v18 = sub_1401(10 * jj + kk);
      if ( v18 )
      {
        sub_138B((__int64)ptr, jj, kk, 'C', '0');
        v8 += dword_409C;
        if ( v18 != dword_409C )
          v5 = 0;
      }
    }
  }
```
This for loop checks for the special cases in which `sub_1401()` returns a positive value and ensures a flood fill centred at the position colours the same number of grid values as the returned value.

```cpp
  sub_138B((__int64)ptr, 7u, 3u, 'D', '1');
  if ( v7 != dword_409C )
    v5 = 0;
  if ( v7 + v8 != 100 )
    v5 = 0;
```
Whereas the last check ensures that the `"1"`s are all connected, then ensures that the sum of the `"0"`s encountered during the various other flood fill calls and of the `"1"`s add up to 100, the area of the grid.

We can therefore conclude that this is modelled after some sort of puzzle. Manually solving it gives us a unique solution, and also the flag!

In fact, a experienced puzzle hunter might recognise what this puzzle is. It is in fact a [Nurikabe](https://en.wikipedia.org/wiki/Nurikabe_(puzzle)) puzzle!

Another way to notice this is from the `Whomp.png` distribution. The image,

![image](Whomp.png)

is that of the Super Mario 64 enemy of the same name. This creature is inspired from a Japanese folklore creature known as the [Nurikabe](https://en.wikipedia.org/wiki/Nurikabe), which is also the puzzle's namesake.

```cpp
  if ( v5 )
  {
    puts("UGRH. The Whomp grunts and steps aside. You get the flag:");
    v20[0] = 0LL;
    v20[1] = 0LL;
    v21 = 0;
    SHA1(s, 86LL, v20);
    sub_1462(v20, &byte_4060, 47LL);
    puts(&byte_4060);
  }
```
Regardless, sending the solution string results in it getting SHA1 hashed, then xored with a 47 length byte array in `sub_1462()` into the flag.

### whomp.cpp
For those who are wondering, here's the full source code I had for `Whomp`, with comments explaining each check in full:

```cpp
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <openssl/sha.h>
using namespace std;

char s[39] = { 67, 11, 33, 76, 99, 67, 99, 33, 99, 67, 81, 81, 9, 99, 24, 26, 99, 76, 76, 20, 11, 76, 99, 67, 9, 74, 99, 83, 37, 20, 24, 63, 99, 81, 99, 63, 67, 26, 81 };
unsigned char flag_enc[47] = {137, 175, 162, 220, 201, 43, 48, 44, 134, 165, 72, 164, 107, 12, 15, 27, 205, 252, 121, 186, 255, 169, 209, 247, 232, 23, 68, 31, 242, 148, 82, 189, 113, 33, 72, 71, 138, 214, 101, 252, 184, 199, 139, 173, 249, 84, 8};
const int ROWS = 10;
const int COLS = 10;
int ptr = 0;

void floodFill(char** grid, int x, int y, char newColor, char prevColor) {
    if (x < 0 || x >= ROWS || y < 0 || y >= COLS || grid[x][y] != prevColor || grid[x][y] == newColor) {
        return;
    }
    grid[x][y] = newColor;
    ptr++;
    floodFill(grid, x + 1, y, newColor, prevColor);
    floodFill(grid, x - 1, y, newColor, prevColor);
    floodFill(grid, x, y + 1, newColor, prevColor);
    floodFill(grid, x, y - 1, newColor, prevColor);
}

void ffill(char** grid, int x, int y, char newColor, char prevColor) {
    ptr = 0;
    if (grid[x][y] != prevColor) return;
    floodFill(grid, x, y, newColor, prevColor);
}

int scnt(int x) {
    int pptr = 0;
    for (int i = 0; i < strlen(s); i++) {
        if (s[i] == x) pptr++;
    }
    return pptr;
}

void strxor(unsigned char key[], unsigned char buf[], int buflen) {
    for (int i = 0; i < buflen; i++) buf[i] = key[i % 20] ^ buf[i];
}

int main() {
    bool check = true;
    char** grid = (char**)malloc(ROWS * sizeof(char*));
    for (int i = 0; i < ROWS; ++i) {
        grid[i] = (char*)malloc(COLS * sizeof(char));
    }

    char input[87];
    printf("UGRH!! The Whomp boldly announces his presence as the imposing wall stands between you and the flag.\nThe Whomp seems to only understand binary.\nWhat do you say to the Whomp?\n>> ");
    fgets(input, sizeof(input), stdin);

    if (strlen(input) > 86) {
        input[86] = '\0';
    }

    int bcnt = 0; // basic validation checks
    int wcnt = 0;
    for (int i = 0; i < 86; i++) {
        if (input[i] != '1' and input[i] != '0') check = false;
        if (input[i] == '1') bcnt++;
    }

    int index = 0;
    for (int i = 0; i < ROWS; ++i) {
        for (int j = 0; j < COLS; ++j) {
            if (!scnt(i * ROWS + j)) {
                grid[i][j] = input[index++];
            }
            else {
                grid[i][j] = '0';
            }
        }
    }

    /*
    printf("\nFilled 10x10 Grid:\n");
    for (int i = 0; i < ROWS; ++i) {
        for (int j = 0; j < COLS; ++j) {
            printf("%c ", grid[i][j]);
        }
        printf("\n");
    }
    */

    for (int i = 0; i < ROWS - 1; ++i) { // check 2 by 2 streams do not exist
        for (int j = 0; j < COLS - 1; ++j) {
            if (grid[i][j] == '1' && grid[i + 1][j] == '1' && grid[i][j + 1] == '1' && grid[i + 1][j + 1] == '1') check = false;
        }
    }

    for (int i = 0; i < ROWS; ++i) { // check island numbers are fulfilled
        for (int j = 0; j < COLS; ++j) {
            int tmp = scnt(i * ROWS + j);
            if (tmp) {
                ffill(grid, i, j, 'C', '0');
                wcnt += ptr;
                if (ptr != tmp) {
                    check = false;
                }
            }
        }
    }

    ffill(grid, 7, 3, 'D', '1'); // check stream is all continuous
    if (ptr != bcnt) check = false; // check all numberinos are different and distinct.
    if (bcnt + wcnt != ROWS*COLS) check = false; // final checks, making sure no area leftr behind

    if (check) {
        printf("UGRH. The Whomp grunts and steps aside. You get the flag:\n");
        unsigned char res[20] = { 0 };
        (void)SHA1((const unsigned char*) input, 86, res);
        strxor(res, flag_enc, 47);
        printf("%s\n", flag_enc);
    }
    else {
        printf("UGRH! The Whomp crushes you as you try to get the flag.\nBetter luck next time!\n");
    }


    for (int i = 0; i < 10; ++i) {
        free(grid[i]);
    }
    free(grid);

    return 0;
}
```

## Beep Boop
```
"I heard only robots are smort enough to solve this chall"  -somebody who dared me to make this chall, probably.

http://34.87.163.49:20003
```

So there's some lore behind this. Someone dared me to make a web challenge involving robots.txt, so I did! But it would be lame if it was just about robots.txt.

Accessing `/robots.txt` gives us the following:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Beep Boop I'm a Robot</title>

</head>
<body>
</head>
<body>
    <p>Beep Boop I'm a Robot</p>
    <p>KYBERL3AGUE{ar3_y0u_k1dd1ng_me_it5_robOTS-TXT_>:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC}<span style="font-size: 6px;">there's-a-scrollbar-btw</span></p>
    <br> </br><br> </br><br> </br><br> </br><br> </br><br> </br><br> </br><br> ... </br><br> </br><br> </br><br> </br><br> </br><br> </br>
    <p> You should check out <b>/app.py</b> while you're at it btw c: </p>
</body>
</html>
```

Which points us to the first URL that turns the sourceless challenge into a source challenge:

`app.py`
```py
from flask import Flask, render_template, request, make_response, redirect, Response
from cwt import CWT, base64_url_decode
from uuid import uuid4
import json

app = Flask(__name__)
flag = open("flag.txt", "r").read()
cwt = CWT()

view = lambda x:Response(x, mimetype='text/plain')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/app.py')
def app_py():
    return view(open(__file__, "r").read())

@app.route('/keys/public_key.pem')
def pub():
    return view(open('keys/public_key.pem', "r").read())

@app.route('/keys/private_key.pem')
def priv():
    return view("I'm legally not allowed to give you private_key.pem but here's this in exchange:\n\n" + open("keys/rsagen.py", "r").read())

@app.route('/cwt.py')
def cwt_py():
    return view(open("cwt.py", "r").read())

@app.route('/robots.txt')
def robot():
    return render_template('robots.html')


@app.route('/login', methods=['GET'])
def login_get():
    token = request.cookies.get('token').encode()
    if not token or token.count(b'.') != 2:
        return redirect('/')
    header, payload, signature = token.split(b'.')
    if not cwt.verify(header, payload, signature):
        return "Invalid token!"
    header_dict = json.loads(base64_url_decode(header))
    payload_dict = json.loads(base64_url_decode(payload))
    if 'uuid' not in payload_dict or 'username' not in payload_dict or 'alg' not in header_dict:
        return "Incomplete token!"
    uuid = payload_dict['uuid']
    if payload_dict['username'] == "iamarobot" and payload_dict['uuid'] == "beepboop":
        uuid = flag
    return render_template('login.html', uuid=uuid, username=payload_dict['username'])


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']

    if not username:
        return "Error, empty username!"
    if username == "iamarobot":
        return "wait...you aren't a bot! >:("

    uuid = str(uuid4())
    token = cwt.generate({"alg":"RSA","typ":"CWT"}, {'uuid': uuid, 'username': username}, algorithm='RSA').decode()
    resp = make_response(render_template('login.html', uuid=uuid, username=username))
    resp.set_cookie('token', token)
   
    return resp


if __name__ == '__main__':
    app.run()
```

We can see that it's a login system that uses some sort of web tokens as its backend. After registering, we are given a uuid and a web token in our cookies, then directed to `login.html`, a simple page that prints our uuid.

We can also make a GET request to login with our own web token cookie, and if the checks all pass, provided our web token contains `iamarobot` in its username and `beepboop` in its uuid value, we are directed to `login.html` but with the flag as the uuid instead.

We also see that we can't just submit `iamarobot` in the `POST` request to `/login`, so we must forge a valid token somehow.

Looking at `/cwt.py` for the source code behind the external token library, we get the following:

`cwt.py`
```py
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.strxor import strxor
import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256


def base64_url_encode(data):
    encoded = urlsafe_b64encode(data).rstrip(b'=')
    return encoded


def base64_url_decode(data):
    padding = b'=' * (4 - (len(data) % 4))
    decoded = urlsafe_b64decode(data + padding)
    return decoded


def xor(s1, s2):
    if len(s1) < len(s2):
        s2 = s2[:len(s1)]
    else:
        s1 = s1[:len(s2)]
    return strxor(s1, s2)


class CWT:

    pubkey = None
    privkey = None
    hshkey = None


    def __init__(self):
        global pubkey, privkey, hshkey
        pubkey = RSA.import_key(open('keys/public_key.pem','rb').read())
        privkey = RSA.import_key(open('keys/private_key.pem','rb').read())
        hshkey = open('keys/private_key.pem','rb').read()[:64]


    def generate(self, header, payload, algorithm):
        global pubkey, privkey, hshkey
        header = base64_url_encode(json.dumps(header).encode())
        payload = base64_url_encode(json.dumps(payload).encode())
        if algorithm == "RSA":
            m = bytes_to_long(header +  b'.' + payload)
            signature = long_to_bytes(pow(m,privkey.d,pubkey.n))
        elif algorithm == "SHA":
            key = xor(bytes(privkey.d % 2**32), hshkey)
            signature = sha256(key + header +  b'.' + payload).digest()
        else:
            return "Invalid algorithm!"
        return header + b'.' + payload + b'.' + base64_url_encode(signature)
    

    def verify(self, header, payload, signature):
        global pubkey, privkey, hshkey
        if not header or not payload or not signature:
            return False
        header_dict = json.loads(base64_url_decode(header))
        signature = base64_url_decode(signature)
        if 'alg' not in header_dict:
            return False
        algorithm = header_dict['alg']
        if algorithm not in ["RSA", "SHA"]:
            return False
        if algorithm == "RSA":
            m = bytes_to_long(header +  b'.' + payload)
            return pow(bytes_to_long(signature),pubkey.e, pubkey.n) == m
        else:
            key = xor(bytes(privkey.d % 2**32), hshkey)
            return signature == sha256(key + header +  b'.' + payload).digest()
```

We observe that it loads two PEM files, of which we can only access the public key.

```py
pubkey = RSA.import_key(open('keys/public_key.pem','rb').read())
privkey = RSA.import_key(open('keys/private_key.pem','rb').read())
hshkey = open('keys/private_key.pem','rb').read()[:64]
```

In addition, it reads the first 64 bytes as some `hshkey` value.

The rest of the code seems to heavily resemble the classic [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token) format. There is, in essence, a header dictionary, a payload dictionary, and a signature. Anyone can write their own headers and payloads, but provided the signature is implemented securely, only the server backend should be able to sign it.

Let's look at the two algorithms that the server allows for signing signatures:

```py
    def generate(self, header, payload, algorithm):
        global pubkey, privkey, hshkey
        header = base64_url_encode(json.dumps(header).encode())
        payload = base64_url_encode(json.dumps(payload).encode())
        if algorithm == "RSA":
            m = bytes_to_long(header +  b'.' + payload)
            signature = long_to_bytes(pow(m,privkey.d,pubkey.n))
        elif algorithm == "SHA":
            key = xor(bytes(privkey.d % 2**32), hshkey)
            signature = sha256(key + header +  b'.' + payload).digest()
        else:
            return "Invalid algorithm!"
        return header + b'.' + payload + b'.' + base64_url_encode(signature)
```

The `RSA` variant uses the private key value and performs standard RSA signatures. We can verify any signature using the public key as we see in a code snippet of `verify()`:

```py
        if algorithm == "RSA":
            m = bytes_to_long(header +  b'.' + payload)
            return pow(bytes_to_long(signature),pubkey.e, pubkey.n) == m
```

Without `privkey.d`, we cannot forge our own signatures. Onto the `SHA` variant, we find that it takes a `hshkey`, i.e. the first 64 bytes of the private key pem file, then xors it with `bytes(privkey.d % 2**32)`.

We also observe that the xor function takes 2 bytestrings and xors up till the string with the lower length:

```py
def xor(s1, s2):
    if len(s1) < len(s2):
        s2 = s2[:len(s1)]
    else:
        s1 = s1[:len(s2)]
    return strxor(s1, s2)
```

So it appears that RSA signatures require knowledge of `privkey.d`, and SHA signatures require knowledge of `privkey.d` (the value of it modulo $2^{32}$) and the private PEM file.

`app.py` has a route if we wish to obtain the private key, but instead,
```py
@app.route('/keys/private_key.pem')
def priv():
    return view("I'm legally not allowed to give you private_key.pem but here's this in exchange:\n\n" + open("keys/rsagen.py", "r").read())
```

We obtain the python file used to generate the keys.

`rsagen.py`
```py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private_key.pem', 'wb') as f:
    f.write(pem)

public_key = private_key.public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public_key.pem', 'wb') as f:
    f.write(pem)
```

So we don't have access to the private PEM file, but we can generate our own private and public key pem files.

We know for a fact that there's very little chance that generating a random `private_key.pem` matches the one used by the server, so anything involving knowledge of `privkey.d` is out of the question. But doesn't this mean both signature methods are impossible to forge?

Not really!

Examining the SHA signature,
```py
key = xor(bytes(privkey.d % 2**32), hshkey)
signature = sha256(key + header +  b'.' + payload).digest()
```

we notice that `bytes(privkey.d % 2**32)` is used. In Python, when `bytes()` is called on a string, say `"abc"`, we get `b"abc"`. But when `bytes()` is called on an integer,

```
>>> bytes(3)
b'\x00\x00\x00'
```

We only get NULL bytes of said integer's length! Thus really we have

```py
key = hshkey
signature = sha256(key + header +  b'.' + payload).digest()
```

So we just need to find the first 64 bytes of the private.pem file. As we generate them using the provided `rsagen.py`, we find that:

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYl6ZUAk7Ygma/
onEcxndGrhSJDxazhDnuop9slnGZ2iRwnj2g3zNgq3eLAYN0ppXwfl3PBMqLgDJm
```
A LOT of the private key files start with the same 64 bytes. This is not just because of the `-----BEGIN PRIVATE KEY-----` format but also the PEM encoding, which causes the pem files to only exhibit slight deviations.

```py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
d33, d62 = set(), set()

for _ in range(100):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    d33.add(chr(pem[33]).encode())
    d62.add(chr(pem[62]).encode())

d33 = {b'w', b'A', b'Q', b'g'}
d62 = {b'Q', b'U', b'Y', b'k', b'g', b'c'}
```
In fact, the only deviation comes in the 33rd and 62nd characters, which only have the following outcomes.

Thus, a simple brute for the hshkey is sufficient for us to spoof our signature and obtain the flag:

### solve.py
```py

import requests
import json
from base64 import urlsafe_b64encode
from hashlib import sha256

def base64_url_encode(data):
    encoded = urlsafe_b64encode(data).rstrip(b'=')
    return encoded

header = base64_url_encode(json.dumps({'alg':'SHA'}).encode())
payload = base64_url_encode(json.dumps({'username':'iamarobot', 'uuid':'beepboop'}).encode())

for k33 in d33:
    for k62 in d62:
        hshkey = b'-----BEGIN PRIVATE KEY-----\nMIIEv' + k33 + b'IBADANBgkqhkiG9w0BAQEFAASCBK' + k62 + b'w'
        signature = sha256(hshkey + header +  b'.' + payload).digest()
        token = header + b'.' + payload + b'.' + base64_url_encode(signature)
        r = requests.get("http://127.0.0.1:20003/login", cookies={'token':token.decode()})
        print(r.text, k33, k62)
```
