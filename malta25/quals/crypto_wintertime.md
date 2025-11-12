![image](Images/wintertime.png)

The hardest challenge of the qualifiers set! And it's written by me! :D

`chall` files are not to be provided in this repository due to the sheer number of files to comb through. You can find it in the [maltactf quals github repo](https://github.com/ctf-mt/maltactf-2025-quals-dev/tree/master/crypto/wintertime/attachments) instead!

![alt text](Images/wintertime_files.png)

This challenge is based on [POKÉ: A Compact and Efficient PKE from Higher-dimensional Isogenies](https://eprint.iacr.org/2024/624). This is a relatively new isogeny based cryptosystem whose details came out just last year!

In the challenge, we have a server oracle. We play as a user, Alice, who is able to have multiple key exchanges with Bob. The key exchange allows for us to have a session key with Bob that we can use to encrypt/decrypt messages. Bob has a separate session key which he uses to communicate to a third user, Charlie, which he sends the flag to. We have access to all 3 users' public keys, and have to recover the session key Bob uses with Charlie to decrypt the flag.

There is a lot to unpack with regards to the vuln. The general idea is that the private key used in Bob's end of the key exchange, $r_3$, is static and not randomly generated with every key exchange query. This allows us to implement an adaptive attack to slowly recover $r_3$ through multiple key exchange attempts. We exploit small subgroups used in the key derivation so as to recover $r_3 \bmod 3$, then $r_3 \bmod 9$, so on and so forth.

This attack is not a novelty. It's based off of a known attack on static [SIDH](https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange) keys. You can find the paper describing it in [On the Security of Supersingular Isogeny Cryptosystems](https://eprint.iacr.org/2016/859)!

Once we recover $r_3$, we can reconstruct the isogeny $\psi$ as wel as its pushforward $\psi'$ that Bob uses. We then perform a change of basis operation to solve for Bob's secret matrix $D_{5c}$, letting us recover the session key used 

This is the simplistic, tldr version of the writeup. If you want to know the details, do check out this paper I'd published rather recently on it. [Adaptive Attack on Static POKÉ Keys](https://eprint.iacr.org/2025/1541)

`solve.py`
```py
from montgomery_isogenies.kummer_line import KummerLine, KummerPoint
from montgomery_isogenies.kummer_isogeny import KummerLineIsogeny

from theta_structures.couple_point import CouplePoint
from theta_isogenies.product_isogeny import EllipticProductIsogeny

from utilities.discrete_log import BiDLP
from utilities.supersingular import torsion_basis, torsion_basis_with_pairing

from sage.all import EllipticCurve, GF, inverse_mod, proof, ZZ

import os
os.environ["TERM"] = "xterm-256color"
os.environ["TERMINFO"] = "/usr/share/terminfo"

import json
from Crypto.Cipher import AES
from hashlib import sha256
from pwn import remote
from tqdm import trange
from time import time

proof.all(False)    

def eval_dimtwo_isog(Phi, q, P, Q, ord, RS=None):

    R1 = P
    R2 = Phi.domain()[1](0)
    phiP = Phi(CouplePoint(R1, R2))
    imP = phiP[0]

    R1 = Q
    R2 = Phi.domain()[1](0)
    phiQ = Phi(CouplePoint(R1, R2))
    imQ = phiQ[0]

    R1 = P-Q
    R2 = Phi.domain()[1](0)
    phiPQ = Phi(CouplePoint(R1, R2))
    imPQ = phiPQ[0]

    if (imP - imQ)[0] != imPQ[0]:
        imQ = -imQ


    if RS == None:
        R, S, WP = torsion_basis_with_pairing(Phi.domain()[1], ord)
    else:
        R, S = RS
        WP = R.weil_pairing(S, ord)

    R1 = Phi.domain()[0](0)
    R2 = R
    phiR = Phi(CouplePoint(R1, R2))
    imR = phiR[0]

    R1 = Phi.domain()[0](0)
    R2 = S
    phiS = Phi(CouplePoint(R1, R2))
    imS = phiS[0]

    R1 = Phi.domain()[0](0)
    R2 = R-S
    phiRS = Phi(CouplePoint(R1, R2))
    imRS = phiRS[0]

    if (imR - imS)[0] != imRS[0]:
        imS = -imS

    wp = WP**q
    x, y = BiDLP(imP, imR, imS, ord, ePQ=wp)
    w, z = BiDLP(imQ, imR, imS, ord, ePQ=wp)


    imP = x*R + y*S
    imQ = w*R + z*S

    imP *= q
    imQ *= q

    return imP, imQ

a, b, c, f = 127, 162, 18, 9
A, B, C = 2**a, 3**b, 5**c
p = 4 * f * A * B * C - 1
x = C

FF = GF(p)['xx']; (xx,) = FF._first_ngens(1)
F = GF(p**2 , modulus=xx**2 +1 , names=('i',)); (i,) = F._first_ngens(1)
E0 = EllipticCurve(F, [1, 0])
E0.set_order((p+1)**2)
PA, QA = torsion_basis(E0, 4*A)
PB, QB = torsion_basis(E0, B)
X0, Y0 = torsion_basis(E0, C)

PQA = PA - QA
PQB = PB - QB
XY0 = X0 - Y0

_E0 = KummerLine(E0)
_PB = _E0(PB[0])
_QB = _E0(QB[0])
_PQB = _E0(PQB[0])
xPA = _E0(PA[0])
xQA = _E0(QA[0])
xPQA = _E0(PQA[0])
xX_0 = _E0(X0[0])
xY_0 = _E0(Y0[0])
xXY_0 = _E0(XY0[0])

to_point = lambda x:eval(x.replace(" : ", ", "))

def decrypt(skA, ct): # POKE decrypt function
    deg, alpha, beta, delta = skA
    EB = EllipticCurve(F, eval(ct["EB"]))
    EAB = EllipticCurve(F, eval(ct["EAB"]))
    P2_B = EB(to_point(ct["PB"]))
    Q2_B = EB(to_point(ct["QB"]))
    X_B = EB(to_point(ct["XB"]))
    Y_B = EB(to_point(ct["YB"]))
    P2_AB = EAB(to_point(ct["PAB"]))
    Q2_AB = EAB(to_point(ct["QAB"]))
    ct_bytes = bytes.fromhex(ct["ct"])

    P2_AB = inverse_mod(alpha, A) * P2_AB
    Q2_AB =  inverse_mod(beta, A) * Q2_AB
    UAB, VAB, wp = torsion_basis_with_pairing(EAB, x)
    
    P, Q = CouplePoint(-deg * P2_B, P2_AB), CouplePoint(-deg * Q2_B, Q2_AB)
    kernel = (P, Q)
    Phi = EllipticProductIsogeny(kernel, a)

    X_AB, Y_AB = eval_dimtwo_isog(Phi, A-deg, X_B, Y_B, x, RS=(UAB, VAB))
    X_AB *= delta
    Y_AB *= delta

    X_bytes = X_AB[0].to_bytes()
    Y_bytes = Y_AB[0].to_bytes() 
    key = sha256(X_bytes + Y_bytes).digest()[:16]
    return AES.new(key, AES.MODE_ECB).decrypt(ct_bytes)

def get_v(x):
    if "*i + " in str(x):
        return [int(k) for k in str(x).split("*i + ")]
    elif "i" in str(x):
        return [int(str(x)[:-1]), 0]
    return [0, int(str(x))]

def kummer_isogeny(phi, xP, xQ, xPQ):
    ximP, ximQ, ximPQ = phi(xP), phi(xQ), phi(xPQ)
    PP, QQ = ximP.curve_point(), ximQ.curve_point()
    if (PP - QQ)[0] != ximPQ.x():
        QQ = -QQ
    return PP, QQ

def r_getCodes(r):
    r.recvuntil(b'> ')
    r.sendline(b'1')
    return json.loads(r.recvline().rstrip().decode())

def r_setCodes(r, args):
    assert len(args) == 5
    r.recvuntil(b'> ')
    r.sendline(b'2')
    for i in range(5):
        r.recvuntil(b'> ')
        r.sendline(str(args[i]).encode())
    return r.recvline().rstrip().decode()

def r_getenc(r):
    r.recvuntil(b'> ')
    r.sendline(b'3')
    return json.loads(r.recvline().rstrip().decode())

def r_getCharlie(r):
    r.recvuntil(b'> ')
    r.sendline(b'4')
    return json.loads(r.recvline().rstrip().decode())

START = time()
REMOTE = remote('127.0.0.1', 20001) #, level='debug')
you_keys = r_getCodes(REMOTE)
you_pub, you_priv = you_keys["pub"], you_keys["priv"]
you_sk = [ZZ(i) for i in (you_priv["q"], you_priv["a"], you_priv["b"], you_priv["d"])]

EA = EllipticCurve(F, eval(you_pub["EA"]))
AEA = KummerLine(EA)
xP3 = KummerPoint(AEA, to_point(you_pub["P3"]))
xQ3 = KummerPoint(AEA, to_point(you_pub["Q3"]))
xPQ3 = KummerPoint(AEA, to_point(you_pub["PQ3"]))
AP3, AQ3, APQ3 = xP3.curve_point(), xQ3.curve_point(), xPQ3.curve_point()
if (AP3 - AQ3)[0] != APQ3.x():
    AQ3 = -AQ3

rr = 0
for ii in trange(b):
    success = False
    for r in range(3):
        AP3_ = AP3 - rr * 3**(b-1-ii) * AQ3 - r * 3**(b-1) * AQ3
        AQ3_ = AQ3 + 3**(b-1-ii) * AQ3
        xP3_, xQ3_, xPQ3_ = AEA(AP3_[0]), AEA(AQ3_[0]), AEA((AP3_-AQ3_)[0])
        v0, v1 = get_v(xP3_._X)
        v2, v3 = get_v(xP3_._Z)
        r_setCodes(REMOTE, [3, v0, v1, v2, v3])
        v0, v1 = get_v(xQ3_._X)
        v2, v3 = get_v(xQ3_._Z)
        r_setCodes(REMOTE, [4, v0, v1, v2, v3])
        v0, v1 = get_v(xPQ3_._X)
        v2, v3 = get_v(xPQ3_._Z)
        r_setCodes(REMOTE, [5, v0, v1, v2, v3])
        ctB = r_getenc(REMOTE)
        try:
            pt = decrypt(you_sk, ctB)
            success = True
            rr += 3**ii * r
            break
        except ValueError as err:
            continue
    assert success

B = ZZ(B)
_KB = _QB.ladder_3_pt(_PB, _PQB, rr)
psi = KummerLineIsogeny(_E0, _KB, B)

c_pub = r_getCharlie(REMOTE)
EC = EllipticCurve(F, eval(c_pub["EA"]))
AEC = KummerLine(EC)
CxP3 = KummerPoint(AEC, to_point(c_pub["P3"]))
CxQ3 = KummerPoint(AEC, to_point(c_pub["Q3"]))
CxPQ3 = KummerPoint(AEC, to_point(c_pub["PQ3"]))
CX_A = EC(to_point(c_pub["XA"]))
CY_A = EC(to_point(c_pub["YA"]))

REMOTE.recvuntil(b'> ')
REMOTE.sendline(b'5')
print(REMOTE.recvline().rstrip())
ct = json.loads(REMOTE.recvline().rstrip().decode())
EB = EllipticCurve(F, eval(ct["EB"]))
C_X_B = EB(to_point(ct["XB"]))
C_Y_B = EB(to_point(ct["YB"]))
C_ct = bytes.fromhex(ct["ct"])

xP2_B, xQ2_B = psi(xPA), psi(xQA)
X_B, Y_B = kummer_isogeny(psi, xX_0, xY_0, xXY_0)
dd1, dd2 = BiDLP(C_X_B, X_B, Y_B, 5**c)
dd3, dd4 = BiDLP(C_Y_B, X_B, Y_B, 5**c)

CxK = CxQ3.ladder_3_pt(CxP3, CxPQ3, rr)
phiB_ = KummerLineIsogeny(AEC, CxK, B)
CxX_A, CxY_A, CxXY_A = AEC(CX_A[0]), AEC(CY_A[0]), AEC((CX_A-CY_A)[0])
CX_AB, CY_AB = kummer_isogeny(phiB_, CxX_A, CxY_A, CxXY_A)
CX_AB, CY_AB = dd1*CX_AB + dd2*CY_AB, dd3*CX_AB + dd4*CY_AB

key = sha256(CX_AB[0].to_bytes() + CY_AB[0].to_bytes()).digest()[:16]
res = AES.new(key, AES.MODE_ECB).decrypt(C_ct)
print(res)
print(f"Time taken: {time() - START} seconds")
"""
[+] Opening connection to 127.0.0.1 on port 20001: Done
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 162/162 [02:06<00:00,  1.28it/s]
b'Bob: My final message,'
b'maltactf{s0_m4ny_l1n35_f0r_a-s1mpl3_CCAvuln...wh0se_p4p3r_came-out_alm0st_a_d3c4d3_ag0!}\x08\x08\x08\x08\x08\x08\x08\x08'
Time taken: 130.0233461856842 seconds
[*] Closed connection to 127.0.0.1 port 20001
"""
```