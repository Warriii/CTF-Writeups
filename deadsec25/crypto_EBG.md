## EBG (16 Solves, 437 Pts)
```
SBG loves LCG, he also loves ECC. Thus he combined both of them and had EBG.

Flag format: deadsec{}

Updates:

G = (211046629312383495603203047061896203904, 184028273928357402268058957910316279756)
q.bit_length() = 168, a < p and b < p
Yet another update: The handout given in the previous version was wrong apparently. It has been updated in the link now.
```
`ebg.sage`
```py
#!/usr/bin/env sage

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from random import randint
from secret import a, b, p, q, flag

Fp = GF(p)
Fq = GF(q)
E = EllipticCurve(Fp, [a, b])

class LCG:
    def __init__(self, seed, a, b):
        self.a, self.b = Fq(a), Fq(b)
        self.state = Fq(seed)

    def next_state(self):
        nxt = self.state * self.a + self.b
        self.state = nxt
        return int(nxt)

seed = randint(1, q)
lcg = LCG(seed, a, b)

collect, points = [], []

itr = 0
while len(collect) != 50:
    itr += 1
    y = lcg.next_state()
    P.<x> = PolynomialRing(Fp)
    try:
        x_ = (x^3+a*x+b-y^2).roots()[0][0]
        assert (x_, y) in E
        collect.append((itr, x_, Fp(y^2)))
        points.append((x_, Fp(y)))
    except:
        pass

qsz = q.bit_length()
#qsz = 168
qhi = q >> (qsz//2)
qlo = q & ((1 << (qsz//2)) - 1)

assert qhi.bit_length() == qsz//2 == 84
assert qlo.bit_length() == qsz//2

G = E.gens()[0]
#G = (211046629312383495603203047061896203904, 184028273928357402268058957910316279756)
hints = [
    sum([i[1]*G for i in points]).xy(), # we ignore this.
    ((qhi^2 + (qlo^3)*69) * G).xy(),
    (((qhi^3)*420 + qlo^2) * G).xy()
]

for _ in range(10^18):
    lcg.next_state()

key = sha256(str(lcg.next_state()).encode()).digest()
ct = AES.new(key, AES.MODE_ECB).encrypt(pad(flag.encode(), 16)).hex()

with open('output_69.txt', 'w') as f:
    f.write(f'{collect=}\n')
    f.write(f'{hints=}\n')
    f.write(f'{ct=}')
```

We have a mix of an LCG (Linear Congruential Generator), mixed in with some ECC (Elliptic Curve Cryptography). We see that the flag is encrypted using AES-ECB with a key thats a hash of one of the states in the LCG. Thus, it is clear that we need to recover the LCG parameters, obtain the LCG initial state and then use it to derive the AES key.

The LCG itself uses unknowns $a, b, q$. Its outputs are squared over $GF(p)$ for some unknown prime $p$, and then it tests whether or not such a point exists in the elliptic curve $y^2 = x^3 + ax + b$, using the same $a, b$ unknowns from before. The point data is given to us in the `collect` array, which also tells us how many times the LCG was run to get to the points.

While we may not know any of the parameters defining the elliptic curve, it is a known fact that given enough points on some curve, one can recover the modulus $p$, and then the coefficients $a, b$.

Given four distinct points on the curve, we can do:

$y_i^2 - x_i^3 = a*x_i + b \quad(\bmod p)$

$(y_i^2 - x_i^3) - (y_j^2 - x_j^3) = a*(x_i - x_j) \quad(\bmod p)$

$((y_i^2 - x_i^3) - (y_j^2 - x_j^3)) * (x_k - x_l) = a * (x_i - x_j) * (x_k - x_l) = ((y_k^2 - x_k^3) - (y_l^2 - x_l^3)) * (x_i - x_j) \quad (\bmod p)$

If we subtract the leftmost and rightmost sides of the equality over the integers, we should get something that is $0 \bmod p$, i.e. a multiple of $p$. Thus, from four points we can recover a multiple of $p$. We sets of 4 points to recover them, then calculate their greatest common divisor to recover $p$.

Once $p$ is recovered, recovering $a, b$ is trivial and left as an exercise to the reader.

The description tells us $a, b$ in the LCG is smaller than $p$, so we have effectively recovered the lcg parameters $a, b$. What about $q$?

We notice $q$ is split into its lower and higher bits $qlo$, $qhi$, and then we are provided, from $hints$, 
```py
assert qhi.bit_length() == qsz//2 == 84
assert qlo.bit_length() == qsz//2

G = E.gens()[0]
#G = (211046629312383495603203047061896203904, 184028273928357402268058957910316279756)
hints = [
    sum([i[1]*G for i in points]).xy(),
    ((qhi^2 + (qlo^3)*69) * G).xy(),
    (((qhi^3)*420 + qlo^2) * G).xy()
]
```

$(qhi^2 + qlo^3 * 69) * G, (qhi^3 * 420 + qlo^2) * G$ where $G$ is a given point on the Elliptic Curve that we can now define.

We can try to solve for the exact values of $qhi^2 + qlo^3 * 69$ and $qhi^3 * 420 + qlo^2$ modulo the curve order. We derive the curve order to be $23 * 16883 * 43093 * 63247 * 12779779 * 14406383 * 1447085987$, a product of various primes. Due to the small bit size of the primes, given $k*G$ and $G$, we can easily recover $k$ using discrete log algorithms such as a mix of Pohlig-Hellman and Baby Step Giant Step. We employ these to recover our two equations involving $qlo, qhi$ modulo the order.

Solving for $qlo, qhi$ may seem tough, but we can just solve for their values modulo each of the primes, and then use the chinese remainder theorem to combine the remainders. As $qlo, qhi$ are 84-bits, we can use the values modulo primes $16883, 43093, 63247, 12779779, 14406383$ to obtain $qlo, qhi$. Solving the system over each prime modulus can be done by initialising the equations as two bivariate polynomials, then taking the resultant of one over the other, and finally solving for their roots over $GF(prime)$. This gave me two possible $q$ values, $201670286310674408750557303575927151106950475452573$ and $258710185051731443595891924523393088943897226489076$.

Okay, so we now have recovered all secret values $a, b, p, q$. $a, b, q$ gives us the full LCG parameters, but now we have to recover the initial seed used in the LCG.

Looking at `collect`, we see that the LCG state is taken, squared in $GF(p)$ (essentially squared modulo p), and then that value is given in `collect[i][-1]`. 

Because $p \equiv 5 \bmod 8$, number theory gives us a way to derive all $y$ values given $y^2 \bmod p$. Note that for every valid solution $y$, $-y$ is also a solution, thus for every point in `collect` we have two possible values on what the LCG state could be. But even if we recover the right $y$ values, this does not give us the full LCG state! As $p$ is 128 bits, $q$ 168 bits, every correct $y$ only gives us $\text{LCG.state} \bmod p$.

We thus have $X_i = Z_i * p + Y_i$, where $X_i$ is the state of the LCG, $Z_i$ is some $168-128=40$ bit unknown and $Y_i$ is the known $y$ values.

From $X_{i+1} \equiv a * X_i + b \quad(\bmod q)$, $X_i = Z_i * p + Y_i$, we can show that

$(Z_i - Z_{i-1}) * p - a' * p (Z_{i+1} - Z_i) \equiv a' * (Y_{i+1} - Y_i) - (Y_i - Y_{i-1}) \quad (\bmod q)$.

where $a'$ is the multiplicative inverse of $a$ modulo $q$.

We may thus write the equation,

$(Z_i - Z_{i-1}) * p + (Z_{i+1} - Z_i) * (-a' * p) + (1) * C + (k) * q = 0$ for derivable constant $C$. This linear equation has our unknowns all within 40-bits (bar $k$, which we don't have to consider). Since the unknowns are very very small compared to $q$, we can use LLL to recover $Z_i - Z_{i-1}$ and $Z_{i+1} - Z_i$, namely via the lattice

```py
        M = Matrix([[p    ,1,0,0],\
                    [ainvp,0,1,0],\
                    [C    ,0,0,1],\
                    [q    ,0,0,0]])
```
In which we scale the first column by $2^{80}$ and the last by $2^{40}$ so that we may obtain the desired reduced basis vector $(0, Z_i - Z_{i-1}, Z_{i+1} - Z_i,-2^{40})$.

From $Z_i - Z_{i-1}$, we derive 

$Z_{i-1} = \frac{(Z_i - Z_{i-1}) * p + Y_i - a * Y_{i-1} - b}{a*p-p} \bmod q$, allowing us to recover $X_i$.

Looking over `collect`, we notice the first 3 points are consecutives, thus we apply the above to recover the full LCG state for the first point in `collect`. We reverse the LCG operation to obtain the initial seed.

Now that we have fully cracked the LCG, we only need to run the LCG operation $10^18 + 76$ times to obtain the state used in deriving the AES key. This would of course take too long to compute naively, so we will have to find a quicker method.

One thing to note about LCGs is that given $x$, the next states are:
- $x_1 = ax + b$
- $x_2 = a^2x + ab + b$
- $x_3 = a^3x + a^2b + ab + b$
- ...
- $x_n = a^n x + (a^{n-1} + a^{n-2} + ... + a^2 + a + 1) *b$

We apply the general form, using the formula for sum of a geometric series to recover the LCG state after $10^18 + 76$ operations. We now plug the value in to recover our AES key, and decrypt the encrypted flag!

`solve.py`
```py
collect=[(1, 129878933909759106346680577632702938145, 64803144266873896929676879739596453119), (2, 47220119480700323979436440438758568517, 3893349004730020878867885140196143162), (3, 135697371446505401996219663500480702535, 189464444217229459768207485455773596223), (5, 186182129928944137532744753332646781304, 47505021787622187627054996066834279986), (7, 137954541206367141157174681214137207747, 112455404714804866219968592681230422581), (9, 175529667588843919176395264612892894471, 218843045729950688472274397830483106785), (11, 128862675358503122400510283922445116890, 138035279566900850637481257540805975414), (12, 97805691366916592363261988507134163988, 177720227234190472988958454612517881331), (13, 37320607457069782511660220198288107093, 255228446758895847755153926039894325307), (14, 100970458868941221421819357068618407949, 91676140984835531582333563847664881098), (15, 82201463401316898075841094019745395963, 260266487802082630684592031519201292651), (17, 5043114699373728171906139671315211181, 248425135022969603482075220432126198400), (18, 119640544102070570692595557127168058306, 268111579624200820306713336942009180324), (20, 110463588191793193141778331277649841048, 4797532526832775982058880463729523264), (22, 278760755999967948519718565533805994706, 136114112271686814800164621343407719288), (25, 110672302544743724380319906762024264356, 68680445916196630263730189447972347932), (26, 240750825991734313849435188671112102063, 140607262286812515787062677112161357228), (27, 212077470771446192506159056893734649290, 139208919729552913218784867774523882872), (28, 137637831635933080402772142835363827980, 47952484402249020094794225674618712649), (29, 192994530647669979393287183382819077102, 167677548999714807450176064433600746494), (31, 14853647048237317965187228947005266698, 102841562937362181108723194061026812490), (34, 240107202043865516942839134775325798950, 2686453816150521537647060532916993425), (36, 73208029507938820821678102306884024515, 90830604924044189991821688941618008840), (40, 25688624474081509405065828826894970251, 263114103038651382917528468474421508970), (41, 78444213858637888025402155644962081478, 1227650586741174850554304777128981999), (43, 272942766489216606077566698464127091018, 137920053698013650330067140095258036186), (44, 65798204149688203259735816406425062061, 117621237377924339748816089574759379471), (45, 131164003547852147184888525175195630124, 14904081683490860466570512910215589498), (46, 198466350447032123061643384415553595098, 78673541778689512186828743280254957513), (47, 197456491312964552004328416921871060830, 230552334439900737955532832928073720340), (51, 241080610190893259502582771341275897638, 219241528921916095074065425829699162686), (52, 148459555599428230670439700969600524001, 37542155356992331599174012814840216579), (53, 88059495731975372270014306339160333953, 108930682089148605379197113672692244026), (54, 115218259744290243775271950656221479749, 24723167154472613578408645343075852359), (55, 207399571896461152245542849222195688602, 21366453255883339351183514872583156635), (56, 162307501083695252772393446813067625372, 191168518546056204278865539774903892632), (58, 100929302163253206689572191975387995056, 105655790195719548802588224439073087010), (60, 12467572025112492680780827851502701102, 54871130437582472120151895946144021439), (61, 205044598922926919923814282423301960892, 185500343153585563548380780384458785364), (62, 101024911549455856285493310072738139255, 76426169921217098398822065726722097433), (63, 231246082087521230014357912014877077244, 199878288912218183844553469641314538467), (65, 267247319359974237615551546666284905313, 167770265994317786428930391203034793125), (66, 271656252329029052888122578423472817324, 162845261167206139764057460246628847647), (67, 11194166780031032504314879126098171978, 100571427681629308118238960034711766909), (69, 99610796406662719216184922009261055141, 139125655131793785350771137873823884055), (70, 268494533197282920070461981868984975932, 158245833042764716130784905936126410852), (71, 172741136840482342263614648174626917928, 112917916923656776758887751909500383428), (72, 154815184807577433299929253616883247343, 101386650699861829992568531051280621901), (74, 210025894946768524275430773071874322579, 235998024821648094726633123862575190685), (75, 134368050189744696586177857951066985541, 178126351653628059845405725796083335991)]
hints=[(5792995813021327870769979628676579982, 143804545079278507495499534347219572515), (243532848166469089179921880480016489388, 63410286149522930076665255263173251947), (241284753827628767067447517837810323910, 208806014494840714718680309755272416222)]
ct='0052c609180b701244836c4e269748ca72c3e89e7897a8a10a11c047ac09adb76f024fa410f8869fc8381439e59c0fabd97b99a536bba33bfce7542e47b53f1d55fa2f55a8333beda85f51e5c71e1667cd22a0bbd3219895f28cebef42c622d2'

def sqrt(x):
    global p
    assert p % 8 == 5
    t = pow(x, (p+3)//8, p)
    if (t**2 % p != x % p):
        t *= pow(2, (p-1)//4, p)
        t %= p
    assert t**2 % p == x
    return (t, -t % p)

from math import gcd, lcm
Ts = []
for i in range(0, len(collect[:-2]), 4):
    x0, y0_2 = collect[i][1:]
    x1, y1_2 = collect[i+1][1:]
    x2, y2_2 = collect[i+2][1:]
    x3, y3_2 = collect[i+3][1:]
    r0, r1, r2, r3 = y0_2 - x0**3, y1_2 - x1**3, y2_2 - x2**3, y3_2 - x3**3
    T1 = (r0 - r1) * (x2 - x3)
    T2 = (r2 - r3) * (x0 - x1)
    Ts.append(T1-T2)
p = gcd(*Ts) # 5 mod 8
x0, y0_2 = collect[0][1:]
x1, y1_2 = collect[1][1:]
r0, r1 = y0_2 - x0**3, y1_2 - x1**3
a = (r0 - r1) * pow(x0-x1, -1, p) % p
b = (r0 - a * x0) % p

print(f'{p = }')
print(f'{a = }')
print(f'{b = }')

from sage.all import EllipticCurve, GF, PolynomialRing, crt, Matrix
E = EllipticCurve(GF(p), [a,b])
G = E(211046629312383495603203047061896203904, 184028273928357402268058957910316279756)
H1, H2 = [E(*i) for i in hints[1:]] # hint[0]? whats that?
r1, r2 = H1.log(G), H2.log(G)

GN = G.order()
primes = [i[0] for i in list(GN.factor())]
# [23, 16883, 43093, 63247, 12779779, 14406383, 1447085987]
# skip 23 cuz 69 is present which is a multiple of 23
# skip 1447085987 cuz resultant fails on sage (too big)

xy_mod = lcm(*primes[1:-1])
y_rems = []
for prime in primes[1:-1]:
    FF = PolynomialRing(GF(prime), names=('x, y')); x,y = FF.gens()
    eq0 = y**2 + x**3 * 69 - r1
    eq1 = y**3 * 420 + x**2 - r2
    ys = eq0.resultant(eq1, x).univariate_polynomial().roots(multiplicities=False)
    y_rems.append([int(i) for i in ys])

from itertools import product
qs = []
for y_rem in product(*y_rems):
    qhi = crt(list(y_rem), primes[1:-1])
    qlo_3 = (r1 - qhi**2) * pow(69, -1, xy_mod) % xy_mod
    qlo_2 = (r2 - qhi**3 * 420) % xy_mod
    qlo = qlo_3 * pow(qlo_2, -1, xy_mod) % xy_mod
    qs.append((qhi << 84) + qlo)
print(qs)

"""
a (Z_i1 * p + Y_i1) + b = Zi*p + Yi
a (Z_i * p + Y_i) + b = Z_i+1 * p + Y_i+1
a ((Z_i - Z_i-1) p + (Y_i - Y_i-1)) == (Z_i+1 - Zi) * p + (Y_i+1 - Y_i)
(Z_i - Z_i-1) p - ainv p (Z_i+1 - Zi) == ainv (Y_i+1 - Y_i) - (Y_i - Y_i-1)
"""
# print([i[0] for i in collect[:20]])
# [1, 2, 3, 5, 7, 9, 11, 12, 13, 14, 15, 17, 18, 20, 22, 25, 26, 27, 28, 29]
# decided to work on [1, 2, 3] as consecutive values

lcg_ys = [sqrt(i[-1]) for i in collect]
sols = []
for q in qs[:1]: # ainv doesnt exist at the other q
    ainv = pow(a, -1, q)
    pp = (-ainv * p) % q
    for y0, y1, y2 in product(*lcg_ys[:3]):
        # optimisation reveals we only need one equation, actually.
        r = (ainv * (y2 - y1) - (y1 - y0)) % q
        M = Matrix([[p ,1,0,0],\
                    [pp,0,1,0],\
                    [r ,0,0,1],\
                    [q ,0,0,0]]) # so smol :3
        M[:,-1] *= 2**40
        for i in range(1):
            M[:,i] *= 2**80
        M = M.LLL()
        for nrow in M:
            if all(i == 0 for i in nrow[:1]) and abs(nrow[-1]) == 2**40:
                if nrow[-1] == 2**40:
                    nrow = [-i for i in nrow]
                sols.append((nrow[1], y0, y1))
print(f'{q = }')

for Z1_minus_Z0, Y0, Y1 in sols:
    Z_0 = (Z1_minus_Z0 * p + Y1 - a * Y0 - b) * pow(a*p-p, -1, q) % q
    if Z_0.bit_length() <= 40:
        X_0 = (Z_0 * p + Y0) % q
        break
# go back one step to recover seed
X_0 = ((X_0 - b) * ainv) % q
state = X_0
print(f'{state = }')

# fast forward for flag
state = (pow(a, 10**18+collect[-1][0]+1, q) * state + (1 - pow(a, 10**18+collect[-1][0]+1, q))*pow(1-a,-1,q)*b) % q

from Crypto.Cipher import AES
from hashlib import sha256
key = sha256(str(state).encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(ct))
print(flag)
"""
p = 281966007153199959768827186794698649037
a = 210201763039972449186286141207774547530
b = 227313635393666788814653401272488978271
[201670286310674408750557303575927151106950475452573, 258710185051731443595891924523393088943897226489076]
q = 201670286310674408750557303575927151106950475452573
state = 90037349026664929242753260454030385468062012870533
b'deadsec{y0u_p40b4bly_7h1nk_7h15_w45_1n5p1r3d_f40m_cH1m3r4_w311...y0u_a43_n07_wr0n6_3n71431Y}\x04\x04\x04\x04'
"""
```