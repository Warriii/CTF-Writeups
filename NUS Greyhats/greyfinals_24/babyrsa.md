### BabyRSA - 18 Solves, 200 Pts
```
lol

Author: hadnot
```

`babyrsa.py`
```py
from Crypto.Util.number import bytes_to_long, getPrime, isPrime, long_to_bytes

with open("flag.txt", "r") as f:
    flag = f.read().encode()

assert(len(flag) == 48)

def gen_safe_prime():
    while True:
        p = getPrime(256)
        q = 2*p + 1
        if isPrime(q):
            return p,q

p, P = gen_safe_prime()
q, Q = gen_safe_prime()
r, R = gen_safe_prime()


N1 = p*Q
N2 = q*R
N3 = r*P

flag = flag[:16], flag[16:32], flag[32:]
m1, m2, m3 = map(bytes_to_long, flag)
e = 0x10001

c1 = pow(m1, e, N1)
c2 = pow(m2, e, N2)
c3 = pow(m3, e, N3)

print(f"N1 = {N1}")
print(f"N2 = {N2}")
print(f"N3 = {N3}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")
print(f"c3 = {c3}")
```

We're given a rather unique prime generation algorithm, with primes `p,q,r` such that them multiplied by 2 plus one is a prime also. Following which standard RSA is done as 3 parts of the flag is then encrypted using `Ns` generated from multiplying the 6 primes together.

Normally if we have `N = p*(2p+1)`, then recovering `p` would be rather trivial. But this time, they're all done separately!

Now there's a few ways one can approach this. The first is to manually derive a formula in terms of just one of the primes, `p` for instance, which would get a quadratic equation. Then one just needs to solve for `p`.

Personally I used sagemath's `.resultant()` functionality. The resultant is commonly used in elimination theory, the classical name for algorithmic approaches to eliminating some variables between polynomials of several variables, in order to solve systems of polynomial equations. I'd used it to eliminate common unknowns between functions so as to derive a new equation that holds true without said unknown. This allows me to derive a polynomial with just 1 unknown. We solve this to recover a prime, recover the remaining primes, and then perform regular RSA decryption.

`solve.sage`
```py
from Crypto.Util.number import long_to_bytes

N1 = 12495068391856999800077002030530346154633251410701993364552383316643702466683773454456456597802923936206937481367758944533287430192110874917786936470363369
N2 = 8077707147198053886290544832343186898331956960638623080378558119874814319984246411074010515131637149736377313917292767376808884023937736055240325038442951
N3 = 10898848501176222929758568549735934974173617359760346224710269537956982757903808181573409877312658404512178685311838325609151823971632352375145906550988157
c1 = 11727185096615670493479944410151790761335959794363922757994065463882149941932060937572492050251349085994568934453243128190891922383731914525051578359318783
c2 = 2327979828535262192716931468063741561142276160684415064469817644730647222015445750643448615540518244828488228477943010970450757391003276726177736335376022
c3 = 4544692061471147250554940137677403449389851357903927336833646427737782533445020327768883285489907725322030741572216172954958842207101301502851102081477126

F.<p,q,r> = PolynomialRing(ZZ, 3)
f1 = (p*(2*q+1)) - N1
f2 = (q*(2*r+1)) - N2
f3 = (r*(2*p+1)) - N3

pp = f3.resultant(f2, r).resultant(f1, q).univariate_polynomial().roots()[0][0]
qq = (N1//pp - 1) // 2
rr = (N2//qq - 1) // 2
e = 0x10001

d1 = pow(e, -1, (pp-1)*(2*qq))
d2 = pow(e, -1, (qq-1)*(2*rr))
d3 = pow(e, -1, (rr-1)*(2*pp))
flag = long_to_bytes(pow(c1, d1, N1)) + long_to_bytes(pow(c2, d2, N2)) + long_to_bytes(pow(c3, d3, N3))
print(flag)
# b'grey{3_equations_3_unknowns_just_use_groebnerXD}'
```