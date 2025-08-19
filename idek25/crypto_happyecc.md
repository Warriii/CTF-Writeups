![alt text](Images/image-3.png)

`chall.py`
```py
from sage.all import *
from Crypto.Util.number import *

# Edited a bit from https://github.com/aszepieniec/hyperelliptic/blob/master/hyperelliptic.sage
class HyperellipticCurveElement:
    def __init__( self, curve, U, V ):
        self.curve = curve
        self.U = U
        self.V = V

    @staticmethod
    def Cantor( curve, U1, V1, U2, V2 ):
        # 1.
        g, a, b = xgcd(U1, U2)   # a*U1 + b*U2 == g
        d, c, h3 = xgcd(g, V1+V2) # c*g + h3*(V1+V2) = d
        h2 = c*b
        h1 = c*a
        # h1 * U1 + h2 * U2 + h3 * (V1+V2) = d = gcd(U1, U2, V1-V2)

        # 2.
        V0 = (U1 * V2 * h1 + U2 * V1 * h2 + (V1*V2 + curve.f) * h3).quo_rem(d)[0]
        R = U1.parent()
        V0 = R(V0)

        # 3.
        U = (U1 * U2).quo_rem(d**2)[0]
        U = R(U)
        V = V0 % U

        while U.degree() > curve.genus:
            # 4.
            U_ = (curve.f - V**2).quo_rem(U)[0]
            U_ = R(U_)
            V_ = (-V).quo_rem(U_)[1]

            # 5.
            U, V = U_.monic(), V_
        # (6.)

        # 7.
        return U, V

    def parent( self ):
        return self.curve

    def __add__( self, other ):
        U, V = HyperellipticCurveElement.Cantor(self.curve, self.U, self.V, other.U, other.V)
        return HyperellipticCurveElement(self.curve, U, V)

    def inverse( self ):
        return HyperellipticCurveElement(self.curve, self.U, -self.V)

    def __rmul__(self, exp):
        R = self.U.parent()
        I = HyperellipticCurveElement(self.curve, R(1), R(0))

        if exp == 0:
            return HyperellipticCurveElement(self.curve, R(1), R(0))
        if exp == 1:
            return self

        acc = I
        Q = self
        while exp:
            if exp & 1:
                acc = acc + Q
            Q = Q + Q
            exp >>= 1
        return acc
    
    def __eq__( self, other ):
        if self.curve == other.curve and self.V == other.V and self.U == other.U:
            return True
        else:
            return False

class HyperellipticCurve_:
    def __init__( self, f ):
        self.R = f.parent()
        self.F = self.R.base_ring()
        self.x = self.R.gen()
        self.f = f
        self.genus = floor((f.degree()-1) / 2)
    
    def identity( self ):
        return HyperellipticCurveElement(self, self.R(1), self.R(0))
    
    def random_element( self ):
        roots = []
        while len(roots) != self.genus:
            xi = self.F.random_element()
            yi2 = self.f(xi)
            if not yi2.is_square():
                continue
            roots.append(xi)
            roots = list(set(roots))
        signs = [ZZ(Integers(2).random_element()) for r in roots]

        U = self.R(1)
        for r in roots:
            U = U * (self.x - r)

        V = self.R(0)
        for i in range(len(roots)):
            y = (-1)**(ZZ(Integers(2).random_element())) * sqrt(self.f(roots[i]))
            lagrange = self.R(1)
            for j in range(len(roots)):
                if j == i:
                    continue
                lagrange = lagrange * (self.x - roots[j])/(roots[i] - roots[j])
            V += y * lagrange

        return HyperellipticCurveElement(self, U, V)
 
p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()

f = R.random_element(5).monic()
H = HyperellipticCurve_(f)

print(f"{p = }")
if __name__ == "__main__":
    cnt = 0
    while True:
        print("1. Get random point\n2. Solve the challenge\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if cnt < 3:
                G = H.random_element()
                k = getRandomRange(1, p)
                P = k * G
                print("Here is your point:")
                print(f"{P.U = }")
                print(f"{P.V = }")
                cnt += 1
            else:
                print("You have enough point!")
                continue

        elif opt == 2:
            G = H.random_element()
            print(f"{(G.U, G.V) = }")
            print("Give me the order !")
            odr = int(input(">"))
            if (odr * G).U == 1:
                print("Congratz! " + open("flag.txt", "r").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.") 
            break
```

The curve is...**h**appy now. Because its a **H**yperelliptic curve. 
Anyways much like in sadecc, I will discuss the challenge briefly here, talk about the cheese, and then save the actual writeup for the revenge challenge.

We essentially get 3 points on an unknown hyperelliptic curve. Then we must show that given a random point on the curve, we know its order. That is, some $n$ such that $(n * G).U = 1$. I will discuss $U, V$ later on.

Looking at how multiplication is done we observe:
```py
    def __rmul__(self, exp):
        R = self.U.parent()
        I = HyperellipticCurveElement(self.curve, R(1), R(0))

        if exp == 0:
            return HyperellipticCurveElement(self.curve, R(1), R(0))
```

So we enter `0` and get a point `(1, 0)`.
```
p = 906719739433
1. Get random point
2. Solve the challenge
3. Exit
> 2
(G.U, G.V) = (x^2 + 642758549788*x + 8773349744, 905810534292*x + 105203120945)
Give me the order !
>0
Traceback (most recent call last):
  File "/mnt/c/Users/warri/Downloads/idek25/happy_ecc/orig.py", line 150, in <module>
    print("Congratz! " + open("flag.txt", "r").read())
FileNotFoundError: [Errno 2] No such file or directory: 'flag.txt'
```

---

![alt text](Images/image-5.png)

I don't exactly have the original source code on me, but as far as I am aware it basically addresses the send 0 cheese.

Now lets discuss the challenge properly.

Hyperelliptic curves are algebraic curves of genus $g > 1$, given by an equation of the form

$y^2 + h(x) y = f(x)$ 

where $f(x)$ is a polynomial of degree $n = 2g + 1 > 4$ or $n = 2g + 2 > 4$ with $n$ distinct roots, 

and $h(x)$ is a polynomial of degree $n < g + 2$ (if the characteristic of the ground field is not 2, one can take $h(x) = 0$).

```py
class HyperellipticCurve_:
    def __init__( self, f ):
        self.R = f.parent()
        self.F = self.R.base_ring()
        self.x = self.R.gen()
        self.f = f
        self.genus = floor((f.degree()-1) / 2)

    def random_element( self ):
        roots = []
        while len(roots) != self.genus:
            xi = self.F.random_element()
            yi2 = self.f(xi)
            if not yi2.is_square():
                continue
            roots.append(xi)
            roots = list(set(roots))
        signs = [ZZ(Integers(2).random_element()) for r in roots]

...

p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()

f = R.random_element(5).monic()
H = HyperellipticCurve_(f)
```

From how the class is defined, and then used, we notice that the curve is, in essence, of the form $y^2 = f(x)$, where $f(x)$ is a monic degree-5 polynomial over a finite field $\mathbb{F}_p$ for some given prime $p$.

From the degree, we may thus derive that the genus of the curve is $g = 2$. Note this is different from the regular elliptic curves which are of genus 1.

One of the things we note is that the "points" used in the hyperelliptic curve do not follow the standard (x, y) coordinates, but some $(U, V)$, where $V$ is the lagrange interpolation of a set of points derived from the roots in $U$, and $U$ is a monic polynomial with $g$ roots.

The use of $U, V$ is what we call the [Mumford representation](https://www.math.auckland.ac.nz/~sgal018/crypto-book/ch10.pdf) of semi-reduced divisors, whereby for a hyperelliptic curve $y^2 + h(x)y = f(x)$, 

$V(x)^2 + h(x)V(x) \equiv f(x) \space (\bmod \space U(x))$. 

(See Section 10.3.1 and Lemma 10.3.5 in the above hyperlink)

We know $h(x) = 0$ in our case, so we have (and can test) the property:

$V(x)^2 \equiv f(x) \space (\bmod \space U(x))$

Since we have 3 random $(U, V)$, as $U$ is quadratic and $V$ is linear (lagrange interpolation is done on $g=2$ points, hence $V$ must be a line), we derive some linear remainders modulo quadratic modulos of $f(x)$. Three sets of these is actually enough for us to recover $f(x)$ reliably using the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem), as the lowest common multiple of the 3 quadratic modulos is likely a 6th degree polynomial, allowing for the full 5 degree polynomial $f(x)$ to be found. This enables us to recover the hyperelliptic curve used.

Interestingly, there exist a way to express the set of all Mumford representations on a given hyperelliptic curve as a group given some group law. This group law comes in the form of [Cantor's Algorithm](https://en.wikipedia.org/wiki/Imaginary_hyperelliptic_curve#Cantor's_algorithm), which the challenge code implements as above.

It remains to find the order of a given point in Mumford representation. The first step is for one to realise that when we consider the group law of points on a curve, be it hyperelliptic or elliptic, we are actually focused on the Jacobian of the curve, which is the mathematical "group structure" attached to the curve.

For elliptic curves, the Jacobian turns out to simply be isomorphic to the usual group on the set of points on this curve, hence why we don't go into "Jacobians" and instead go into "points on the elliptic curve".

For hyperelliptic curves, where the genus is greater than one, however, the Jacobian is different from the number of points on the curve. So we actually are not focused on the number of points of our $y^2 = f(x)$ curve but rather the order or cardinality of the Jacobian. It turns out that every element of the Jacobian has what we call one reduced divisor attached to it. Of which the Munford Representation is employed to represent the divisor specifically!

Aside from Jacobian-related mathematics, we should also cover the zeta function which all elliptic and hyperelliptic curves have. This zeta function is defined as

$Z(C, T) = e^{\left( \sum_{n=1}^{\infty} \frac{N_n}{n} \, T^n \right)}$, 

where $N_n$ is the number of points in the curve of field extension $\mathbb{F}^n$. 

This function was proven by Weil to be a rational function

$Z(C, T) = \frac{P(T)}{(1-T)(1-qT)}$

where $P(T)$ is some polynomial of degree $2g$. If we let the reciprocal roots of $P(T)$ be $\lbrace \alpha_0, \alpha_1, ..., \alpha_{2g-1} \rbrace$, i.e. $P(T) = \prod_{i=1}^{2g} (1 - \alpha_i T)$ where $\lbrace \alpha_0, \alpha_1, ..., \alpha_{2g-1} \rbrace$ are elements on the complex plane with magnitude $\sqrt{q}$.

Interestingly, we can rewrite

$\log(Z(C,T))$

$= \sum_{i=1}^{2g} \log(1-\alpha_i T) - \log(1-T) - \log(1-qT)$

$= \sum_{i=1}^{2g} \sum_{n\ge1}^{\infty} -\frac{(\alpha_iT)^n}{n} - \sum_{n\ge1}^{\infty} -\frac{(-T)^n}{n} - \sum_{n\ge1}^{\infty} -\frac{(qT)^n}{n}$

$= \sum_{n\ge1}^{\infty} (\frac{1}{n} (q^n + 1-\sum_{i=1}^{2g} \alpha_i^n) T^n )$

$= \sum_{n=1}^{\infty} \frac{N_n}{n} \, T^n$

(Use the property $\frac{1}{1-x} = 1 + x + x^2 + ...$ for $|x| < 1$, then apply integration to derive the $\log(1-x) = -\sum_{n\ge1}^{\infty} \frac{x^n}{n}$ identity)

This allows us to derive $N_n = q^n + 1-\sum_{i=1}^{2g} \alpha_i^n$, i.e. the number of points on the curve over $\mathbb{F}_q^n$. One might notice that this could be where the [Hasse-Weil bound](https://en.wikipedia.org/wiki/Hasse%27s_theorem_on_elliptic_curves) is derived from!

On the other hand, the order of the curve Jacobian is given by

$\text{\#}J(C)(\mathbb{F}_q) = \prod_{i}^{2g}(1-\alpha_i)$ (i have no idea where or how this is derived from, but just take it as fact for now)

which surprisingly enough equates to $P(1)$.

Now here's the fun part. Remember how I said the jacobian order is equivalent to the number of points of an elliptic curve when the genus is 1? We can actually derive this!

Notably, when the genus is 1, there are only two values of $\alpha$, say $\alpha_0$ and $\alpha_1$. Because $|\alpha_i|=\sqrt{q}$, we may show:

$N_1 = q + 1 - \sum\alpha_i = \prod\alpha_i + 1 - \sum\alpha_i = \prod_{i=1}^{2} (1 - \alpha_i) = \text{\#}J(C)(\mathbb{F}_q)$

of which this relation holds if and only if there are two $\alpha$ values, i.e. genus 1!

Moving on from interesting mathematical properties, we return to the challenge. From the hyperelliptic curve that we have already constructed, we can derive the zeta function, then extract the numerator $P(T)$, and lastly compute $P(1)$ to derive the order of the Jacobian, which is what we need to solve the challenge!

Here is my proof of concept script.

```py
p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()

f = R.random_element(5).monic()
H = HyperellipticCurve_(f)

print(f"{p = }")

def opt1():
    G = H.random_element()
    k = getRandomRange(1, p)
    P = k * G
    return P.U, P.V
def opt2(odr):
    G = H.random_element()
    print(f"{(G.U, G.V) = }")
    print("Give me the order !")
    if (odr * G).U == 1:
        print("Congratz! ")
    else:
        print("Wrong...")

u1, v1 = opt1()
u2, v2 = opt1()
u3, v3 = opt1()

# V(x)2 ≡ f(x)(modU(x)).
rec_f = crt([v1**2, v2**2, v3**2], [u1, u2, u3])
assert rec_f == f

rec_H = HyperellipticCurve(rec_f) # we're using the sage object this time round!

from time import time
start = time()
P = rec_H.zeta_function().numerator()
odr = P(1)
print(time() - start)

print(odr, P)
opt2(odr) # should print Congratz!
```

A rather interesting observation stems from how...potentially random the time taken to derive the order value goes. While the crt step happens very fast, upon testing for various bit sizes of p I obtained the following benchmarks.
```
# 16-bit p = 33857          0.0760338306427002s
# 24-bit p = 8515967        1.2574412822723389s
# 32-bit p = 3477713039     72.88372015953064s
# 40-bit p = 823280383273   700.5502178668976s
```
Specifically, the challenge uses a 40-bit p value.

Running the script a few times, I obtained:
```
p = 555500372159
287.41215896606445
308580776576634077648478 308580663468787502321281*x^4 + 113108208277154785*x^3 - 361702031204*x^2 + 203615*x + 1
(G.U, G.V) = (x^2 + 432968158449*x + 525271510096, 56140444973*x + 159785929704)
Give me the order !
Congratz!
```

```
p = 635561982137
447.5006275177002
403939733616491675354188 403939033137912307086769*x^4 + 700477647430491043*x^3 + 931936674236*x^2 + 1102139*x + 1
(G.U, G.V) = (x^2 + 146479347999*x + 74699063454, 624967985193*x + 84379691476)
Give me the order !
Congratz!
```

where the second line is the time taken to compute the order.


It is...interesting, that the order computation step varies in time taken.

