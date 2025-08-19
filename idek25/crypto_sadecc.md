This writeup was written by Mono from slightsmile! A few edits were made here and there by warri.

This .md file contains the writeups for sadecc and its revenge challenge. Both operate on the same custom curve with the same custom operations and have the same challenge contexts. The only exception lies in that sadecc is cheesable due to the way the author implemented it, leading it to get more solves.

I'll be covering the cheese for sadecc and will not touch too much on the actual challenge itself. For the challenge, see Mono's input in sadecc revenge! I've also provided my own proof of concept using slightly different polynomials from Mono. -warri

![alt text](Images\image-2.png)

`chall.py`
```py
from Crypto.Util.number import *
from secret import n, xG, yG
import ast

class DummyPoint:
    O = object()

    def __init__(self, x=None, y=None):
        if (x, y) == (None, None):
            self._infinity = True
        else:
            assert DummyPoint.isOnCurve(x, y), (x, y)
            self.x, self.y = x, y
            self._infinity = False

    @classmethod
    def infinity(cls):
        return cls()

    def is_infinity(self):
        return getattr(self, "_infinity", False)

    @staticmethod
    def isOnCurve(x, y):
        return "<REDACTED>"

    def __add__(self, other):
        if other.is_infinity():
            return self
        if self.is_infinity():
            return other

        # ——— Distinct‑points case ———
        if self.x != other.x or self.y != other.y:
            dy    = self.y - other.y
            dx    = self.x - other.x
            inv_dx = pow(dx, -1, n)
            prod1 = dy * inv_dx
            s     = prod1 % n

            inv_s = pow(s, -1, n)
            s3    = pow(inv_s, 3, n)

            tmp1 = s * self.x
            d    = self.y - tmp1

            d_minus    = d - 1337
            neg_three  = -3
            tmp2       = neg_three * d_minus
            tmp3       = tmp2 * inv_s
            sum_x      = self.x + other.x
            x_temp     = tmp3 + s3
            x_pre      = x_temp - sum_x
            x          = x_pre % n

            tmp4       = self.x - x
            tmp5       = s * tmp4
            y_pre      = self.y - tmp5
            y          = y_pre % n

            return DummyPoint(x, y)

        dy_term       = self.y - 1337
        dy2           = dy_term * dy_term
        three_dy2     = 3 * dy2
        inv_3dy2      = pow(three_dy2, -1, n)
        two_x         = 2 * self.x
        prod2         = two_x * inv_3dy2
        s             = prod2 % n

        inv_s         = pow(s, -1, n)
        s3            = pow(inv_s, 3, n)

        tmp6          = s * self.x
        d2            = self.y - tmp6

        d2_minus      = d2 - 1337
        tmp7          = -3 * d2_minus
        tmp8          = tmp7 * inv_s
        x_temp2       = tmp8 + s3
        x_pre2        = x_temp2 - two_x
        x2            = x_pre2 % n

        tmp9          = self.x - x2
        tmp10         = s * tmp9
        y_pre2        = self.y - tmp10
        y2            = y_pre2 % n

        return DummyPoint(x2, y2)

    def __rmul__(self, k):
        if not isinstance(k, int) or k < 0:
            raise ValueError("Choose another k")
        
        R = DummyPoint.infinity()
        addend = self
        while k:
            if k & 1:
                R = R + addend
            addend = addend + addend
            k >>= 1
        return R

    def __repr__(self):
        return f"DummyPoint({self.x}, {self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

if __name__ == "__main__":
    G = DummyPoint(xG, yG)
    print(f"{n = }")
    stop = False
    while True:
        print("1. Get random point (only one time)\n2. Solve the challenge\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if stop:
                print("Only one time!")
            else:
                stop = True
                k = getRandomRange(1, n)
                P = k * G
                print("Here is your point:")
                print(P)

        elif opt == 2:
            ks = [getRandomRange(1, n) for _ in range(2)]
            Ps = [k * G for k in ks]
            Ps.append(Ps[0] + Ps[1])

            print("Sums (x+y):", [P.x + P.y for P in Ps])
            try:
                ans = ast.literal_eval(input("Your reveal: "))
            except:
                print("Couldn't parse."); continue

            if all(P == DummyPoint(*c) for P, c in zip(Ps, ans)):
                print("Correct! " + open("flag.txt").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.") 
            break
```

The general idea here is that there's some custom elliptic curve arithmetic going on, and you're given $k_0 * G, k_1 * G, (k_0 + k_1) * G$. The code intends for you to use the sum of each point's coordinates and enter the exact values of $k_0 * G, k_1 * G, (k_0 + k_1) * G$.

The issue however lies in 
```py
try:
    ans = ast.literal_eval(input("Your reveal: "))
except:
    print("Couldn't parse."); continue

if all(P == DummyPoint(*c) for P, c in zip(Ps, ans)):
    print("Correct! " + open("flag.txt").read())
else:
    print("Wrong...")
break
```

We can send `[]` into `ast.literal_eval()` to get an empty list as `ans`. The `zip(Ps, ans)` logic will terminate immediately as `ans` is empty, thus Correct! and the flag are printed onto console.
![alt text](Images\sadcheese.png)

---
Onto the revenge challenge:

![alt text](Images\image-4.png)

`revenge.py`
```py
from Crypto.Util.number import *
# from secret import n, xG, yG
import ast

class DummyPoint:
    O = object()

    def __init__(self, x=None, y=None):
        if (x, y) == (None, None):
            self._infinity = True
        else:
            assert DummyPoint.isOnCurve(x, y), (x, y)
            self.x, self.y = x, y
            self._infinity = False

    @classmethod
    def infinity(cls):
        return cls()

    def is_infinity(self):
        return getattr(self, "_infinity", False)

    @staticmethod
    def isOnCurve(x, y):
        return pow(y - 1337, 3, n) == pow(x, 2, n)

    def __add__(self, other):
        if other.is_infinity():
            return self
        if self.is_infinity():
            return other

        # ——— Distinct‑points case ———
        if self.x != other.x or self.y != other.y:
            dy    = self.y - other.y
            dx    = self.x - other.x
            inv_dx = pow(dx, -1, n)
            prod1 = dy * inv_dx
            s     = prod1 % n       # dy/dx

            inv_s = pow(s, -1, n)   # dx/dy
            s3    = pow(inv_s, 3, n)

            tmp1 = s * self.x
            d    = self.y - tmp1 # y = sx + d

            # y = sx + d
            # x2 == (y-1337)3
            # x2 == (sx + d - 1337)3 == ... + 3(d-1337)s2 x2 + ...
            # (1 - 3(d-1337) s2)) == s3 (x1 + x2 + x3) by vieta
            # 1/s3 - 3(d-1337)/s - x1 - x2 == x3

            d_minus    = d - 1337
            neg_three  = -3
            tmp2       = neg_three * d_minus # -3 (d - 1337)
            tmp3       = tmp2 * inv_s   # 1/s * -3 (d - 1337)
            sum_x      = self.x + other.x
            x_temp     = tmp3 + s3
            x_pre      = x_temp - sum_x #  1/s * -3 (d - 1337) + s^-3 - x1 - x2
            x          = x_pre % n # this is correct...except they did not flip the x over!!

            tmp4       = self.x - x # y = sx + d therefore (y0 - y') == s(x0-x')
            tmp5       = s * tmp4
            y_pre      = self.y - tmp5
            y          = y_pre % n  # this is correct y value

            return DummyPoint(x, y)

        dy_term       = self.y - 1337
        dy2           = dy_term * dy_term
        three_dy2     = 3 * dy2
        inv_3dy2      = pow(three_dy2, -1, n)
        two_x         = 2 * self.x
        prod2         = two_x * inv_3dy2
        s             = prod2 % n

        inv_s         = pow(s, -1, n)
        s3            = pow(inv_s, 3, n)

        tmp6          = s * self.x
        d2            = self.y - tmp6

        d2_minus      = d2 - 1337
        tmp7          = -3 * d2_minus
        tmp8          = tmp7 * inv_s
        x_temp2       = tmp8 + s3
        x_pre2        = x_temp2 - two_x
        x2            = x_pre2 % n

        tmp9          = self.x - x2
        tmp10         = s * tmp9
        y_pre2        = self.y - tmp10
        y2            = y_pre2 % n

        return DummyPoint(x2, y2)

    def __rmul__(self, k):
        if not isinstance(k, int) or k < 0:
            raise ValueError("Choose another k")

        R = DummyPoint.infinity()
        addend = self
        while k:
            if k & 1:
                R = R + addend
            addend = addend + addend
            k >>= 1
        return R

    def __repr__(self):
        return f"DummyPoint({self.x}, {self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

if __name__ == "__main__":
    G = DummyPoint(xG, yG)
    print(f"{n = }")
    stop = False
    while True:
        print("1. Get random point (only one time)\n2. Solve the challenge\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if stop:
                print("Only one time!")
            else:
                stop = True
                k = getRandomRange(1, n)
                P = k * G
                print("Here is your point:")
                print(P)

        elif opt == 2:

            ks = [getRandomRange(1, n) for _ in range(2)]
            Ps = [k * G for k in ks]
            Ps.append(Ps[0] + Ps[1]) # k0 G, k1 G, (k0+k1) G

            ans = sum([[P.x, P.y] for P in Ps], start=[])
            print("Sums (x+y):", [P.x + P.y for P in Ps])
            try:
                check = ast.literal_eval(input("Your reveal: "))
            except:
                print("Couldn't parse.");

            if ans == check:
                print("Correct! " + open("flag.txt").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.")
            break
```

The first difficulty of this challenge lies in how it is offuscated. So, lets break down how to deoffuscate it. 

The code may be simplified in the following way: 
```
s = (y₁ - y₂) / (x₁ - x₂) mod n  (Point Addition)
s = 2x / (3 * (y - 1337)²) mod n (Point Doubling)
x₃ = -3(y₁ - sx₁ - 1337)s⁻¹ + s⁻³ - x₁ - x₂ mod n
y₃ = y₁ - s(x₁ - x₃) mod n
```

Looking at the formula for `s` in Point Addition, we can infer that `s` is supposed to refer to the gradient of the 2 points which it is supposed to add together. This combined with $y_3$ means that the points $(x_i, y_i)$ all lie on the same line. It seems like some variation on the elliptic curve system. 

We also notice that `(y-1337)` seems to appear a bunch. Lets replace all instances of `y - 1337` with just `y` for simplicities sake. 
```
s = (y₁ - y₂) / (x₁ - x₂) mod n  (Point Addition)
s = 2x / (3 * y²) mod n (Point Doubling)
x₃ = -3(y₁ - sx₁)s⁻¹ + s⁻³ - x₁ - x₂ mod n
y₃ = y₁ - s(x₁ - x₃) mod n
```
Better, but not quite there yet. We now take a look at the definition for s for point doubling. We know that in a normal elliptic curve system, that s is the gradient at the point. In other words, 
$$
dy/dx = 2x / (3 * y²)\implies 3y^2\;dy = 2x\;dx\\
$$

Integrating both sides, 
$$
y^3 = x^2 + C
$$
However, as the server allows us to get a random point, we can find the value of $C$. Testing this against the server, we get that $C=0$. 

So, we have that $(y-1337)^3 \equiv x^2 \pmod{n}$. We can verify this by testing this against the server repeatedy. 

However, there is 1 last nuance to it. If you examine the point addition carefully, the x coordinate of the point is flipped compared to a normal ECC. It is a small change, but one which we need to acknowledge. 

Henceforth, we shall transition to the more standard form of this curve, namely $y^2 = x^3$. We may do this by doing the substitution $(x_{\text{new}}, y_{\text{new}}) = (y-1337, x)$.

Now, the challenge which we are left with is as follows: 
> We have points $P_1, P_2, P-3$ with coordinates $(x_1, y_1), (x_2, y_2), (x_3, y_3)$, such that $P_3 = P_1 + P_2$. We are given $s_i = x_i+y_i,\; i\in\{1,2,3\}$, and need to get all the coordinates $x_i, y_i$. 

We can attempt to do point addition as we normally would. However, as this curve is singular, we can simply this abit. 

Notably, in this curve, if we set $y = (-t)^3$, we have that $1/t_3 = 1/t_1 + 1/t_2$. 

So, we now have the following equations (all under mod n): 
```
t1 + 1 = s1 * t1^3             -(1)
t2 + 1 = s2 * t2^3             -(2)
(t1+t2) + 1 = s3 * (t1+t2)^3   -(3)
```
Noting that $n$ is composite, we may have a better time solving for $t_i$ using the gcd algorithm. In fact, we seem to want to: 
- Take gcd on (1) and (3) to get an equation (4) in `t2`,
- Take gcd on (2) and (4) to solve for `t2`
- Substitue this value of `t2` into (3), and take gcd with (1). 

When we have `t1`, `t2`, sending the coordinates is trivial. 


(with the help of gpt)
`mono_solve.sage`
```py
n = 18462925487718580334270042594143977219610425117899940337155124026128371741308753433204240210795227010717937541232846792104611962766611611163876559160422428966906186397821598025933872438955725823904587695009410689230415635161754603680035967278877313283697377952334244199935763429714549639256865992874516173501812823285781745993930473682283430062179323232132574582638414763651749680222672408397689569117233599147511410313171491361805303193358817974658401842269098694647226354547005971868845012340264871645065372049483020435661973539128701921925288361298815876347017295555593466546029673585316558973730767171452962355953
sums = [15304773097245954853987530854949687677406010508586270973049655980027832069739757957903461845626655940077943491909880603366688748808512263686236957138711335009216923024205469452150370065950832780107402428037043090150972445655835986302922287622701490961144920324325286885977214921156821620413595815609757135223414372548810865184312791658284395545861215535979987817184523921999029053442762199749270713487644251372347896226946646911679436285387905111441945884367524779701268467836214576294762219950337045148287144774702495628842354983493262917341111057007920332180216509947389847339616781643821066307158608163345877129311, 30542717213433420425782466968723975648499448702392782847973828026658913463223450549780855181391978561972699436420519613821563254210274781419297267554272053921985539871496677525056672060363730824427105553965514942842462548431888840521402698511897387485985815626614750602753222350119008266532977227499415773519300961440271782056250760272711944253517117177707286570230012949268042518940425277442986424141116482816124695902981952950734102551412070491451812940011589341613915256043986314287154325787972918340323796081543991129524457955229208301476517669834483111998784953677941111978659251471402584028149047542211211263544, 6093766280677151614625014471969171245974406774556356653029711925547175514554019022381940550284993553946390993296976697071166349716650902166609855064392618885131155193215738157599202467692350237515732755284306597474434091563067548447665400234435876129383541161244545675892291662150162577923447756233608375157807500861555350933667565855439113562160599121469401917461515467826764575149241123141711978747449577097787952975891712451447434537066550411202856504207034992741066231089756990593016572525984192305233523818145912898204276621633534963027448036815711358057937718879542600280391669890362968227532189408934163222353]

s1, s2, s3 = sums[0]-1337, sums[1]-1337, sums[2]-1337 


Zn = Integers(n)

def polynomial_gcd_mod_n(p1_zz, p2_zz, n):
    if p1_zz.parent() != p2_zz.parent():
        raise TypeError("Input polynomials must be in the same ring.")
    Zn = Integers(n)
    P_Zn = PolynomialRing(Zn, p1_zz.variable_name())
    a, b = P_Zn(p1_zz), P_Zn(p2_zz)
    while b != 0:
        #print(f"Current polynomials: \na = {a}, \nb = {b}\n")
        lc_b = b.leading_coefficient()
        try:
            inv_lc = pow(int(lc_b), -1, int(n))
        except ValueError:
            factor = gcd(int(lc_b), int(n))
            return ('FACTOR_FOUND', factor)
        b_monic = b * inv_lc
        a, b = b_monic, a % b_monic
    lc_a = a.leading_coefficient()
    if lc_a == 0:
        return ('SUCCESS', p1_zz.parent().zero())
    try:
        inv_lc_a = pow(int(lc_a), -1, int(n))
        a_monic = a * inv_lc_a
        return ('SUCCESS', p1_zz.parent()(a_monic))
    except ValueError:
        factor = gcd(int(lc_a), int(n))
        return ('FACTOR_FOUND', factor)


def get_solver_polynomial_zz(s1, s2, s3):
    print("--- Step A: Defining polynomials and computing resultant over ZZ ---")
    R_ZZ.<u1, u2> = PolynomialRing(ZZ)
    F1_biv_ZZ = int(s1) * u1**3 - u1 - 1
    H_biv_ZZ  = -int(s3) * (u1+u2)**3 + (u1+u2) - 1
    Res_u2_ZZ_multi = F1_biv_ZZ.resultant(H_biv_ZZ, u1)

    # Define the univariate polynomial ring for the output
    P_u2_ZZ.<u2_z> = PolynomialRing(ZZ)

    # Manually reconstruct the polynomial term by term to avoid casting errors.
    Res_u2_zz = P_u2_ZZ(0)
    for c, m in zip(Res_u2_ZZ_multi.coefficients(), Res_u2_ZZ_multi.monomials()):
        # The monomial 'm' will only have a 'u2' part. Get its degree.
        k = m.degree(u2)
        # Add the term (coefficient * variable^degree) to our new polynomial.
        Res_u2_zz += c * (u2_z**k)
    
    # Define the F2 polynomial over ZZ
    F2_poly_zz = int(s2) * u2_z**3 - u2_z - 1
    
    print("Resultant and polynomial definition successful.\n")
    return (Res_u2_zz, F2_poly_zz)


Res_poly, F2_poly = get_solver_polynomial_zz(s1, s2, s3)


# 2. Call the GCD function with the integer polynomials and the modulus n
print("--- Final GCD Calculation (modulo n) ---")
status, result = polynomial_gcd_mod_n(Res_poly, F2_poly, n)
print(status)
print(result)

u2Sol = n-result[0]

R_ZZ.<u1> = PolynomialRing(ZZ)
F1_biv_ZZ = int(s1) * u1**3 - u1 - 1
H_biv_ZZ  = -int(s3) * (u1+int(u2Sol))**3 + (u1+int(u2Sol)) - 1
status, result = polynomial_gcd_mod_n(F1_biv_ZZ, H_biv_ZZ, n)
print(status)
print(result)
u1Sol = n-result[0]


t1_secret = u1Sol
t2_secret = u2Sol
t3_secret = t1_secret + t2_secret
t1p = pow(t1_secret, -1, n) 
t2p = pow(t2_secret, -1, n) 
t3p = pow(t3_secret, -1, n) 
x1, y1 = t1p^2, t1p^3
x2, y2 = t2p^2, t2p^3
x3, y3 = t3p^2, t3p^3



final = [[y1 %n,x1+1337 %n], [y2 %n,x2+1337 %n], [(-(y3))%n,x3+1337 %n]]

print()
for i in range(3): 
    print((final[i][0] + final[i][1] - sums[i]) %n) 
    print((final[i][0]^2 - (final[i][1]-1337)^3) % n) 
        
        
print("--- Final Coordinates ---")
print(str(final).replace(" ", ""))
```

`idek{the_idea_came_from_a_Vietnamese_high_school_Mathematical_Olympiad_competition_xD_sorry_for_unintended_:sob:_75f492115a34ff4324212e09e24aa5bd}`

While Mono used 1/t as his polynomials, I had used the following:

$u_1^3 + u_1^2 + 1337 - s_1 = 0$

$u_2^3 + u_2^2 + 1337 - s_2 = 0$

$-(u_1^{-1} + u_2^{-1})^{-3} + (u_1^{-1} + u_2^{-1})^{-2} + 1337 - s_3 = 0$

The first two is directly derivable from the $(x, y) \rightarrow (t^3, t^2 + 1337)$ map. For the third one, notice that due to the way the curve is mapped and how the x,y axes are inverted,

$G, k*G$ maps to $t, \frac{t}{k}$ for some point $G$

Given $k_0 * G, k_1 * G$, we have $u_1 = \frac{t}{k_0}$, $u_2 = \frac{t}{k_1}$ for some $t$. I'll leave proof that $(k_0 + k_1) * G$ mapping to $(u_1^{-1} + u_2^{-1})^{-1}$ as an exercise to the reader.

One thing to note, however, is that the point addition formula employed by the challenge is incomplete. That is, while point addition ends with flipping the third point with respect to the x axis (y axis in this case), the point addition formula in here does not do so. Therefore, in order to accurately represent $(k_0 + k_1) * G$ in proper elliptic curve point addition, we add the -ve sign to the x coordinate. That is, $(u_1^{-1} + u_2^{-1})^{-3}$ becomes $-(u_1^{-1} + u_2^{-1})^{-3}$

We can use these polynomials and some direct sage resultant computation to derive the flag. Here's a proof of  concept.
```py
n = 18462925487718580334270042594143977219610425117899940337155124026128371741308753433204240210795227010717937541232846792104611962766611611163876559160422428966906186397821598025933872438955725823904587695009410689230415635161754603680035967278877313283697377952334244199935763429714549639256865992874516173501812823285781745993930473682283430062179323232132574582638414763651749680222672408397689569117233599147511410313171491361805303193358817974658401842269098694647226354547005971868845012340264871645065372049483020435661973539128701921925288361298815876347017295555593466546029673585316558973730767171452962355953

import random

ks = [random.randint(1, n) for _ in range(2)]
Ps = [DummyPoint((k**3) % n, ((k**2)+1337) % n) for k in ks]
Ps.append(Ps[0] + Ps[1])

s1, s2, s3 = Ps[0].x + Ps[0].y, Ps[1].x + Ps[1].y, Ps[2].x + Ps[2].y

from sage.all import Zmod, PolynomialRing, ZZ, QQ
import random
ks = [random.randint(1, n) for _ in range(2)]
Ps = [DummyPoint((k**3) % n, ((k**2)+1337) % n) for k in ks]
Ps.append(Ps[0] + Ps[1])

s1, s2, s3 = Ps[0].x + Ps[0].y, Ps[1].x + Ps[1].y, Ps[2].x + Ps[2].y

F = PolynomialRing(ZZ, names=('u1, u2')); u1, u2 = F.gens()

uu1, uu2 = ks
f1 = u1**3 + u1**2 + 1337 - s1
f2 = u2**3 + u2**2 + 1337 - s2
f3 = -(u1**-1 + u2**-1)**-3 + (u1**-1 + u2**-1)**-2 + 1337 - s3
# we flip the -1 here because DummyPoint's wonky addition is elliptic curve point add without the flipping over vertical axis (horizontal in ECC)
print(f1(u1=uu1) % n, f2(u2=uu2) % n, f3(u1=uu1,u2=uu2) % n)

def polygcd(a, b):
    while b != 0:
        b_monic = b.monic()
        a, b = b_monic, a % b_monic
    return a.monic()

f3_num = f3.numerator()
hh = f3_num.resultant(f2, u2).change_ring(Zmod(n)).univariate_polynomial()
f1 = f1.change_ring(Zmod(n)).univariate_polynomial()
u1_ = n - polygcd(hh, f1)[0]
print(u1_ == uu1)
```