### embryonic_plant
---

#### Files
`source.py`
```py
from Crypto.Util.number import getPrime, long_to_bytes, inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from secret import FLAG


class RNG:

    def __init__(self, seed):
        self.e = 0x10001
        self.s = seed

        self.r = getPrime(768)
        while True:
            self.p, self.q = getPrime(768), getPrime(768)
            if self.p < self.r and self.q < self.r:
                break

        self.n = self.p * self.q * self.r
        phi = (self.p - 1) * (self.q - 1) * (self.r - 1)
        self.d = inverse(self.e, phi)

    def next(self):
        self.s = (self.s * self.p + self.q) % self.r
        return self.s


def main():
    rng = RNG(getPrime(512))
    rns = [rng.next() for _ in range(5)]

    key = sha256(long_to_bytes(rng.d)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    enc_flag = cipher.encrypt(pad(FLAG, 16)).hex()

    with open('output.txt', 'w') as f:
        f.write(f'n = {rng.n}\n')
        f.write(f's = {rns}\n')
        f.write(f'enc_flag = {enc_flag}\n')


if __name__ == "__main__":
    main()
```

`output.txt`
```
n = 875160154252520186251141359813376844205078837688859219647998263059390545455666959868272831956779132045330105458640460325486680058028233270020291614157451317894110269639780507518860757299450578151147748572019371950843986400076289065334864577087504297359676338166424192877389197803442490978821375794048316553853085966558794240760959161987598108459441945291723309230665829568115073301763544532552179053221908864303864014278134933463597319119189753348991487712539547783209384907074459767339389912999640300731884080101606842315180302622347685382825488775275363493924203654141256657466019975768214244502429057343992946031175889606627829209702720334661107181627261133702840164098042293465302874342367
s = [45948196110742333078791904670754464213578139076280109814760521831353273605782767324779081189039031009815013571451298379981707915542440414220083426012609548317078548002379773850309022768943249397294154504631709396600886029113258544, 665421018479354408650321321446504004021595291664664613059639369284378526681870680990726015080235767661978417143890017835302285399955943814186163819783105747360598346167878408804511855184450139017542601099343516459031570045750334635, 116901116055486713179543809270968616175254891027356317875260251653063459332706332539151662885597749087527500088196623717000607610204151297409257838680010556067036481294394312559141590536968964270065614095041734217016802912127551399, 257185387102952423422505329148493981831897715690584197952849048768011651303898015179171902245107615610642197589412557491017458513344338002354160349045327465820185865360211004133692933165886876481285477189851986291296987966454584913, 600597039831835988459465667623398229366883082253281715825043750022005882279772326647162809398726368298023180858058246314753665389921411839577046046481816334727242911521098595075675355340100111145925656700034968689114367721111389240]
enc_flag = "df534b412fbbb5bf920a9c8a76f85013b2c6cb49642c30a7e5e801f9576b4f36071945f46d3e78c8b1e2adff0c090d7d88e9a068caae958d87ca56bcd0763e00e527371f271530bd6bb779284233ec45"
```
#### Writeup

Working backwards from the encrypted flag `enc_flag`, we find that it is `AES` encrypted with `rng.d` as the AES key (after hashing with the `sha256` hashing algorithm). Thus, to recover the flag we need `rng.d`.

Now we look into the `RNG` class and see how `rng.d` is derived. `__init__()` very clearly replicates an RSA-style key generation where primes `p, q, r` are generated, and then `d = pow(0x10001, -1, (p-1)*(q-1)*(r-1))`. So we need to find `rng.p`, `rng.q`, `rng.r`.

We learn from `main()` that we have `rng.n = p*q*r`, and `rns = <5 consecutive rng.next() outputs>`. We see that `rng.next()` takes some internal state number `s`, performs `(s*p + q) % r`, outputs that and saves it as the new `s` value. Exactly like a Linear Congruential Generator (LCG)!

So, in order to recover the flag we need `rng.d`. To get `rng.d` we need `rng.p, rng.q, rng.r`. Which are parameters to some LCG whose 5 consecutive outputs we can find in `rns`.

For convenience, we rewrite `rng.p` as a multiplier `a`, `rng.q` as an increment `b`, and `rng.r` as a modulus `m`.

With basic algebra, we can rewrite the five numbers in `rns` as 

$s, a*s+b, a^2 s + ab + b, a^3 s + a^2 b + ab + b, a^4 s + a^3 b + a^2 b + ab + b$, all done mod $m$

By taking differences between the last four consecutive values we can derive:

$d_0 = ((a^2-a)*s + ab)$ mod $m$

$d_1 = a * ((a^2-a)*s + ab)$ mod $m$

$d_2 = a^2 * ((a^2-a)*s + ab)$ mod $m$

Therefore we have $d_0 * d_2 == d_1^2$ (mod $m$), meaning $d_0 * d_2 - d_1 * d_1 == k * m$ for some integer $k$. Since we have $rng.n = a*b*m$, we can use the greatest common divisor algorithm to recover $m$.

Since $d_1 = a * d_0$ (mod $m$), knowing $m, d_0, d_1$ we can derive $a$. We can then find $b = \text{rns[1]} - a * \text{rns[0]}$ (mod $m$). By finding all 3 LCG parameters, we now have `rng.p, rng.q, rng.r`. Now all it remains is to derive the `rng.d` and then the flag!

#### solve.py
```py
n = ...
s = ...
enc_flag = bytes.fromhex("...")

from math import gcd

def get_params(y, m=None):
    d0 = y[2] - y[1]    #   ((a2-a)s + ab)
    d1 = y[3] - y[2]    # a ((a2-a)s + ab)
    d2 = y[4] - y[3]    # a2((a2-a)s + ab)
    g = d2 * d0 - d1 * d1
    m = gcd(g, m)
    a = d1 * pow(d0, -1, m) % m
    b = (y[1] - a * y[0]) % m
    return m, a, b

m,a,b = get_params(s, n)
assert m*a*b == n
phi = (m - 1) * (a - 1) * (b - 1)
d = pow(65537, -1, phi)

from Crypto.Util.number import getPrime, long_to_bytes, inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
key = sha256(long_to_bytes(d)).digest()
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(enc_flag))
# b'HTB{0op5_my_$33d$_f311_0ff_5h3_gr0und_4nd_br0ugh5_y0u_4_fl4g!#@$%}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
```