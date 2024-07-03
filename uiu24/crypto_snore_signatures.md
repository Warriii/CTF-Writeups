## Snore Signatures (122 Solves, 416 Pts)
```
Author: Richard

These signatures are a bore!

ncat --ssl snore-signatures.chal.uiuc.tf 1337
```

`chal.py`
```py
#!/usr/bin/env python3

from Crypto.Util.number import isPrime, getPrime, long_to_bytes, bytes_to_long
from Crypto.Random.random import getrandbits, randint
from Crypto.Hash import SHA512

LOOP_LIMIT = 2000


def hash(val, bits=1024):
    output = 0
    for i in range((bits//512) + 1):
        h = SHA512.new()
        h.update(long_to_bytes(val) + long_to_bytes(i))
        output = int(h.hexdigest(), 16) << (512 * i) ^ output
    return output


def gen_snore_group(N=512):
    q = getPrime(N)
    for _ in range(LOOP_LIMIT):
        X = getrandbits(2*N)
        p = X - X % (2 * q) + 1
        if isPrime(p):
            break
    else:
        raise Exception("Failed to generate group")

    r = (p - 1) // q

    for _ in range(LOOP_LIMIT):
        h = randint(2, p - 1)
        if pow(h, r, p) != 1:
            break
    else:
        raise Exception("Failed to generate group")

    g = pow(h, r, p)

    return (p, q, g)


def snore_gen(p, q, g, N=512):
    x = randint(1, q - 1)
    y = pow(g, -x, p)
    return (x, y)


def snore_sign(p, q, g, x, m):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = hash((r + m) % p) % q
    s = (k + x * e) % q
    return (s, e)


def snore_verify(p, q, g, y, m, s, e):
    if not (0 < s < q):
        return False

    rv = (pow(g, s, p) * pow(y, e, p)) % p
    ev = hash((rv + m) % p) % q

    return ev == e


def main():
    p, q, g = gen_snore_group()
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    queries = []
    for _ in range(10):
        x, y = snore_gen(p, q, g)
        print(f"y = {y}")

        print('you get one query to the oracle')

        m = int(input("m = "))
        queries.append(m)
        s, e = snore_sign(p, q, g, x, m)
        print(f"s = {s}")
        print(f"e = {e}")

        print('can you forge a signature?')
        m = int(input("m = "))
        s = int(input("s = "))
        # you can't change e >:)
        if m in queries:
            print('nope')
            return
        if not snore_verify(p, q, g, y, m, s, e):
            print('invalid signature!')
            return
        queries.append(m)
        print('correct signature!')

    print('you win!')
    print(open('flag.txt').read())

if __name__ == "__main__":
    main()
```

`snore_gen()`, `snore_sign()`, `snore_verify()`, appear to be a modified implementation of [DSA/Digital Signature Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm). The algorithm is built upon public key infrastructure, wherein with the sender's public key one can verify any of the sender's signature of a message, while only the sender with knowledge of their private key can construct a valid message-signature pair. I won't delve into the intricacies for now, but in the case of `snore` it boils down to the fact that in the `sign()` and `verify()` parts, stuff eventually cancels out leading to the derivation of `r` and `rv`.

`r` requires the private information `x` to generate a valid signature, whereas `rv` merely requires an existing message-signature pair. If `rv == r`, then we know the signature is valid as whoever that signed it must generate a valid `r`, which must mean they know `x` and therefore should be the sender that they claim to be.

Lets not get ourselves lost into the theory and focus on the problem.

To get the flag, we need to pass 10 rounds, wherein each round we need to forge a valid `(m1, s1)` message-signature pair given a known `(m,s)` pair of which we control `m`. The parameters to the DSA differ across the 10 rounds, and we are restricted to always change our `m`s throughout the 10 rounds. We can't quite derive `x` from a single `(m, s)` pair to forge our signatures, but we do know that while we need to find `m1 != m`, `s` can be `s1`. With the same signature, `snore_verify()` would compute `rv == r`.

Thus, we now have to find distinct `m1, m` such that:
```
hash((rv + m) % p) % q == hash((r + m) % p) % q
```

In theory there could be a weakness in the `hash()` function that result in finding a collision, but I doubt there exists one. A more interesting thing to note is that the input of the hash is `[rv/r] + m (mod p)` (note rv is r in our case).

Since the modulo is computed first, we can just use `m, m+p` as our `m, m1` pair. Reusing the same signature results in the integer inputs into `hash()` becoming the same value under modulo p, and thus we easily forge our distinct separate message-signature pair!

Now we just need to repeat this 10 times to get the flag.

```
ncat --ssl snore-signatures.chal.uiuc.tf 1337
p = 25314438212884162584121069893909753686458941721746907770211587969395420887840345365432202868511635194267014049140029699952322933552012002076923624112840884761581790235207955410899458374642840190417328918662885397961220265337305590620365689045929796432165299831808974900241783103469206719532643394780542865141
q = 12858375881781895428144390121600885071214528420047651726166005444055626523863042960786224670246018437154803602137172275269070351057216041111272658213288431
g = 12263963434932711109691167588559353566579036023146855587452310498023514339185401720467404447253728534935992612843450711407958886559886958043224805381763615834612639835948914417955018360622634025802941570023547620307565261402028238659457862219971160782121371644523794603068419348180818278735315501335182912401
y = 15134735124292279854444439235391773776738250615295418025875201890632956404958089204814387071915374244494687852473649852888292788395017740552857643277914623856582968260304118409368060393573117604724783714187435113664741175499019299381764498418220196298697143670298478269397790396343523962758855092636938411732
you get one query to the oracle
m = 0
s = 12824084492202487331308522560254908205060296004697502079942893397150973907271474676494878639728605773308326416981833995903635982382291671170675722517419451
e = 9040371380243573010406038623757516140943722372090455621521622407502531959445662328573501401413310568297471690803729987176745180474910252286238977899794294
can you forge a signature?
m = 25314438212884162584121069893909753686458941721746907770211587969395420887840345365432202868511635194267014049140029699952322933552012002076923624112840884761581790235207955410899458374642840190417328918662885397961220265337305590620365689045929796432165299831808974900241783103469206719532643394780542865141
s = 12824084492202487331308522560254908205060296004697502079942893397150973907271474676494878639728605773308326416981833995903635982382291671170675722517419451
correct signature!
...
...
...
y = 24291913110989178430976188737249545579087378613222869573386912203346252820323082049282383949103585106721829807649174149449634419413458142252126463193146487010643610475854395865209122019323738578659400572370413775712692361379663967405425586254303600938942616843943488409309475119583856543802534171140392096218
you get one query to the oracle
m = 9
s = 2405166630956665237953658084678053324165883157595803783018465963045656567821106452762220201662313026405431445922421867778205437938725179586295551399807443
e = 8817315091133970070664765176290586050077392565114729059270141814832283708217649321046003732216932961113472534112976574969280719896582448272254838187836377
can you forge a signature?
m = 25314438212884162584121069893909753686458941721746907770211587969395420887840345365432202868511635194267014049140029699952322933552012002076923624112840884761581790235207955410899458374642840190417328918662885397961220265337305590620365689045929796432165299831808974900241783103469206719532643394780542865150
s = 2405166630956665237953658084678053324165883157595803783018465963045656567821106452762220201662313026405431445922421867778205437938725179586295551399807443
correct signature!
you win!
uiuctf{add1ti0n_i5_n0t_c0nc4t3n4ti0n}
```
Pretty much the only relevant python script I'd used for the challenge lol
```py
p = ENTER_P_VALUE_HERE
for _ in range(10):
    print("Use m pair", _, _+p)
```