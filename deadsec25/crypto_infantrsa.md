## InfantRSA (160 Solves, 50 Pts)
```
Mandatory RSA challenge
```
`chall.py`
```py
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long
from secret import flag

p, q = getPrime(512), getPrime(512)
n = p * q
e = 65537
phi = (p-1) * (q-1)
hint = phi & ((1 << 500)-1)

m = bytes_to_long(flag)
c = pow(m, e, n)

print(f'{n=}')
print(f'{c=}')
print(f'{hint=}')
```
We have a standard RSA challenge where low bits of $\phi_n$ is given. To solve this, I implemented a Breadth First Search algorithm to recover the lower significant bits (LSBs) of $p$ and $q$ by comparing $LSB(pq)$ with $LSB(n)$ and $LSB(\phi_n)$.

`solve.py`
```py
n=144984891276196734965453594256209014778963203195049670355310962211566848427398797530783430323749867255090629853380209396636638745366963860490911853783867871911069083374020499249275237733775351499948258100804272648855792462742236340233585752087494417128391287812954224836118997290379527266500377253541233541409
c=120266872496180344790010286239079096230140095285248849852750641721628852518691698502144313546787272303406150072162647947041382841125823152331376276591975923978272581846998438986804573581487790011219372437422499974314459242841101560412534631063203123729213333507900106440128936135803619578547409588712629485231
hint=867001369103284883200353678854849752814597815663813166812753132472401652940053476516493313874282097709359168310718974981469532463276979975446490353988

queue = [('1', '1')]
for i in range(1,500):
    nq = []
    if len(queue) == 0:
        break
    for pbits, qbits in queue:
        p0, p1, q0, q1 = [int(j,2) for j in ['0'+pbits, '1'+pbits, '0'+qbits, '1'+qbits]]
        tn0, tn1, tn2, tn3 = [j % 2**i for j in [p0*q0, p1*q0, p0*q1, p1*q1]]
        th0, th1, th2, th3 = [j % 2**i for j in [(p0-1)*(q0-1), (p1-1)*(q0-1), (p0-1)*(q1-1), (p1-1)*(q1-1)]]
        rn, rh = n % 2**i, hint % 2**i
        if tn0 == rn and th0 == rh:
            nq.append(('0'+pbits, '0'+qbits))
        if tn1 == rn and th1 == rh:
            nq.append(('1'+pbits, '0'+qbits))
        if tn2 == rn and th2 == rh:
            nq.append(('0'+pbits, '1'+qbits))
        if tn3 == rn and th3 == rh:
            nq.append(('1'+pbits, '1'+qbits))
    queue = set(nq)

p_candidates = set(j[0] for j in queue)
print(len(p_candidates))
for p in p_candidates:
    for i in range(2**12):
        tp = int(p,2) + 2**500 * i
        if n % tp == 0:
            q = n // tp
            phi = (tp-1)*(q-1)
            d = pow(65537, -1, phi)
            m = pow(c, d, n)
            print(m.to_bytes(1024,"big").lstrip(b'\x00'))
            exit()
```

Of which we have 512 candidates of $p$ (or $q$). For each prime, we do a simple brute to guess the correct 12 most significant bits. Eventually one of them gives us the flag, `deadsec{1_w0nd3r_1f_7h15_p40bl3m_c0u1d_b3_s0lv3d_1f_m0r3_b1t7_w343_unKn0wn}`

And to answer that question, yes! From LSB of p, we just need an amount sufficient enough for Coppersmith to do the rest.