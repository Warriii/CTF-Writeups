![alt text](images/ptg.png)

The distributed files primarily revolves around `activator.py` which is rather beefy:

```py
import random
import sympy
from Crypto.Util.number import inverse
from Crypto.Hash import SHA1
from Crypto.Cipher import AES

ptr = 0

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_prime():
    global ptr
    while True:
        p = random.getrandbits(256)
        ptr += 1
        if sympy.isprime(p):
            return p

def generate_keys():
    while True:
        p = generate_prime() # feels like cado
        print(ptr)
        q = generate_prime()
        print(ptr)

        if p == q: # so different. ok
            print("SAME")
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537

        if gcd(e, phi) == 1:
            break
        print("NOT COPRIME")

    d = inverse(e, phi)
    return ((e, n), (d, n))

def verify(s, pubk):
    e, n = pubk
    return pow(s, e, n)

def sign(m, pk):
    d, n = pk
    return pow(m, d, n)

def encrypt(pk, otp, sqn):
    if sqn.bit_length() > 16 or otp.bit_length() > 256:
        return 0
    
    sqn_bin = f"{sqn:016b}"
    otp_bin = f"{otp:0256b}"   
    m = sqn_bin + otp_bin

    h = SHA1.new()
    h.update(m.encode())

    m = int(m, 2)
    s = sign(m, pk)
    return (s, h.hexdigest())

def activator(enc):
    pubk, pk = generate_keys()
    pubk_pin = (65537, 10418337868798443858901820790977066288221460515275090946243785628154408062569898328025289026686304809160241911029126122415897106930156444377187260816798137)

    s, h = enc

    if (int(s) == 0):
        return 0

    m = verify(s, pubk_pin)
    m_bin = f"{m:0272b}"

    h_ = SHA1.new()
    h_.update(m_bin.encode())

    if h != h_.hexdigest():
        return 0

    otp_a = random.getrandbits(256) 
    otp_a_bin = f"{otp_a:0256b}"

    otp_c = m_bin[16:272] 
    sqn = m_bin[:16]
    sqn = f"{int(sqn, 2) + 1:016b}" 

    if len(otp_c) != len(otp_a_bin):
        return 0

    sess_k = ''.join(str(int(a) ^ int(b)) for a, b in zip(otp_c, otp_a_bin))

    if len(sess_k) < 256:
        raise "C"

    sess_k = int(sess_k, 2).to_bytes(32, byteorder='big')
    iv = random.getrandbits(128).to_bytes(16, byteorder='big')
    
    aes = AES.new(sess_k, AES.MODE_CBC, iv)

    p = "authenticated. flag{not_a_real_flag}".encode()
    pad_len = 16 - (len(p) % 16)
    pad = bytes([pad_len] * pad_len)
    c = aes.encrypt(p + pad)

    return (encrypt(pk, otp_a, int(sqn, 2)), pubk, c, iv)

def card_terminal():
    pubk, pk =  bro,ken
    
    sqn = random.getrandbits(16)
    
    otp_c = random.getrandbits(256)
    otp_c_bin = f"{otp_c:0256b}"
    
    (s, h), pubk_pin, c, iv = activator(encrypt(pk, otp_c, sqn))
    if s == 0:
        return 0
    
    m = verify(s, pubk_pin)
    m_bin = f"{m:0272b}"
    otp_a_bin = m_bin[16:272]
    
    sess_k = ''.join(str(int(a) ^ int(b)) for a, b in zip(otp_c_bin, otp_a_bin))
    sess_k = int(sess_k, 2).to_bytes(32, byteorder='big')

    aes = AES.new(sess_k, AES.MODE_CBC, iv)
    p = aes.decrypt(c)

    pad_len = p[-1]

    if p[-pad_len:] != bytes([pad_len] * pad_len):
        return 0

    p = p[:-pad_len]

    print(p.decode('utf-8'))

if __name__ == "__main__":
    try:
        card_terminal() # auto breaks
    except Exception as e:
        # Allow for external card terminals
        try:
            (s, h), pubk_pin, c, iv = activator((int(input("s: ")), input("h: ")))
            print(s)
            print(pubk_pin)
            print(c.hex())
            print(iv.hex())
        except Exception:
            print("Invalid Input")
```

Upon establishing a connection to the server we have `card_terminal()` being called, but as we can see:

```py
def card_terminal():
    pubk, pk =  bro,ken
    ...
```

The function fails and triggers an exception, as `bro` nor `ken` are variables that were assigned values to begin with!

This triggers the Exception Handler in `__main__` which takes `(s, h)` as an input. It then calls `activator()`, and returns the output signature `s`, `pubk_pin`, ciphertext `c` and nonce value `iv`.

Looking into `activator()`, we observe:

1. `generate_keys()` is called which uses Python's random library to generate an RSA key. At the same time another RSA public key is initialised in `pubk_pin`
```py
def activator(enc):
    pubk, pk = generate_keys()
    pubk_pin = (65537, 10418337868798443858901820790977066288221460515275090946243785628154408062569898328025289026686304809160241911029126122415897106930156444377187260816798137)
    ...
```

Our inputs `s` and `h` are then verified to be legitimate. The details doesn't particularly matter as we can always generate a valid `h` given any input `s`.
```py
    ...
    s, h = enc

    if (int(s) == 0):
        return 0

    m = verify(s, pubk_pin)
    m_bin = f"{m:0272b}"

    h_ = SHA1.new()
    h_.update(m_bin.encode())

    if h != h_.hexdigest():
        return 0
    ...
```

Subsequently, `getrandbits()` is called to obtain a 256-bit random value `otp_a`. We also see the output from verifying `s` being used to initialise some `otp_c` and `sqn`. `sqn` seems to be used for verification purposes.

```py
    ...
    otp_a = random.getrandbits(256) 
    otp_a_bin = f"{otp_a:0256b}"

    otp_c = m_bin[16:272] 
    sqn = m_bin[:16]
    sqn = f"{int(sqn, 2) + 1:016b}" 

    if len(otp_c) != len(otp_a_bin):
        return 0
    ...
```

Lastly, `otp_c` and `otp_a` are xored together to form a 16-byte key `sess_k`. This is used to encrypt the flag using `AES.CBC`, of which the ciphertext `c` and nonce `iv` is provided.

```py
    ...
    sess_k = ''.join(str(int(a) ^ int(b)) for a, b in zip(otp_c, otp_a_bin))

    if len(sess_k) < 256:
        raise "C"

    sess_k = int(sess_k, 2).to_bytes(32, byteorder='big')
    iv = random.getrandbits(128).to_bytes(16, byteorder='big')
    
    aes = AES.new(sess_k, AES.MODE_CBC, iv)

    p = "authenticated. flag{not_a_real_flag}".encode()
    pad_len = 16 - (len(p) % 16)
    pad = bytes([pad_len] * pad_len)
    c = aes.encrypt(p + pad)

    return (encrypt(pk, otp_a, int(sqn, 2)), pubk, c, iv)
```

As we have `c`, `iv`, and can recover `otp_c` from any valid `(s,h)` pair that we generate and control, we're left with requiring `otp_a`. The problem here is that the one time pass is randomly generated, and even though Python's `random` library uses Mersenne Twister whose internal state can be recoverable, we require a lot more data points, and this challenge alone hardly provides us with any.

The key to our puzzle lies in the other value that is returned.

```py
encrypt(pk, otp_a, int(sqn, 2))
```

```py
def encrypt(pk, otp, sqn):
    if sqn.bit_length() > 16 or otp.bit_length() > 256:
        return 0
    
    sqn_bin = f"{sqn:016b}"
    otp_bin = f"{otp:0256b}"   
    m = sqn_bin + otp_bin

    h = SHA1.new()
    h.update(m.encode())

    m = int(m, 2)
    s = sign(m, pk)
    return (s, h.hexdigest())
```

This `encrypt()` call is made using the randomly generated RSA key that we were provided, which merges the `otp_a` and `sqn` parameters into `m`. It then calls `sign(m, pk)` which performs RSA decryption on the message.
```py
def sign(m, pk):
    d, n = pk
    return pow(m, d, n)
```

The problem lies in that in trying to encrypt `otp_a + sqn`, the code accidentally signs it instead! Signing without properly hashing the value that is to be signed allows for one to simply raise to the power of `e`, reversing the `^d` and thereby recovering `otp_a + sqn`!

By sending any valid `(s,h)` pair to the server, we evaluate our own `otp_c`, then recover `otp_a` from the incorrectly signed `otp_a`. We use `sqn`s to verify `otp_a`, then use it to recover the session key and thus, the flag!

`sol.py`

```py
from Crypto.Hash import SHA1
from Crypto.Cipher import AES

n = 10418337868798443858901820790977066288221460515275090946243785628154408062569898328025289026686304809160241911029126122415897106930156444377187260816798137
e = 65537

s = 231748378942379847289
m = pow(s, e, n)
m_bin = f"{m:0272b}"
h_ = SHA1.new()
h_.update(m_bin.encode())
h = h_.hexdigest()
# send values to server

otp_c = m_bin[16:272] 
sqn = m_bin[:16]
sqn_client = int(f"{int(sqn, 2) + 1:016b}", 2) 


# values retrieved from server
ss = 1130163737457838466591062294828532732322932466074644987692865711195357268992763408940510372570977801705674152372167154859378902753060652184462069202688560
e, nn = (65537, 1285418520836599727387450730304190618803624294548110088988340780736470056310122867453407421729308666930271800867680123942382080394981476265527928825165763)
ct = "189453e7f521facf19cf827deff35256bbfaf210ff4f15c5b960a3117771ce461721eae3b4bd8bffb5d114645f1403e5c6c5dd39a1dd7655904862c8939e781243f458cf1d8096cf985b837e45e95aab67b1778a9b38bd99497e4cd53984390b"
iv = "f8d2d3ff9fdfb73e4566cc7ea0a7aba2"

# solve for otp_a
mm = format(pow(ss, e, nn), f"0{16+256}b")
sqn_server = int(mm[:16], 2)
assert sqn_server == sqn_client
otp_a = mm[16:]

# recover session key and decrypt ciphertext
sess_k = ''.join(str(int(a) ^ int(b)) for a, b in zip(otp_c, otp_a))
sess_k = int(sess_k, 2).to_bytes(32, byteorder='big')
iv = bytes.fromhex(iv)
ct = bytes.fromhex(ct)
aes = AES.new(sess_k, AES.MODE_CBC, iv)
print(aes.decrypt(ct)) 
# b'authenticated. flag{Wh8aT_a_c7ur5sed_P2rotOcoL_and_O23,_her#Es_yoUr_Mil9kSha2kE}\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
```