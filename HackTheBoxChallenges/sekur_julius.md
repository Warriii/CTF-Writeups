### Sekur Julius
---

#### Files
`source.py`
```py
from random import choices
import os

def julius_encrypt(msg, shift):
    ct = ''
    for p in msg:
        if p == ' ':
            ct += '0'
        elif not ord('A') <= ord(p) <= ord('Z'):
            ct += p
        else:
            o = ord(p) - 65
            ct += chr(65 + (o + shift) % 26)
    return ct

def encrypt(msg, key):
    for shift in key:
        msg = julius_encrypt(msg, shift)
    return msg

msg = open('secret.txt').read().upper()
secure_key = os.urandom(1337)

with open('output.txt', 'w') as f:
    f.write(encrypt(msg, secure_key))

```

`output.txt`
```
JRYPBZR0GB0UNPXGUROBB0GJBGUBHFNAQGJRAGLSBHE!0GUVF0VF0N0CEBBS0BS0PBAPRCG0GB0CEBIR0LBH0GUNG0GUR0PNRFNE0PVCURE0VF0VAFRPHER0AB0ZNGGRE0UBJ0ZNAL0GVZRF0LBH0NCCYL0VG.0GUR0FRPHEVGL0BS0N0GUBHFNAQ0QVFGVAPG0FUVSGF0VF0RIRAGHNYYL0GUR0FNZR0NF0GUNG0BS0N0FVATYR0FUVSG.0RABHTU0ZHZOYVAT,0GNXR0LBHE0SYNT0NAQ0RAWBL0GUR0ERFG0BS0GUR0PBAGRFG.0ZNXR0FHER0LBH0JENC0GUR0SBYYBJVAT0GRKG0JVGU0GUR0UGO0SYNT0SBEZNG0GURRSSRPGVIRXRLFCNPRBSPNRFNEQRCRAQFBAGURFVMRBSGURNYCUNORG.
```
#### Writeup

We are given a source code used to encrypt a message as well as the encrypted output, in output.txt. `julius_encrypt()` may seem very difficult with its number of lines, but if we analyse it step by step we find it is describing a rather trivial function.

For every characcter `p` in the input `msg`, `julius_encrypt()` does the following:
```py
        if p == ' ':
            ct += '0'
```
- Replaces any `' '` spaces with `0`
```py
        elif not ord('A') <= ord(p) <= ord('Z'):
            ct += p
```
- Only changes characters from `A` to `Z`
```py
        else:
            o = ord(p) - 65
            ct += chr(65 + (o + shift) % 26)
```
- For a character from `A` to `Z`, it cycles through the alphabet by `shift` amount. We know this is the case because `chr(65) = 'A'`, thus `o` is really just how far is `p` from the first letter of the capital alphabet. Following which we increment it `shift` times, modulo it by 26 - the number of letters in the alphabet, then add back with `A` to recover the corresponding letter.

An easy way to demonstrate this is via running the following code in a python interpreter:
```
>>> chr(65)
'A'
>>> ord('B') - ord('A')
1
>>> ord('A') + 6
71
>>> chr(ord('A') + 6)
'G'
>>>
```
We will let the reader's intuition do the rest.

So, what we have is essentially a caesar cipher with some unknown key that is `shift`.

```py
msg = open('secret.txt').read().upper()
secure_key = os.urandom(1337)

with open('output.txt', 'w') as f:
    f.write(encrypt(msg, secure_key))
```

Even though the `shift` value is some `1337*8-bit` integer, because everything is done modulo 26, we only need to check for `shift = 0,1,2,...,25`. Decrypting the ciphertext with each shift and sieving through the outputs gives us the following:

```
WELCOME TO HACKTHEBOO TWOTHOUSANDTWENTYFOUR! THIS IS A PROOF OF CONCEPT TO PROVE YOU THAT THE CAESAR CIPHER IS INSECURE NO MATTER HOW MANY TIMES YOU APPLY IT. THE SECURITY OF A THOUSAND DISTINCT SHIFTS IS EVENTUALLY THE SAME AS THAT OF A SINGLE SHIFT. ENOUGH MUMBLING, TAKE YOUR FLAG AND ENJOY THE REST OF THE CONTEST. MAKE SURE YOU WRAP THE FOLLOWING TEXT WITH THE HTB FLAG FORMAT THEEFFECTIVEKEYSPACEOFCAESARDEPENDSONTHESIZEOFTHEALPHABET.
```
with `shift = 13`. Thus we get the flag, `HTB{THEEFFECTIVEKEYSPACEOFCAESARDEPENDSONTHESIZEOFTHEALPHABET}`

#### solve.py
```py
s = "JRYPBZR0GB0UNPXG..."

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
for key in range(26):
    new_s = ""
    for i in s:
        if i in ALPHABET:
            new_s += ALPHABET[ALPHABET.index(i) - key]
        else:
            new_s += i
    print(new_s.replace('0',' '), key)

# HTB{THEEFFECTIVEKEYSPACEOFCAESARDEPENDSONTHESIZEOFTHEALPHABET}
```