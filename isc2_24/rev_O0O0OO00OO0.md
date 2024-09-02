### Rev - O0O0OO00OO0 (11 Solves, 970 pts)
```
0OOO00OO0OO0OOOO0OO0OO0O0OO00O0O0OO0OOOO0OO0OOO00OO00O0O00O000000OOO00O00OO0000O0OO0OOO000O000000OOO0O000OO0O0000OO0O00O0OOO00OO00O000000OO000OO0OO0OOOO0OO00O000OO00O0O00O000000OO0OOOO0OO0OOO000O000000OO0OO0O0OOOO00O00O000000OO00OO00OO0OO000OO0000O0OO00OOO00O0OO0000O000000OO0OOO00OO0OOOO0OOO0OOO00O000000OO0O00O0OOO0O000OOO00OO00O000000OO000OO0OO0OOOO0OO0OOO00OOO0O000OO00O0O0OO0OOO00OOO0O000OOO00OO00O000000OO0000O0OOO00O00OO00O0O00O000000OO0O00O0OOO00O00OOO00O00OO00O0O0OO000OO0OO0OOOO0OOO0OO00OO00O0O0OOO00O00OO0000O0OO000O00OO0OO000OO00O0O00O0000000OOO0OO00O0OO0O00OOO0OO

Author: warri
```

`O0O0OO00OO0.py`
```py
# This code was already run on flag.txt, its joever the flag's irrecoverable QnQ

def O0OOO0O000O0O0OOO0(O0OOO0O000O0O0OOO ):
    with open (O0OOO0O000O0O0OOO ,"rb")as OO0OO0O0000O000O0:
        O00OO00O00O0OOO0O=OO0OO0O0000O000O0. read ()
    return O00OO00O00O0OOO0O
def O000O0000O0O00OOO0(O000O0000O0O00OOO ):
    return (872 * O000O0000O0O00OOO+173 ) & 0x3c
def O0O0OO0OOO000O0O00():
    O0OO00O0000OO00 = "atxingml_f."
    return O0OO00O0000OO00[9:6:-2] + O0OO00O0000OO00[0::5]+ O0OO00O0000OO00[1:3] +O0OO00O0000OO00[1]
def O0O00OO0O0O0OO0OOO(O0O00OO0O0O0OO0OO ):
    O0O000OOOOO000O00 =3
    OOOO0O00O0OO00OO0 =[]
    O0O000OO0OO000O00 = 2
    for O0O000OO00OOOO00O in O0O00OO0O0O0OO0OO :
        OOOO0O00O0OO00OO0.append((O0O000OO00OOOO00O^ O0O000OOOOO000O00) + max(O0O00OO0O0O0OO0OO.index(O0O000OO00OOOO00O), O0O000OO0OO000O00) )
        O0O000OOOOO000O00 = O000O0000O0O00OOO0(O0O000OOOOO000O00)
        O0O000OO0OO000O00 = O0O000OO0OO000O00 +1
    return OOOO0O00O0OO00OO0
def O0O0OO0OOO000O0OO0(O0O0OO0OOO000O0OO ,O0O0O0O00OO00O00O ):
    with open (O0O0OO0OOO000O0OO ,"wb")as O0O0OOOO00OO0O000 :
        O0O0OOOO00OO0O000 .write (bytes (O0O0O0O00OO00O00O ))
def O0O0OO0OOO000O0OOO():
    O0OO00O0000OO0O = "atxingml_f"
    return O0OO00O0000OO0O[-2] + O0OO00O0000OO0O [8] + O0OO00O0000OO0O[6] + O0OO00O0000OO0O  [0] + O0OO00O0000OO0O[3:5] + 2* O0OO00O0000OO0O[8]


if __name__ ==O0O0OO0OOO000O0OOO():
    O0O0OO0OOO000O0OO0("flag.txt",O0O00OO0O0O0OO0OOO(O0OOO0O000O0O0OOO0("flag.txt")))
```

We have a rather...obfuscated bit of python code. The comment above implies that it was run on `flag.txt`, resulting in it getting encrypted into the distributed flag file - 

`flag.txt` (as python bytestring)
```
b'LzSCU_R\x80rJOPJKSTNvPXy\x85\x82\x92y\x8aT\x95K\x81\x8bt\x9ex\x9c\x89\x89cdl\x8dgo\x8f\x81\x8fm\x98\x9b\x86l\x88\xb2\xb5{u\x9d~\x7f\xa0\xaf'
```

Let's first start by dealing with all the `O0`s in the obfuscated code. We rename them to variables that make some sense and come up with the following:

```py
# This code was already run on flag.txt, its joever the flag's irrecoverable QnQ

def read_file(filename):
    with open (filename ,"rb")as f:
        file_data = f.read()
    return file_data

def next(x):
    return (872 * x + 173) & 0x3c

# def O0O0OO0OOO000O0O00(): # this code is unused
#     s = "atxingml_f."
#     return s[9:6:-2] + s[0::5]+ s[1:3] +s[1]

def encrypt(filedata):
    xor_key =3
    output =[]
    ptr = 2
    for character in filedata:
        output.append((character ^ xor_key) + max(filedata.index(character), ptr) )
        xor_key = next(xor_key)
        ptr = ptr +1
    return output

def write_file(filename ,filedata ):
    with open(filename ,"wb") as f :
        f.write(bytes(filedata))

def return__main__():
    s = "atxingml_f"
    return s[-2] + s[8] + s[6] + s[0] + s[3:5] + 2* s[8]


if __name__ ==return__main__():
    write_file("flag.txt",encrypt(read_file("flag.txt")))
```

So the original flag is read, then encrypted, and then rewritten into `flag.txt`. We just need to reverse the encryption function. We observe that in `encrypt()`, `max(filedata.index(character), ptr) )` will always return `ptr` which aids us in simplifying it further.

We then replicate `encrypt()` and reverse the encryption done to `flag.txt`

`solve.py`
```py
enc_flag = open("flag.txt","rb").read()

def next(x):
    return (872 * x +173 ) & 0x3c

i = 3
flag = ""
j = 2
for enc_char in enc_flag:
    flag_char = (enc_char - j) ^ i
    i = next(i)
    j += 1
    flag += chr(flag_char)
print(flag) # ISC2CTF{d3OO00OO0o0OobfuSc4t!ng_pYtho00Oo0On_l1ke_4_prO0oOOo}
```

