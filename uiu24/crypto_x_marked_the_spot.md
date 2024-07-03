## X Marked the Spot (531 Solves, 93 Pts)
```
Author: Anakin

A perfect first challenge for beginners. Who said pirates can't ride trains...
```

I believe this was also solved by my teammate Yun. Let's take a look at the files and see what we can do...

`public.py`
```py
from itertools import cycle

flag = b"uiuctf{????????????????????????????????????????}"
# len(flag) = 48
key  = b"????????"
# len(key) = 8
ct = bytes(x ^ y for x, y in zip(flag, cycle(key)))

with open("ct", "wb") as ct_file:
    ct_file.write(ct)
```

`ct` is a bunch of raw bytes, but I've converted it to the following hexstring for reference:
```
1d0d1c121600111f5810361b17531e2e1c0c5a2e11125e031c3b0b0416395e1d5d5436050a5535420600485043474b0c
```

`itertools.cycle()` basically takes its input and just cycles through it over and over again. Thus, in this case we see that `ct` is just the flag xored with an 8 block key, akin to a block cipher.

In other words, supposing I have a key of length 4 with bytes. `b0 b1 b2 b3`. Given a plaintext `m0 m1 m2 m3 m4 m5 m6 m7`, the output ciphertext would be `m0 ^ b0, m1 ^ b1, m2 ^ b2, m3 ^ b3, m4 ^ b0, m5 ^ b1, ...`.

Since if `a ^ b = c`, then `b == a ^ c`, we derive the first 7 bytes of our key by xoring the known flag header `uiuctf{` with the first 7 bytes of `ct`. Because the flag length is a multiple of the key length, the last character of the flag, `}`, would be xored with the last byte of the key.

We leverage this to recover the full key and hence, the flag.

```py
from itertools import cycle
ct = bytes.fromhex("1d0d1c121600111f5810361b17531e2e1c0c5a2e11125e031c3b0b0416395e1d5d5436050a5535420600485043474b0c")
key = bytes(x ^ y for x, y in zip(b'uiuctf{}', ct[:7] + ct[-1:]))
flag = bytes(x ^ y for x, y in zip(ct, cycle(key)))
print(flag) # b'uiuctf{n0t_ju5t_th3_st4rt_but_4l50_th3_3nd!!!!!}'
```
