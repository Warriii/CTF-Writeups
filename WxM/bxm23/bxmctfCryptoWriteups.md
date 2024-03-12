
<h2>I Can't Beelieve It</h2>
Crypto 1

Flag: `ctf{allknown}`

---

We are given a text file containing the following.
```text
Kings and queens, their roles well-defined,
Nectar they gather, nature's sweetest find.
Opulent honeycombs, a golden treasure,
We marvel at their intricate measure.
Nurturing their young, a family affair,
Ending our exposition here, beware.

Cautiously, bees buzz through the air,
Together they work, a hive to share.
Flowers they find, a vital mission,
And in their flight, a colorful rendition.
Life in motion, nature's great ballet,
Let's explore the world of the Bee Movie today!
```

The flag is formed by taking the first letter of each line from the second, then the first stanza. This gets `CTFALLKNOWNE`. Seeing that the `E` is referring to `End`, we remove the `E` and format the flag to `CTF{allknown}`


<h2>Where Snakes Die</h2>
Crypto 2

Flag: `ctf{tabsoverspaces}`

---

We have a text file that oddly enough, contains this:
```text
	 	 |	|  	 |	| 	|	   |   |			|   	| | 	 |   | 		 | 	|	 	 | |   
```

This seems odd, theres so much blank in there and hardly any info on the flag. We can putting it in `hexed.it` or any hex editor to obtain the following hexdump:
```
0x09, 0x20, 0x09, 0x20, 0x7C, 0x09, 0x7C, 0x20, 0x20, 0x09, 0x20, 0x7C, 0x09, 0x7C, 0x20, 0x09, 0x7C, 0x09, 0x20, 0x20, 0x20, 0x7C, 0x20, 0x20, 0x20, 0x7C, 0x09, 0x09, 0x09, 0x7C, 0x20, 0x20, 0x20, 0x09, 0x7C, 0x20, 0x7C, 0x20, 0x09, 0x20, 0x7C, 0x20, 0x20, 0x20, 0x7C, 0x20, 0x09, 0x09, 0x20, 0x7C, 0x20, 0x09, 0x7C, 0x09, 0x20, 0x09, 0x20, 0x7C, 0x20, 0x7C, 0x20, 0x20, 0x20, 0x0A
```

Notice how there's `0x09`s and `0x20`s as two bits that encode the flag, with `0x7c` (the `|` character) acting as some separator.

The values in between the `0x7c`s are around 1-4 chars long, which eliminates the possibility of it being some form of `ASCII` or odd base encodng.

The first form of encoding that easily comes to mind is morse. Any adhoc python code to convert it (or manual conversion, either works and takes about the same time really)
```py
f = open('clue.txt','r').read()
for i in f:
    if i == '\t':
        print('-',end="")
    elif i == ' ':
        print('.',end="")
    else:
        print(" ",end="")
```
Nets us 
```-.-. - ..-. - .- -... ... --- ...- . .-. ... .--. .- -.-. . ...```, 

which translates to `CTFTABSOVERSPACES`, hence the flag `ctf{tabsoverspaces}`

<h2>RAID Safety Assays, But Fixed</h2>
Crypto 3

Flag: `ctf{cryptpainfulflag}`

---

The challenge provides us with the following RSA values:
```py
e = 65537
n = 4629059450272139917534568159172903078573041591191268130667
c = 6743459147531103219359362407406880068975344190794689965016
```

Alongside python code `main.py`
```py
from Crypto.Util.number import *
import random

p = getPrime(96)
q = getPrime(96)
n = p*q
e = 65537

flag = b'ctf{0000000000000000}'
flag = str(pow(bytes_to_long(flag), e, n))

perm = list(range(10))
random.shuffle(perm)
perm = list(map(str, perm))

c = ''.join([perm[int(x)] for x in flag])

print(f'e = {e}')
print(f'n = {n}')
print(f'c = {c}')
```

A quick run of `factor(n)` in SageMath nets us the prime factors p=`62682123970325402653307817299` and q=`73849754237166590568543300233`

And hence d = `pow(e,-1,(p-1)*(q-1))` as is standard RSA Decryption. We can then use `pow(c,d,n)` to get the original plaintext, but there is a problem.

As seen in `main.py`, a list `perm` containing values from 0 to 10 is shuffled randomly, and then each digit in the encrypted flag `c` is substituted with its corresponding value in `perm`.

We can bruteforce all perms using `itertools.permutations` and test all possible variants until we get the flag. This brute force can be made faster knowing that the `6` in c must be replaced by any number from `0` to `4` so that the original c is less than n to begin with, but standard brute force is more than sufficient to get the flag. And so we have the following solve script:

```py
e = 65537
n = 4629059450272139917534568159172903078573041591191268130667
c = 6743459147531103219359362407406880068975344190794689965016
p= 62682123970325402653307817299
q= 73849754237166590568543300233
d = pow(e,-1,(p-1)*(q-1))

from Crypto.Util.number import *
from itertools import permutations

perms = list(permutations(range(10)))
for perm in perms:
    c0 = int(''.join([str(perm[int(i)]) for i in str(c)]))
    m0 = pow(c0,d,n)
    flag = long_to_bytes(m0)
    if flag.startswith(b'ctf{'):
        print(flag, perm)
        break
```

Giving us the flag `ctf{cryptpainfulflag}` with permutation `(7, 9, 1, 6, 4, 0, 2, 5, 8, 3)`

<h2>Super Secure Shreddng</h2>
Crypto X

Flag: `Unknown` (at least I think its unsolvable, see below)

---

For a crypto challenge, this felt more of a `Rev/Forensics` chall.

I was not able to get the contents of the zip file again before the challenge was removed, but in essence we have a private `secret.mp3` file. The author of the challenge then ran

```bash
$ python3 src/visualiser.py -e diff -r gif -f shred secret.mp3 public.gif
Bytes: 34839
Entropy: 7.3142
```

and left us with a `public.gif` file.

We also have a github link, https://github.com/slightlyskepticalpotat/file-visualiser that is used to strip the mp3 file.

Looking at the github we can put together the following:
1. `src/visualiser.py` reads all the bytes from the mp3
2. It then computes a separate byte array containing the differences between every consecutive byte in the mp3
3. For every 3 bytes in said difference array, it represents them as a pixel colour in an RGB image, then creates 24 of them as frames that it later saves as a gif

This makes reversing what has been done simple. We just need to extract each frame from the .gif file, obtain the byte data of the pixels, then guessing the magic byte / starting byte of `mp3` files to be either `0xff` or `0x49`, (https://en.wikipedia.org/wiki/List_of_file_signatures), reconstruct the original mp3 file.

Except, here's the problem. As pointed out by Neobeo in the discord server, there exists a concept called `gif quantisation`. It is a process that reduces the number of distinct colors used in an image, for instance reducing an image of say, 256 different colours to 16.

In gifs, color quantization is often used as gif files support up to 256 colors. See the issue?

For every 3 bytes worth of possible original input file data, which is put into a single RGB pixel, saving it as a gif has reduced it to a single byte's worth of data.

Which means every pixel could represent 256^2 possible combinations of 3-byte data, on average. The space and time complexities of bruteforcing 256^2 for every single pixel is impossible to do, which makes recovering the original mp3 file impossible.



<h2> ICS5U </h2>
Rev 2

Flag: `ctf{2029395652961987395}`

---

The main reason why I'm including this here is due to how it has a little bit of crypto in it, which is quite interesting. The realm of cryptography not just covers encryption and decryption methods, ancient ciphers etc. but also involves discrete mathematics and modular arithmetic. In this case, some bit of programming and reversing is needed, but more importantly there is a need to know two mathematical concepts.

`Fermat's Little Theorem`, which states that for any integer `a` coprime to any prime `p`, `pow(a,p-1,p) == a % p`

This theorem itself is the basis for a common Primality Testing Method known as the `Fermat Primality Test`.

The test states that if p is prime and a is not divisible by p, then
`a^(p-1) == 1 (mod  p)`. If one wants to test whether p is prime, then we can pick random integers a not divisible by p and see whether the equality holds. If the equality does not hold for a value of a, then p is composite. This congruence is unlikely to hold for a random a if p is composite. Therefore, if the equality does hold for one or more values of a, then we say that p is probably prime.

The second concept to know is of `Carmichael numbers`, but we'll get into that later.

And so we move on to the challenge. We are given 3 items. Namely,

clue.txt
```text
JEQHO33OMRSXELROFYQHO2DBOQQGC4TFEB2GQZJAMZUXE43UEBTG65LSEBXHK3LCMVZHGIDPMYQHI2DFEBZWC3LFEB2HS4DFEBQXGIDJNYQCE4DVPJ5GYZJOOBUHAIRAORUGC5BAMFZGKIDHOJSWC5DFOIQHI2DBNYQDCIDUOJUWY3DJN5XC4LRO
```
which can be Base32 decrypted via tools such as Cyberchef to obtain
```text
I wonder... what are the first four numbers of the same type as in "puzzle.php" that are greater than 1 trillion...
```

This brings us to the second item, `puzzle.php`, which contains 4 functions. We'll be looking at them individually.

Firstly, we have `alpha($a, $b)`
```php
<?php

/* Hmm, what does this program seem to do? */

function alpha($a, $b)
{
    if ($a < $b)
    {
        return alpha($b, $a);
    }
    
    if ($a % $b == ($a ^ $a))
    {
        return $b;
    }
    
    return alpha($b, $a % $b);
}
...
```

`alpha()` takes in two inputs `a` and `b`, and ensures that the former input is greater than the second. It then returns `b` if `b` divides `a`, else it calls itself with variables `b` and `a % b`. (note that `a ^ a == 0` for all `a` as is the `xor` operation)

It might be hard to notice, but this is equivalent to the Greatest Common Divisor, or `gcd()` algorithmn, which computes the greatest divisor between two numbers.

```php
...
function beta($x, $y, $z)
{
    $ans = 1;

    if ($y & 1 != 0)
    {
        $ans = $x;
    }

    while ($y != 0)
    {
        $y >>= 1;
        $x = ($x * $x) % $z;

        if ($y & 1 != 0)
        {
            $ans = ($ans * $x) % $z;
        }
    }

    return $ans;
}
...
```
`beta()` takes in 3 inputs this time, and returns a variable `ans`. If `y` is odd, it sets `ans` to `x` and if not, keeps it at `1`. It then moves through the bits of `y`, and for every nth bit in `y`, it multiplies `x` by itself modulo `z`. If the nth bit is odd, it multiplies `ans` by `x` modulo `z`.

Notice how for a sample `y` = `0b10011`, we trace `ans` to be 
```py
ans = (x * (x*x) * (((x*x)*(x*x))*((x*x)*(x*x)))*(((x*x)*(x*x))*((x*x)*(x*x))) ) % z
    = (x * (x**2) * (x**16) ) % z
    = (x ** 19) % z
    = (x ** y) % z
```
Note that modulo arithmetic has a property whereby:

`a*b mod n == (a mod n * b mod n) mod n`, which enables us to express `ans` like so.

This leads to the conclusion that `beta` is the equivalent of `modular exponentiation`, which essentially returns `pow(x,y,z)` in python. x is the base, y is the exponent and z is the modulus.


```php
...
function gamma($n)
{
    for ($_ = 2; $_ <= $n; ++$_)
    {
        
        if (alpha($_, $n) == 1)
        {
            
            if (beta($_, $n - 1, $n) != 1)
            {
                return 0;
            }
        }
    }
    
    return 1;
}
...
```

`gamma()` is slightly more complicated and uses both `alpha()` (gcd) and `beta()` (powmod) algorithmns. For a given number n, it iterates through all possible values `_` from 2 to n. If `gcd(_,n) == 1`, and if `powmod(_, n-1, n) != 1`, it immediately returns 0. Else, it returns 1.

So for the function to return 0, there must exist some integer `_` less than `n` and more than `1` such that both `_` and `n` are coprime, AND `pow(_,n-1,n) != 1`. Recall Fermat's Little Theorem and the Fermat's Primality Test? One might be too hasty to jump to the conclusion that `gamma()` just tests if `n` is prime.

But that's not always the case. `gamma()` filters only primes yes, but it also fails to filter out certain composite numbers. There do exist non primes x where for all integers a below it that are > 1, `pow(a,x-1,x) == 1`. These numbers, naturally gifted to spoof themselves as primes per the Fermat Primality Test, are known as `carmichael numbers`.

So basically `gamma()` returns True for any prime or carmichael number. If anything above confuses you, just know that it does just that.
```php
...
function init($n)
{
    $check = (gamma($n) == 1 ? true : false);

    if ($check)
    {
        echo('YES');
    }

    else
    {
        echo('NO');
    }
}

?>
```

Evidently `init()` just calls `gamma()` on your input and returns if it is a prime/carmichael number or no.

Now, from `clue.txt`, the first four numbers, naturally, would be the first 4 primes above 10**12. Or `clue.txt` is partly wrong and isn't to be trusted, and instead you're supposed to throw in the first 4 `carmichael numbers` greater than one trillion. We'll see which is which as we move on to `main.cpp`.

Another issue with the `php` code is that...`php` kinda 'self-destructs' with big number inputs, meaning `beta(x,y,z)` just returns 0 for extremely large x,y,z. And this applies very much so to inputs > one trillion, where the line `$x = ($x * $x) % $z;` literally returns 0 since php cannot handle the overflow for some reason. We'll ignore this and assume hypothetically it does not fail us.

Last but not least, we have `main.cpp`

```cpp
#include <bits/stdc++.h>
using namespace std;

int64_t manipulate(const string &input)
{
    const int32_t SZ = input.size(), B1 = 131, B2 = 13, K = 1e9 + 7;
    int64_t fh[SZ], fs[SZ], pw1[SZ], pw2[SZ];
    for (int i = 0; i < SZ; ++i) fh[i] = fs[i] = 0;
    pw1[0] = pw2[0] = 1;
    for (int _ = 1; _ <= SZ; ++_)
    {
        pw1[_] = pw1[_-1] * B1 % K;
        pw2[_] = pw2[_-1] * B2 % K;

        fh[_] = (fh[_-1] * B1 + input[_-1]) % K;
        fs[_] = (fs[_-1] * B2 + input[_-1]) % K;
    }

    int64_t f = (fh[SZ] - fh[0] * pw1[SZ] % K + K) % K;
    int64_t s = (fs[SZ] - fs[0] * pw2[SZ] % K + K) % K;

    return (f << 31) ^ s;
}

int main()
{
    while (true)
    {
        printf("Error. Login Required.\n");
        printf("Please enter the corresponding passcodes to proceed.\n");

        int64_t a, b, c, d;

        printf("Enter \'a\'\n");
        cin >> a;

        printf("Enter \'b\'\n");
        cin >> b;

        printf("Enter \'c\'\n");
        cin >> c;

        printf("Enter \'d\'\n");
        cin >> d;

        int64_t x = manipulate(to_string(a));
        int64_t y = manipulate(to_string(b));
        int64_t z = manipulate(to_string(c));
        int64_t w = manipulate(to_string(d));

        int64_t token = manipulate(to_string(x + y + z + w));
        cout << "ctf{" << to_string(token) << "}\n";
    }
}
```

If it hasn't been made clear we need first 4 numbers where `init()` works from `puzzle.php`, as per `clue.txt`. But, entering the first 4 primes, being 
```
1000000000039
1000000000061
1000000000063
1000000000091
```
nets us `ctf{702781500672167564}`, which is an incorrect flag.

Instead, trying the first 4 `carmichael numbers` above one trillion, being
```
1000151515441
1000321709401
1000642078801
1001102784001
(https://oeis.org/A002997/b002997.txt)
```
nets us the correct flag, `ctf{2029395652961987395}`.