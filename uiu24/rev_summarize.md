## Summarize (161 Solves, 381 Pts)
```
Author: Nikhil

All you have to do is find six numbers. How hard can that be?
```

We are given an ELF binary. Analyzing it with IDA we arrive at the following pseudocode;

```cpp
__int64 __fastcall main(int a1, char **argv, char **a3)
{
  unsigned int v4; // [rsp+18h] [rbp-58h] BYREF
  unsigned int v5; // [rsp+1Ch] [rbp-54h] BYREF
  unsigned int v6; // [rsp+20h] [rbp-50h] BYREF
  unsigned int v7; // [rsp+24h] [rbp-4Ch] BYREF
  unsigned int v8; // [rsp+28h] [rbp-48h] BYREF
  unsigned int v9; // [rsp+2Ch] [rbp-44h] BYREF
  char s[56]; // [rsp+30h] [rbp-40h] BYREF
  unsigned __int64 v11; // [rsp+68h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  puts("To get the flag, you must correctly enter six 9-digit positive integers: a, b, c, d, e, and f.");
  putchar(10);
  printf("a = ");
  __isoc99_scanf("%d", &v4);
  printf("b = ");
  __isoc99_scanf("%d", &v5);
  printf("c = ");
  __isoc99_scanf("%d", &v6);
  printf("d = ");
  __isoc99_scanf("%d", &v7);
  printf("e = ");
  __isoc99_scanf("%d", &v8);
  printf("f = ");
  __isoc99_scanf("%d", &v9);
  if ( (unsigned __int8)check(v4, v5, v6, v7, v8, v9, argv) )
  {
    puts("Correct.");
    sprintf(s, "uiuctf{%x%x%x%x%x%x}", v4, v5, v6, v7, v8, v9);
    puts(s);
  }
  else
  {
    puts("Wrong.");
  }
  return 0LL;
}
```

`main()` is pretty straight forward, asking for 6 integers which it then parses through a `check()` function.

```cpp
_BOOL8 __fastcall check(
        unsigned int a1,
        unsigned int a2,
        unsigned int a3,
        unsigned int a4,
        unsigned int a5,
        unsigned int a6)
{
  unsigned int v1; // eax
  int v2; // ebx
  unsigned int v3; // eax
  unsigned int v4; // ebx
  unsigned int v5; // eax
  unsigned int v12; // eax
  unsigned int var_30; // [rsp+20h] [rbp-30h]
  unsigned int var_2C; // [rsp+24h] [rbp-2Ch]
  unsigned int v20; // [rsp+28h] [rbp-28h]
  unsigned int v21; // [rsp+2Ch] [rbp-24h]
  unsigned int v22; // [rsp+30h] [rbp-20h]
  unsigned int v23; // [rsp+34h] [rbp-1Ch]
  unsigned int v24; // [rsp+38h] [rbp-18h]
  unsigned int v25; // [rsp+3Ch] [rbp-14h]

  if ( a1 <= 100000000 || a2 <= 0x5F5E100 || a3 <= 0x5F5E100 || a4 <= 0x5F5E100 || a5 <= 0x5F5E100 || a6 <= 0x5F5E100 )
    return 0LL;
  if ( a1 > 999999999 || a2 > 0x3B9AC9FF || a3 > 0x3B9AC9FF || a4 > 0x3B9AC9FF || a5 > 0x3B9AC9FF || a6 > 0x3B9AC9FF )
    return 0LL;
  v1 = sub_4016D8(a1, a2);
  var_30 = (unsigned int)sub_40163D(v1, a3) % 17492321;
  var_2C = (unsigned int)sub_40163D(a1, a2) % 17381917;
  v2 = sub_4016FE(2u, a2);
  v3 = sub_4016FE(3u, a1);
  v4 = sub_4016D8(v3, v2);
  v20 = v4 % (unsigned int)sub_40174A(a1, a4);
  v5 = sub_40163D(a3, a1);
  v21 = (unsigned int)sub_4017A9(a2, v5) % 0x6E22;
  v22 = (unsigned int)sub_40163D(a2, a4) % a1;
  v12 = sub_40163D(a4, a6);
  v23 = (unsigned int)sub_40174A(a3, v12) % 0x1CE628;
  v24 = (unsigned int)sub_4016D8(a5, a6) % 0x1172502;
  v25 = (unsigned int)sub_40163D(a5, a6) % 0x2E16F83;
  return var_30 == 4139449
      && var_2C == 9166034
      && v20 == 556569677
      && v21 == 12734
      && v22 == 540591164
      && v23 == 1279714
      && v24 == 17026895
      && v25 == 23769303;
}
```
`check()` is a bit interesting. We see it take these 6 numbers and compute a bunch of mathematics on them, before returning a series of AND conditions on 8 different tests at the end. We also notice from the start that each variable / integer must be between `100000000` and `999999999`.

### Numerical Subroutines

We start with `sub_40163D()`;
```cpp
__int64 __fastcall sub_40163D(unsigned int a1, unsigned int a2)
{
  unsigned int v5; // [rsp+10h] [rbp-18h]
  char v6; // [rsp+14h] [rbp-14h]
  int v7; // [rsp+18h] [rbp-10h]
  int v8; // [rsp+1Ch] [rbp-Ch]
  __int64 v9; // [rsp+20h] [rbp-8h]

  v9 = 0LL;
  v5 = 0;
  v6 = 0;
  while ( a1 || a2 )
  {
    v7 = a1 & 1;
    v8 = a2 & 1;
    a1 >>= 1;
    a2 >>= 1;
    v9 += (v5 ^ v8 ^ v7) << v6;
    v5 = v5 & v7 | v8 & v7 | v5 & v8;
    ++v6;
  }
  return ((unsigned __int64)v5 << v6) + v9;
}
```

At first this seems rather scary and hard to perceive; While loops, bit shifting and bitwise operations, what exactly is going on here? Lets try and analyse this line by line.

```cpp
v5, v6 = 0, 0           // set two vars v5, v6 to be zero
while (a1 || a2)        // checks that either a1 or a2 is non zero

    v7 = a1 & 1         // takes the least significant bit (LSB) of a1
    v8 = a2 & 1         // repeat for a2

    a1 >>= 1; a2 >>= 1  // we shift a1, a2 to the right by one. This is equivalent to us doing (in python, a1 //= 2; a2 //= 2;). Notice this is the only thing that gets us closer to (a1 == 0 && a2 == 0), which would break the loop

    // so the while loop seems to process each bit of a1 and a2, until both a1 and a2 are 0. i.e. given a1 = 0b1101 and a2 = 0b1000, it gets (1,0), (0,0), (1,0), (1,1), after which both a1 and a2 are NULL which breaks the while loop

    v9 += (v5 ^ v8 ^ v7) << v6 // compute the bitwise xor of v7 and v8, the LSBs of a1 and a2, then xor it with v5. Notice that since the bitwise xor is done on 1-bit values, we can see xor as just a bit flipper. We then shift it to the right by v6 times

    v5 = v5 & v7 | v8 & v7 | v5 & v8;
    // this is a bit weird, but this essentially sets v5 to whether or not among the 3 variables, at least 2 of them contain 1

    ++v6; // increments v6 by 1

return (v5 << v6) + v9; // output
```

This might be hard to arrive at, but what this function does is that its essentially an adder.

Consider adding two numbers, 346 and 519 for instance. Without a calculator, one might resort to the following approach:

```
(the 1 at the top represents the carry over, since 6+9 = 15)
      1
    3 4 6
  + 5 1 9
  -------
    8 6 5   
```

We first take the ones digit, `6`, `9`, and add them together. This gets us `15`, of which the `1` is carried over to the tens. We repeat this process and arrive at our number eventually. The reason why we carry-over the `1` is because, well, `6+9 > 10`.

Notice how in base 2 or binary, the exact same thing is happening. From
`v9 += (v5 ^ v8 ^ v7) << v6`, we know `v7` and `v8` would be the binary "ones" or "tens" or "hundreds". Observe how `v7 ^ v8` would be simulating adding the binary values together (since 1 + 1 = 0b10, and 1 ^ 1 == 0 for instance), whereas `v5` represents the "carry-over" bit, which would only occur when the sum of the binary values is `0b10` or `0b11`, which would require 2 or more 1s!

`v6` on the other hand serves as a tracker to multiply the result by; Much like how we can express `346 + 519 = (6+9) * 1 + (4+1) * 10 + (3+5) * 100`, `<< v6` performs the `... * 1 + ... * 2 + ... * 4 + ...` in this case. By the time the function ends, `v9` represents the binary sum without any carry-over at the end, thus `(v5 << v6)` is added to make way for the last carry-over bit.

Thus, we can conclude `sub_40163D()` to be addition.

```cpp
__int64 __fastcall sub_4016D8(unsigned int a1, int a2)
{
  return sub_40163D(a1, (unsigned int)-a2);
}
```

Moving on to the other subroutines, `sub_4016D8()` calls `sub_40163D()` but flips the sign of the second parameter. Clearly this is doing subtraction.

```cpp
__int64 __fastcall sub_40174A(unsigned int a1, unsigned int a2)
{
  unsigned int v5; // [rsp+8h] [rbp-10h]
  int v6; // [rsp+Ch] [rbp-Ch]
  int v7; // [rsp+10h] [rbp-8h]
  int v8; // [rsp+14h] [rbp-4h]

  v5 = 0;
  v6 = 0;
  while ( a1 || a2 )
  {
    v7 = a1 & 1;
    v8 = a2 & 1;
    a1 >>= 1;
    a2 >>= 1;
    v5 += (v8 ^ v7) << v6++;
  }
  return v5;
}
```

Through similar logic, we observe that `sub_40174A()` is doing numerical bitwise xor.

```cpp
__int64 __fastcall sub_4017A9(unsigned int a1, unsigned int a2)
{
  unsigned int v5; // [rsp+8h] [rbp-10h]
  int v6; // [rsp+Ch] [rbp-Ch]
  int v7; // [rsp+10h] [rbp-8h]
  int v8; // [rsp+14h] [rbp-4h]

  v5 = 0;
  v6 = 0;
  while ( a1 || a2 )
  {
    v7 = a1 & 1;
    v8 = a2 & 1;
    a1 >>= 1;
    a2 >>= 1;
    v5 += (v8 & v7) << v6++;
  }
  return v5;
}
```

While `sub_4017A9()` is just numerical bitwise and.

```cpp
__int64 __fastcall sub_4016FE(unsigned int a1, int a2)
{
  unsigned int v4; // [rsp+Ch] [rbp-Ch]
  int v5; // [rsp+10h] [rbp-8h]

  v4 = 0;
  v5 = 0;
  while ( a1 )
  {
    v4 += (a1 & 1) * (a2 << v5);
    a1 >>= 1;
    ++v5;
  }
  return v4;
}
```

The last subroutine left to analyse is `sub_4016FE()`. We observe that in place of checking for both `a1` and `a2`, the while loop only checks for `a1` and with each LSB of `a1`, if it is a `1`, adds `v4` by `a2 << v5`, i.e. `v4 += a2 * 2**v5`.

Consider what happens if I call `sub_4016FE(11, 981)`. `11` in binary is `0b1011`. We can use a table to trace the values of `v4` and `a1` and `v5` as we go through the start of every iteration within the while loop:

v4|a1 (in binary)|v5
--|--|--
`0`|`1011`|`0`
`981*1`|`101`|`1`
`981*1 + 981*2`|`10`|`2`
`981*1 + 981*2 + 0*4`|`1`|`3`
`981*1 + 981*2 + 0*4 + 981*8`|` `|`4`

And at the end, the while loop breaks and `v4 = 981x1 + 981x2 + 981x4` is returned. Notice how `v4 = 981x1 + 981x2 + 0x4 + 981x8 = 981x(1+2+8) = 981x0b1011`? Clearly `sub_4016FE()` is just numerical multiplication in disguise!

### Solving the System

With all of our subroutines done, we can finally relook at `check()` in a better light;

```cpp
if ( a1 <= 100000000 || a2 <= 0x5F5E100 || a3 <= 0x5F5E100 || a4 <= 0x5F5E100 || a5 <= 0x5F5E100 || a6 <= 0x5F5E100 )
    return 0LL;
  if ( a1 > 999999999 || a2 > 0x3B9AC9FF || a3 > 0x3B9AC9FF || a4 > 0x3B9AC9FF || a5 > 0x3B9AC9FF || a6 > 0x3B9AC9FF )
    return 0LL;
  v7 = subtraction(a1, a2);
  v18 = addition(v7, a3) % 17492321;
  v19 = addition(a1, a2) % 17381917;
  v8 = multiplication(2u, a2);
  v9 = multiplication(3u, a1);
  v10 = subtraction(v9, v8);
  v20 = v10 % bitwise_xor(a1, a4);
  v11 = addition(a3, a1);
  v21 = bitwise_and(a2, v11) % 0x6E22;
  v22 = addition(a2, a4) % a1;
  v12 = addition(a4, a6);
  v23 = bitwise_xor(a3, v12) % 0x1CE628;
  v24 = subtraction(a5, a6) % 0x1172502;
  v25 = addition(a5, a6) % 0x2E16F83;
  return v18 == 4139449
      && v19 == 9166034
      && v20 == 556569677
      && v21 == 12734
      && v22 == 540591164
      && v23 == 1279714
      && v24 == 17026895
      && v25 == 23769303;
```

We can simply express this system of constraints into z3 and have it solve for the unknown variables. Since the integers in c/cpp (in the context of the binary) are 32-bit integers, we use `z3.BitVec(NAME,32)` to express our unknowns.

We then insert in the required checks, and run it to obtain our solution set.

`summ.py`
```py
from z3 import *

BITS = 32
s = Solver()
a,b,c,d,e,f = BitVec('a',BITS), BitVec('b',BITS), BitVec('c',BITS), BitVec('d',BITS), BitVec('e',BITS), BitVec('f',BITS)
vs = [a,b,c,d,e,f]
for v in vs:
    s.add(v < 999999999)
    s.add(v >= 100000000)

s.add( (a-b+c) % 17492321 == 4139449)
s.add( (a+b) % 17381917 == 9166034)
s.add( (3*a - 2*b) % (a^d) == 556569677)
s.add( ((c + a) & b) % 0x6E22 == 12734)
s.add( (b + d) % a == 540591164)
s.add( ((d + f) ^ c) % 0x1CE628 == 1279714)
s.add( (e - f) % 0x1172502 == 17026895)
s.add( (e + f) % 0x2E16F83 == 23769303)

s.check()
print(s.model())
```

```
python3 summ.py
[d = 465893239,
 c = 341222189,
 a = 705965527,
 b = 780663452,
 f = 217433792,
 e = 966221407]
```

We input these exact numbers into the binary and obtain our flag.
```
./summarize

To get the flag, you must correctly enter six 9-digit positive integers: a, b, c, d, e, and f.

a = 705965527
b = 780663452
c = 341222189
d = 465893239
e = 966221407
f = 217433792
Correct.
uiuctf{2a142dd72e87fa9c1456a32d1bc4f77739975e5fcf5c6c0}
```






