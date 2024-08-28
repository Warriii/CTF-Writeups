### Satisfiability 🩸 | 10 Solves 993 Points
```
Have you heard about Z3 or CVC5?

I'll be satisfied if you know how to use it :)

Author: Jin Kai
```

This challenge was blooded and solved by my teammate `elijah5399` the 🐐

We have another RE challenge with the source code provided to us;
```c
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>

bool check(char* flag) {
	if (
		((long)(flag[45] - flag[47] + flag[42] - flag[41] + flag[29] )== 154) &&
		((long)(flag[28] - flag[54] - flag[53] * flag[59] * flag[5] )== -1378125) &&
		((long)(flag[37] + flag[17] * flag[11] - flag[30] + flag[38] )== 10553) &&
		((long)(flag[22] - flag[2] * flag[35] + flag[19] - flag[49] )== -9499) &&
		((long)(flag[46] + flag[4] - flag[24] * flag[10] * flag[8] )== -955425) &&
		((long)(flag[36] * flag[3] * flag[55] * flag[23] + flag[44] )== 126674995) &&
		((long)(flag[25] * flag[6] + flag[18] * flag[20] * flag[39] )== 1051714) &&
		((long)(flag[56] * flag[21] - flag[7] - flag[57] + flag[40] )== 11953) &&
		((long)(flag[0] + flag[12] + flag[1] - flag[51] * flag[14] )== -4808) &&
		((long)(flag[58] * flag[50] - flag[27] - flag[52] - flag[32] )== 9609) &&
		((long)(flag[15] - flag[16] * flag[13] + flag[26] + flag[43] )== -10017) &&
		((long)(flag[9] - flag[34] + flag[31] * flag[33] - flag[48] )== 13335) &&
		((long)(flag[53] - flag[31] + flag[33] * flag[27] + flag[56] )== 10920) &&
		((long)(flag[35] - flag[24] + flag[5] + flag[6] + flag[1] )== 326) &&
		((long)(flag[28] + flag[50] * flag[23] * flag[18] - flag[38] )== 912300) &&
		((long)(flag[4] - flag[9] + flag[47] + flag[7] + flag[16] )== 337) &&
		((long)(flag[58] + flag[48] * flag[3] - flag[40] - flag[8] )== 11857) &&
		((long)(flag[45] + flag[20] + flag[21] + flag[34] + flag[52] )== 549) &&
		((long)(flag[54] * flag[13] + flag[41] - flag[37] - flag[36] )== 10793) &&
		((long)(flag[17] * flag[25] + flag[12] + flag[22] - flag[55] )== 7452) &&
		((long)(flag[2] + flag[46] * flag[19] - flag[43] + flag[32] )== 11323) &&
		((long)(flag[0] + flag[51] - flag[44] + flag[30] - flag[15] )== 61) &&
		((long)(flag[29] + flag[14] - flag[49] - flag[11] - flag[26] )== -104) &&
		((long)(flag[39] + flag[10] * flag[59] * flag[42] * flag[57] )== 192973597) &&
		((long)(flag[22] * flag[7] * flag[49] + flag[50] * flag[5] )== 1488699) &&
		((long)(flag[18] * flag[54] * flag[15] * flag[27] + flag[31] )== 114450418) &&
		((long)(flag[55] * flag[11] - flag[3] * flag[48] - flag[41] )== -1624) &&
		((long)(flag[30] - flag[4] * flag[17] + flag[19] * flag[1] )== -405) &&
		((long)(flag[51] * flag[57] - flag[29] + flag[2] - flag[21] )== 5756) &&
		((long)(flag[6] - flag[24] - flag[47] + flag[32] * flag[46] )== 11431) &&
		((long)(flag[45] * flag[14] - flag[35] + flag[42] * flag[52] )== 22262) &&
		((long)(flag[38] * flag[36] + flag[26] - flag[59] - flag[9] )== 11462) &&
		((long)(flag[23] * flag[0] - flag[56] - flag[40] + flag[12] )== 9677) &&
		((long)(flag[39] * flag[25] * flag[37] - flag[20] * flag[13] )== 818514) &&
		((long)(flag[16] - flag[28] * flag[33] + flag[44] + flag[43] )== -12856) &&
		((long)(flag[35] * flag[2] - flag[43] * flag[34] + flag[33] )== 3844) &&
		((long)(flag[40] - flag[53] * flag[21] - flag[23] - flag[10] )== -12373) &&
		((long)(flag[6] * flag[50] * flag[0] + flag[44] + flag[54] )== 968925) &&
		((long)(flag[36] + flag[45] - flag[47] - flag[39] + flag[7] )== 143) &&
		((long)(flag[5] * flag[9] + flag[3] - flag[16] + flag[52] )== 10293) &&
		((long)(flag[29] - flag[58] - flag[48] - flag[57] + flag[46] )== -85) &&
		((long)(flag[56] * flag[59] + flag[30] * flag[32] + flag[37] )== 23894) &&
		((long)(flag[41] - flag[27] + flag[19] * flag[4] + flag[42] )== 12176) &&
		((long)(flag[31] - flag[49] + flag[55] + flag[17] * flag[26] )== 8075) &&
		((long)(flag[22] * flag[12] - flag[13] + flag[28] - flag[51] )== 13423) &&
		((long)(flag[14] + flag[8] * flag[11] + flag[38] * flag[15] )== 22007) &&
		((long)(flag[25] * flag[20] + flag[1] - flag[18] - flag[24] )== 8481) &&
		((long)(flag[1] - flag[55] + flag[0] * flag[51] - flag[24] )== 5395) &&
		((long)(flag[13] - flag[2] - flag[11] + flag[4] + flag[26] )== 91) &&
		((long)(flag[16] + flag[22] - flag[40] - flag[23] * flag[10] )== -10727) &&
		((long)(flag[36] - flag[39] + flag[35] + flag[43] * flag[18] )== 5061) &&
		((long)(flag[44] * flag[27] + flag[57] - flag[56] + flag[7] )== 9141) &&
		((long)(flag[47] - flag[28] * flag[6] * flag[53] * flag[41] )== -108976780) &&
		((long)(flag[9] * flag[50] - flag[15] * flag[37] + flag[20] )== -2274) &&
		((long)(flag[33] - flag[12] + flag[17] + flag[58] + flag[54] )== 308) &&
		((long)(flag[30] * flag[32] - flag[25] + flag[46] - flag[59] )== 10820) &&
		((long)(flag[38] - flag[45] * flag[14] * flag[48] * flag[52] )== -101263535) &&
		((long)(flag[19] + flag[34] * flag[31] * flag[42] + flag[5] )== 1655743) &&
		((long)(flag[8] - flag[21] * flag[49] - flag[29] * flag[3] )== -27136) &&
		((long)(flag[26] + flag[0] * flag[55] * flag[48] - flag[24] )== 968716) &&
		((long)(flag[3] + flag[21] - flag[50] + flag[13] - flag[36] )== 118) &&
		((long)(flag[35] - flag[20] - flag[43] + flag[45] * flag[37] )== 12254) &&
		((long)(flag[34] + flag[6] - flag[33] + flag[47] + flag[17] )== 286) &&
		((long)(flag[32] + flag[57] - flag[2] + flag[12] - flag[16] )== 119) &&
		((long)(flag[29] * flag[14] * flag[18] * flag[22] - flag[49] )== 121150166) &&
		((long)(flag[46] + flag[5] - flag[52] - flag[51] + flag[23] )== 166) &&
		((long)(flag[54] - flag[42] - flag[4] - flag[7] + flag[41] )== -143) &&
		((long)(flag[27] + flag[59] * flag[19] * flag[58] * flag[30] )== 132300095) &&
		((long)(flag[38] * flag[11] + flag[40] - flag[10] + flag[53] )== 11112) &&
		((long)(flag[39] - flag[15] + flag[28] - flag[25] + flag[1] )== 141) &&
		((long)(flag[56] * flag[31] + flag[9] - flag[8] + flag[44] )== 12245)
	) {
		return true;
	} else {
		return false;
	}
}

int main() {
	char input[61];
	printf("flag? ");
	read(STDIN_FILENO, input, 60);
	if (check(input)) {
		puts("correct!");
	} else {
		puts("wrong!");
	}
}
```

It looks like `check()` takes our 60 byte flag and checks with numerous equations. From the `&&`s its clear that we must satisfy all of them for the flag checker to print `correct!`.

This challenge looks very reminiscient of a similar reversing challenge I'd made in a [past CTF](https://github.com/Lag-and-Crash/2024/tree/main/challenges/re/L1N3), but just as different in that while mine only used addition and did a bunch of typesetting shenanigans, multiplication was involved here :o (that said these challenges are very much different and involve slightly different methodologies)

Regardless, we have a series of equations and we need to find a solution set that solves them. Luckily, there exist high performance theorem provers such as [z3](https://ericpony.github.io/z3py-tutorial/guide-examples.htm). By taking these equations, we can feed them into a solver and have it solve for us!

With a bit of python magic we pipe our equations in and, voila!

```py
src_code = \
    """(flag[45] - flag[47] + flag[42] - flag[41] + flag[29] )== 154
		(flag[28] - flag[54] - flag[53] * flag[59] * flag[5] )== -1378125
        ...
        ...
        ...
		(flag[39] - flag[15] + flag[28] - flag[25] + flag[1] )== 141
		(flag[56] * flag[31] + flag[9] - flag[8] + flag[44] )== 12245"""

import z3
import time

# Initialise our unknowns
flag = [z3.Int(f'f_{i}') for i in range(60)]

# Start solver
sol = z3.Solver()

# Constraint 1 - range conditions
for f_item in flag:
    sol.add(0 <= f_item)
    sol.add(f_item <= 256)

# Constraint 2 - equations our flag must satisfy
for line in src_code.split("\n"):
    sol.add(eval(line))

# Constraint 3 - known flag parameters
for i,j in zip(flag, b'grey{'):
    sol.add(i == j)

# Start the solver
st = time.time()
print("Solving...")
sol.check()
m = sol.model()

# From the model, recover the values and output as flag
flag_str = ""
for i in flag:
    flag_str += chr(m[i].as_long())
print(f"Time taken: {time.time() - st} seconds")
print(f"{flag_str = }")
# Time taken: 1.6513004302978516 seconds
# flag_str = 'grey{i_learnt_all_about_SMT_solvers_today_z3_or_cvc5_is_god}'
```