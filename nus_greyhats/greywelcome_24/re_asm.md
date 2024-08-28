### ASM | 12 Solves 990 Points
```
I wrote a program to generate the flag, but it's too slow. Can you help me speed it up?

Author: jro
```

`vm.py`
```py
import sys, hashlib

class VM:
    def __init__(self, memory_size=256):
        self.memory = [0] * memory_size
        self.registers = {
            "ZERO": 0, "ONE": 1,
            'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0,
            'R4': 0, 'R5': 0, 'R6': 0, 'R7': 0
        }
        self.pc = 0
        self.zero_flag = False
        self.instructions = {
            'ADD': self.add,
            'SUB': self.sub,
            'XOR': self.xor,
            'LOAD': self.load,
            'STORE': self.store,
            'INPUT': self.input,
            'HALT': self.halt,
            'MOV': self.mov,
            'CMP': self.cmp,
            'JMP': self.jmp,
            'JE': self.je,
            'JNE': self.jne,
            'PRINT': self.print,
            'PRINTFLAG': self.printflag,
            'INC': self.inc,
            'DIV': self.div,
            'MOD': self.mod
        }

    def add(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] + self.registers[src2]

    def sub(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] - self.registers[src2]

    def xor(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] ^ self.registers[src2]

    def load(self, dest, addr):
        self.registers[dest] = self.memory[addr]

    def store(self, src, addr):
        self.memory[addr] = self.registers[src]

    def input(self, dest):
        self.registers[dest] = ord(sys.stdin.read(1))

    def halt(self):
        sys.exit(0)

    def mov(self, dest, value):
        if value in self.registers:
            self.registers[dest] = self.registers[value]
        else:
            self.registers[dest] = int(value)

    def cmp(self, src1, src2):
        self.zero_flag = (self.registers[src1] == self.registers[src2])

    def jmp(self, offset):
        self.pc += int(offset) - 1  # -1 because pc will be incremented after this

    def je(self, offset):
        if self.zero_flag:
            self.jmp(offset)

    def jne(self, offset):
        if not self.zero_flag:
            self.jmp(offset)

    def print(self, src):
        if src in self.registers:
            print(self.registers[src], end=' ')
        else:
            print(src.strip('"'), end='')
    
    def printflag(self, src):
        # :)
        flag_enc = b'\xca (:\xda\x1f\xea\xd5q+;\x8a\x82\xeb\xaa\t\x86\x12\xec\x83\xc3d0'
        if src in self.registers:
            h = hashlib.sha1(str(self.registers[src]).encode()).digest() * 2
            print(bytes(a^b for a, b in zip(flag_enc, h)))

    def inc(self, dest):
        self.registers[dest] += 1

    def div(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] // self.registers[src2]

    def mod(self, dest, src1, src2):
        self.registers[dest] = self.registers[src1] % self.registers[src2]

    def run(self, program):
        self.pc = 0
        while self.pc < len(program):
            line = program[self.pc]
            # print(line)
            parts = line.strip().split(' ')
            if not parts:
                self.pc += 1
                continue
            opcode = parts[0].upper()
            if opcode in self.instructions:
                args = parts[1:]
                # print(args)
                self.instructions[opcode](*args)
            else:
                print(f"Unknown instruction: {opcode}")
                sys.exit(1)
            self.pc += 1

def main():
    program = [
        "MOV R2 31337",
        "MOV R5 2410",
        "MOV R0 2",
        "MOV R1 1",
        "MOV R3 0",
        "MOD R4 R0 R1",
        "CMP R4 ZERO",
        "JNE 2",
        "ADD R3 R3 R1",
        "INC R1",
        "CMP R1 R0",
        "JNE -6",
        "CMP R0 R3",
        "JNE 4",
        "MOD R4 R0 R2",
        "CMP R4 R5",
        "JE 3",
        "INC R0",
        "JMP -15",
        "PRINTFLAG R0",
        "HALT"
    ]
    vm = VM()
    vm.run(program)

if __name__ == "__main__":
    main()
```

This is rather interesting. We're given a custom assembly that's simulated using Python! These instructions seem very resembling of Intel's architecture, with stuff like `cmp` and `jmp` etc. We can also do some reversing to see what each of the instructions truly mean.

After some reading we can arrive at the following:
```py
> START
R2 = 31337
R5 = 2410
R0 = 2

> LOOP_2
R1 = 1
R3 = 0

> LOOP_1
R4 = R0 % R1
IF R4 == 0: # JNE 2
    R3 = R3 + R1
R1 += 1
IF R1 != R0:
    GOTO LOOP_1 # JNE -6

IF R0 != R3:
    R0 += 1
    GOTO LOOP_2 # JMP -15
R4 = R0 % R2
IF R4 != R5:
    R0 += 1
    GOTO LOOP_2 # JMP -15

PRINTFLAG(R0)
> END
```

Evidently an inner `LOOP_1` occurs, and then the values of `R0` and `R3` are piped into two checks. If it passes the two checks, the flag is printed with `R0` as its input variable and the program ends. Running `vm.py` seems to take forever, so we'll have to find a way to simplify this.

Looking at the inner `LOOP_1` first we find that when it begins, `R3 = 0` and `R1 = 1`. We also see that `R1` is incremented till `R0`, and if `R1` is a factor of `R0`, `R3` is added by the value of `R1`. So `R3 = sum(factors of R0) - R0` as we exclude `R0` which is a factor of itself. There is a term in number theory used to describe this, known as the [aliquot sum](https://en.wikipedia.org/wiki/Aliquot_sum).

After removing some unnecessary variables we can now further simplify our assembly into;

```py
> START
R0 = 2

> LOOP_2
R3 = sum(factors of R0) - R0 # LOOP_1 simplified
IF R0 != R3:
    R0 += 1
    GOTO LOOP_2 # JMP -15
R4 = R0 % 31337
IF R4 != 2410:
    R0 += 1
    GOTO LOOP_2 # JMP -15

PRINTFLAG(R0)
> END
```

`R0` is slowly incremented from 2 onwards till it satisfies the two if statements. These two statements require that;

1. `R3 == R0`, thus the sum of factors of R0 == 2*R0
2. `R0` % 31337 == 2410

With a bit of research we find that values of `R3` that satisfies the first condition are known as [perfect numbers](https://en.wikipedia.org/wiki/Perfect_number). Using the [The On-Line Encyclopedia of Integer Sequences (OEIS)](https://oeis.org/) we find a list of perfect numbers in [A000396](https://oeis.org/A000396). 

Whereupon we find a list for the first 15 perfect numbers;
```
1 6
2 28
3 496
4 8128
5 33550336
6 8589869056
7 137438691328
8 2305843008139952128
9 2658455991569831744654692615953842176
10 191561942608236107294793378084303638130997321548169216
```

of which the ninth is the first to satisfy the second criteria. With this, we easily simplify the program to the following

```py
program = [
    "MOV R0 2658455991569831744654692615953842176",
    "PRINTFLAG R0",
    "HALT"
]
vm = VM()
vm.run(program)
```

which upon running gives us the flag,
`grey{p3rf3c7_r3v3r51n6}`
