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
        "JNE 2", # if not zero, jumps next 2 into CMP R1, R0
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
    program = [
        "MOV R0 2658455991569831744654692615953842176",
        "PRINTFLAG R0",
        "HALT"
    ]
    vm = VM()
    vm.run(program)

if __name__ == "__main__":
    main()

# R0, R1, R2, R3, R5 = 2, 1, 31337, 0, 2410

# # START

# # R3 = SUM OF ALL FACTORS OF R0
# R1 = 1
# R3 = 0
# while R1 != R0:
#     R4 = R0 % R1
#     if R4 == 0:
#         R3 += R1 # R3 adds up all the factors of R0 excluding R0 itself
#     R1 += 1


# if R0 != R3:
#     R0 += 1
#     # GO BACK TO START
# else:
#     # REQ 1: R0 == R3
#     R4 = R0 % R2
#     # REQ 2: R0 % 31337 == 2410
#     # if R4 == R5:
#     #     # WIN R0
#     # else:
#     #     R0 += 1
#     #     # GO BAK



xs = [6,28,496,8128,33550336,8589869056,137438691328,
 2305843008139952128,
 2658455991569831744654692615953842176,
 191561942608236107294793378084303638130997321548169216]
for x in xs:
    print(x % 31337)
