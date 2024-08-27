from pwn import *

p = remote("challs.nusgreyhats.org", 32111)
context.log_level = 'debug'
p.recvuntil(b"begin")
p.sendline("")
p.recvuntil(b"GO!\n\n")
for _ in trange(1000):
    notes = p.recvline()[:-1].decode().strip().split("|")
    # print(notes)
    if notes[1] == ' X ':
        p.send(b'h')
    elif notes[2] == ' X ':
        p.send(b'j')
    elif notes[3] == ' X ':
        p.send(b'k')
    else:
        p.send(b'l')
p.interactive()