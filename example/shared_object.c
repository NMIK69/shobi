#include <stdio.h>

__attribute__((constructor)) static void setup(void) {
	fprintf(stderr, "Hello, World!\n");
}

__attribute__((destructor)) static void destr(void) {
	fprintf(stderr, "Goodbye, World!\n");
}
