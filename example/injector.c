#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "../shobi.h"

int main(int argc, char **argv)
{

	assert(argc == 2);
	int pid = atol(argv[1]);	
	assert(pid > 0);

	const char *so_path = "./shared_object.so";


	void *so_handle = shobi_load_so(pid, so_path);
	if(so_handle == NULL) {
		fprintf(stderr, "[!] Injection failed\n");
		exit(EXIT_FAILURE);
	}
	printf("[*] Injection successful\n");


	getchar();


	int ret = shobi_unload_so(pid, so_handle);
	if(ret != 0) {
		fprintf(stderr, "[!] Removal failed\n");
		exit(EXIT_FAILURE);
	}
	printf("[*] Removal successful\n");


	return 0;

}
