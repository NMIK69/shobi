#ifndef SHOBI_H
#define SHOBI_H

#include <stdint.h>

void *shobi_load_so(int pid, const char *so_name);
int shobi_unload_so(int pid, void *lib_handle);


#endif
