#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <limits.h>

// for link_map struct 
#include <link.h>

#include "shobi.h"


#define GET_LIB_START(HANDLE) \
	((uintptr_t)(((struct link_map*)HANDLE)->l_addr))

#define ARR_SIZE(arr) (sizeof(arr) / sizeof(*arr))

#define BITMASK_CLEAR_AND_SET(reg, cmask, smask)\
	((reg) = (((reg) & (~(cmask))) | (smask)))


#define LIBC_NAME "libc.so.6"
#define MMAP_MIN_SIZE (PATH_MAX + 256)


/* in arch_asm/asm_instr_*.S */
extern void syscall_instr_start(void);
extern void syscall_instr_end(void);
extern void func_call_instr_start(void);
extern void func_call_instr_end(void);


static int detatch(int pid);
static int attatch(int pid);
static int break_at_syscall(int pid);
static int wait_for_syscall_exit(int pid);
static int cont_exec(int target);
static int set_cpu_regs(int target, struct user_regs_struct* regs);
static int read_cpu_regs(int pid, struct user_regs_struct *regs);
static size_t read_mem(int pid, uintptr_t addr, void *data, size_t nbytes);
static size_t write_mem(int pid, uintptr_t addr, void *data, size_t nbytes);


static uintptr_t get_target_lib_start(int pid, const char *lib_name);
static uintptr_t get_lib_func_addr_in_target(int pid, const char *lib_name, 
					const char *func_name);

static void *make_mmap_syscall_in_target(int pid, size_t size);
static int make_munmap_syscall_in_target(int pid, uintptr_t addr, size_t size);
static int make_syscall_in_target(int pid, struct user_regs_struct *syscall_regs);
static void *make_dlopen_call_in_target(int pid, const char *so_name, uintptr_t addr);
static int make_dlclose_call_in_target(int pid, uintptr_t addr, uintptr_t handle);


void *shobi_load_so(int pid, const char *so_name)
{
	assert(sizeof(void *(*)(const char *, int)) <= sizeof(uintptr_t));
	assert(sizeof(int (*)(void *)) <= sizeof(uintptr_t));

	attatch(pid);	

	void* mmap_addr = make_mmap_syscall_in_target(pid, MMAP_MIN_SIZE);
	if(mmap_addr == NULL || mmap_addr == MAP_FAILED)
		return NULL;

	void *dlopen_ret = make_dlopen_call_in_target(pid, so_name, (uintptr_t)mmap_addr);
	if(dlopen_ret == NULL)
		return NULL; 

	int munmap_ret = make_munmap_syscall_in_target(pid, (uintptr_t)mmap_addr, MMAP_MIN_SIZE);
	if(munmap_ret == -1)
		return NULL;
		
	detatch(pid);

	return dlopen_ret;
}


int shobi_unload_so(int pid, void *lib_handle)
{
	assert(sizeof(void *(*)(const char *, int)) <= sizeof(uintptr_t));
	assert(sizeof(int (*)(void *)) <= sizeof(uintptr_t));

	attatch(pid);	

	void* mmap_addr = make_mmap_syscall_in_target(pid, MMAP_MIN_SIZE);
	if(mmap_addr == MAP_FAILED)
		return -1;

	int dlclose_ret = make_dlclose_call_in_target(pid, (uintptr_t)mmap_addr, 
							(uintptr_t)lib_handle);
	if(dlclose_ret != 0)
		return -1;


	int munmap_ret = make_munmap_syscall_in_target(pid, 
					(uintptr_t)mmap_addr, MMAP_MIN_SIZE);
	if(munmap_ret == -1)
		return -1;
		
	detatch(pid);

	return 0;
}

static int attatch(int pid)
{
	long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if(ret == -1)
		return -1;

	int status;	
	if(waitpid(pid, &status, 0) == -1)
		return -1;

	if(WIFSTOPPED(status) == 0)
		return -1;

	return 0;
}

static int detatch(int pid)
{
	long ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if(ret == -1)
		return -1;

	return 0;
}

static int break_at_syscall(int pid)
{
	unsigned long sig = 0;
	long ret = ptrace(PTRACE_SYSCALL, pid, &sig, NULL);
	if(ret == -1)
		return -1;

	int status;	
	if(waitpid(pid, &status, 0) == -1)
		return -1;

	if(WIFSTOPPED(status) == 0)
		return -1;

	return 0;
}

static int cont_exec(int target)
{
	long ret = ptrace(PTRACE_CONT, target, NULL, NULL) ;
	if(ret == -1)
		return -1;

	int status;	
	if(waitpid(target, &status, 0) == -1)
		return -1;

	if(WIFSTOPPED(status) == 0)
		return -1;

	if(WSTOPSIG(status) != SIGTRAP)
		return -1;
	
	return 0;
}


static int wait_for_syscall_exit(int pid)
{
	/* continue execution and stop before system call entry. */
	if(break_at_syscall(pid) != 0)
		return -1;

	/* continue execution and stop after system call entry. */
	if(break_at_syscall(pid) != 0)
		return -1;

	/* continue execution and stop at system call exit. */
	if(break_at_syscall(pid) != 0)
		return -1;
	
	return 0;
}


static size_t read_mem(int pid, uintptr_t addr, void *data, size_t nbytes)
{
	long *word_itr = (long *)data;
	size_t bytes_read = 0;
	const size_t word_size = sizeof(long);

	long ret;
	while(bytes_read + word_size <= nbytes) {
		errno = 0;
		ret = ptrace(PTRACE_PEEKTEXT, pid, addr + bytes_read, NULL);
		if(ret == -1 && errno != 0)
			return bytes_read;

		*(word_itr++) = ret;
		bytes_read += word_size;
	}

	/* ptrace only does word sized reads. */
	uint8_t *byte_itr = (uint8_t *)word_itr;
	while(bytes_read < nbytes) {
		errno = 0;
		ret = ptrace(PTRACE_PEEKTEXT, pid, addr + bytes_read, NULL);
		if(ret == -1 && errno != 0)
			return bytes_read;

		*(byte_itr++) = (uint8_t)ret;
		bytes_read += sizeof(uint8_t); 
	}

	return bytes_read;
}


static size_t write_mem(int pid, uintptr_t addr, void *data, size_t nbytes)
{

	long *word_itr = (long *)data;
	size_t word_size = sizeof(long);
	size_t bytes_written = 0;

	long ret;
	while(bytes_written + word_size <= nbytes) {
		ret = ptrace(PTRACE_POKETEXT, pid, addr + bytes_written,
						*(word_itr++));
		if(ret == -1)
			return bytes_written;
		bytes_written += word_size;
	}

	/* ptrace only allows word sized writes. */
	if(bytes_written < nbytes) {
		uint8_t *byte_itr = (uint8_t *)word_itr;
		long word; 
		size_t br = read_mem(pid, addr + bytes_written, 
					    &word, sizeof(word));

		if(br != sizeof(word))
			return bytes_written;

		int leftover = nbytes - bytes_written;
		int i = 0;
		assert(leftover <= (int)nbytes);

		while(i < leftover) {
			int shift = (i * 8);
			assert(shift >= 0);

			long clear_mask = 0xffL << shift;
			long set_mask = byte_itr[i];
			set_mask = set_mask << shift;
			BITMASK_CLEAR_AND_SET(word, clear_mask, set_mask);

			i += 1;
		}

		ret = ptrace(PTRACE_POKETEXT, pid, addr + bytes_written, word);
		if(ret == -1)
			return bytes_written;

		bytes_written += i;
	}

	assert(bytes_written == nbytes);
	
	return bytes_written;
}


static int set_cpu_regs(int target, struct user_regs_struct* regs)
{
	long ret = ptrace(PTRACE_SETREGS, target, NULL, regs);
	if(ret == -1)
		return -1;

	return 0;
}


static int read_cpu_regs(int pid, struct user_regs_struct *regs)
{
	long ret = ptrace(PTRACE_GETREGS, pid, NULL, regs);
	if(ret == -1)
		return -1;

	return 0;
}


static uintptr_t get_target_lib_start(int pid, const char *lib_name)
{
	char maps_path[PATH_MAX];
	char entry[PATH_MAX];

	int ret = snprintf(maps_path, ARR_SIZE(maps_path), "/proc/%d/maps", pid);
	if(ret <= 0 || (size_t)ret >= ARR_SIZE(maps_path))
		return 0;

	FILE *f = fopen(maps_path, "r");
	if(f == NULL)
		return 0;

	uintptr_t addr_start = 0;
	
	while(feof(f) == 0 && fgets(entry, ARR_SIZE(entry), f) != NULL) {
		ret = sscanf(entry, "%lx-", &addr_start);
		if(ret == 1 && strstr(entry, lib_name) != NULL)
			break;
	}

	fclose(f);
	return addr_start;	
}


static uintptr_t get_lib_func_addr_in_target(int pid, const char *lib_name, 
					const char *func_name)
{
	void *h_lib = dlopen(lib_name, RTLD_LAZY);
	if(h_lib == NULL)
		return 0;

	uintptr_t lib_func_addr = (uintptr_t)dlsym(h_lib, func_name); 
	if(lib_func_addr == (uintptr_t)NULL)
		return 0;

	uintptr_t lib_start_addr = GET_LIB_START(h_lib);

	dlclose(h_lib);

	uintptr_t lib_func_offset = lib_func_addr - lib_start_addr;
	uintptr_t target_lib_start = get_target_lib_start(pid, lib_name);
	if(target_lib_start == 0)
		return 0;

	return (target_lib_start + lib_func_offset);
}

static void *make_mmap_syscall_in_target(int pid, size_t size)
{
	struct user_regs_struct regs;
	read_cpu_regs(pid, &regs);
	int prot = PROT_READ | PROT_EXEC | PROT_WRITE;
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	
	/* syscall number */
	regs.rax = SYS_mmap;
	
	/* arg1 (addr) */
	regs.rdi = (uintptr_t)NULL;

	/* arg2 (size) */
	regs.rsi = size;

	/* arg3 (prot) */
	regs.rdx = prot;

	/* arg4 (flags) */
	regs.r10 = flags;

	/* arg5 (fd) */
	regs.r8 = -1;

	/* arg6 (offset) */
	regs.r9 = 0;

	int ret = make_syscall_in_target(pid, &regs);
	if(ret != 0)
		return NULL;

	unsigned long long mmap_ret = regs.rax;

	return (void *)mmap_ret;
}


static int make_munmap_syscall_in_target(int pid, uintptr_t addr, size_t size)
{
	struct user_regs_struct regs;
	read_cpu_regs(pid, &regs);

	/* syscall number */
	regs.rax = SYS_munmap;
	
	/* arg1 (addr): NULL */
	regs.rdi = addr;

	/* arg2 (size): size */
	regs.rsi = size;

	int ret = make_syscall_in_target(pid, &regs);
	if(ret != 0)
		return -1;

	unsigned long long munmap_ret = regs.rax;

	return (int)munmap_ret;
}


static int make_syscall_in_target(int pid, struct user_regs_struct *syscall_regs)
{
	struct user_regs_struct orig_regs;
	uint8_t orig_data[256];


	read_cpu_regs(pid, &orig_regs);
	uintptr_t loc = (uintptr_t)orig_regs.rip;
	syscall_regs->rip = loc;

	size_t br = read_mem(pid, loc, orig_data, ARR_SIZE(orig_data));
	if(br != ARR_SIZE(orig_data))
		return -1;

	int ret = set_cpu_regs(pid, syscall_regs);
	if(ret != 0)
		return -1;

	/* prepare trap_call */
	uintptr_t trap = (uintptr_t)syscall_instr_start;
	size_t trap_num_bytes = (uintptr_t)syscall_instr_end -
					(uintptr_t)syscall_instr_start;

	/* copy trap call bytes into target */
	size_t bw = write_mem(pid, loc, (void *)trap, trap_num_bytes); 
	if(bw != trap_num_bytes)
		return -1;


	ret = wait_for_syscall_exit(pid);
	if(ret != 0)
		return -1;

	/* get the return value before overwriting with the original
	 * registers. */
	ret = read_cpu_regs(pid, syscall_regs);
	if(ret != 0)
		return -1;

	/* restore original data */
	bw = write_mem(pid, loc, orig_data, ARR_SIZE(orig_data)); 
	if(bw != ARR_SIZE(orig_data))
		return -1;

	/* restore original cpu registers */
	ret = set_cpu_regs(pid, &orig_regs);
	if(ret != 0)
		return -1;

	return 0;
}


static void *make_dlopen_call_in_target(int pid, const char *so_name, uintptr_t addr)
{
	struct user_regs_struct orig_regs;
	struct user_regs_struct regs;
	read_cpu_regs(pid, &orig_regs);
	read_cpu_regs(pid, &regs);
	regs.orig_rax = ULLONG_MAX; 
	regs.rax = (unsigned long long)NULL; 
	

	/* get pointer to dlopen addresses in the target process
	 * memeory. */
	uintptr_t target_libc_dlopen_addr = get_lib_func_addr_in_target(pid, 
							LIBC_NAME, "dlopen");
	if(target_libc_dlopen_addr == 0)
		return NULL;

	/* copy name (string) of the .so file that shall be loaded into the
	 * target process into the mmaped region in the target process. */
	size_t bw = write_mem(pid, addr, (void *)so_name, strlen(so_name) + 1); 
	if(bw != strlen(so_name) + 1)
		return NULL; 

	/* call the target dlopen with the pointer to the .so file name that was
	 * copied into the mmaped area of the target process. */
	regs.r9 = target_libc_dlopen_addr;
	regs.rdi = addr;
	regs.rsi = RTLD_NOW;

	/* +1 for null terminator, and + 8 because im paranoid */
	addr += strlen(so_name) + 1 + 8;
	regs.rip = addr;

	int ret = set_cpu_regs(pid, &regs);
	if(ret != 0)
		return NULL;


	uintptr_t func_call = (uintptr_t)func_call_instr_start;
	size_t func_call_num_bytes = (uintptr_t)func_call_instr_end - 
					(uintptr_t)func_call_instr_start;
	bw = write_mem(pid, regs.rip, (void *)func_call, func_call_num_bytes); 
	if(bw != func_call_num_bytes)
		return NULL;

	ret = cont_exec(pid);
	if(ret != 0)
		return NULL;

	ret = read_cpu_regs(pid, &regs);
	if(ret != 0)
		return NULL;

	void *dlopen_ret = (void *)regs.rax;
	
	/* restore registers */
	ret = set_cpu_regs(pid, &orig_regs);
	if(ret != 0)
		return NULL;

	return dlopen_ret;

}


static int make_dlclose_call_in_target(int pid, uintptr_t addr, uintptr_t handle)
{
	struct user_regs_struct orig_regs;
	struct user_regs_struct regs;
	read_cpu_regs(pid, &orig_regs);
	read_cpu_regs(pid, &regs);
	regs.orig_rax = ULLONG_MAX; 
	regs.rax = (unsigned long long)NULL;
	

	/* get pointer to dlclose addresses in the target process
	 * memeory. */
	uintptr_t target_libc_dlclose_addr = get_lib_func_addr_in_target(pid,
						LIBC_NAME, "dlclose");
	if(target_libc_dlclose_addr == 0)
		return -1;

	/* call the target dlclose with given handle */
	regs.r9 = target_libc_dlclose_addr;
	regs.rdi = handle;
	regs.rip = addr;

	int ret = set_cpu_regs(pid, &regs);
	if(ret != 0)
		return -1;

	uintptr_t func_call = (uintptr_t)func_call_instr_start;
	size_t func_call_num_bytes = (uintptr_t)func_call_instr_end - 
					(uintptr_t)func_call_instr_start;
	size_t bw = write_mem(pid, regs.rip, (void *)func_call, func_call_num_bytes); 
	if(bw != func_call_num_bytes)
		return -1;


	ret = cont_exec(pid);
	if(ret != 0)
		return -1;

	ret = read_cpu_regs(pid, &regs);
	if(ret != 0)
		return -1;

	int dlclose_ret = (int)regs.rax;
	
	/* restore registers */
	ret = set_cpu_regs(pid, &orig_regs);
	if(ret != 0)
		return -1;

	return dlclose_ret;
}

