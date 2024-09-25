# What is SHOBI?
**SHOBI** stands for **SH**ared **OB**ject **I**njector and is a library that
allows you to dynamically load and unload `.so` files into running processes 
on ```x86_64``` Linux. The only requirement is that the target process must depend
on ```libc```.

> [!Warning]
> THIS LIBRARY MANIPULATES THE MEMORY, INSTRUCTIONS, AND CPU REGISTERS OF THE
> TARGET PROCESS. USE IT AT YOUR OWN RISK.

### Features
- Dynamically load and unload shared objects into running processes.
- No ```-ldl``` requirement for the target process.

### Limitations
- Currently only supports ```x86_64``` architecture.
- The target process must be linked with ```libc```.
- `shobi` needs to be run as a superuser, as it attaches to the target
  process and accesses its memory and CPU registers.

### TODOs
- Add proper error messages to indicate why `shobi` failed.
- If the loading or unloading of a shared object fails, the target process might
  be left in an invalid state (depending on what fails). Detect when this
  occurs and terminate the target process if necessary.
- Add compatibility with ```x86_32```.

# Usage
The library provides two functions.

```c 
void *shobi_load_so(pid_t pid, const char *so_path);
int shobi_unload_so(pid_t pid, void *so_handle);
```

The ```shobi_load_so``` function can be used to load a ```.so``` file into a
running process. The ```pid``` parameter is the process ID of the target
process. The ```so_path``` parameter is the path to the .so file. **Important:**
The path must be either absolute, or relative to **the location where the target
process is running**. It is recommended to use an absolute path to avoid
confusion. On success, a valid handle to the loaded shared object inside of the
target process is returned. On failure, NULL is returned.

The ```shobi_unload_so``` function can be used to remove the injected shared
object. The ```pid``` parameter is the process ID of the target process. The
```so_handle``` parameter is a handle to the loaded shared object inside of the
target process. Such a handle is returned by ```shobi_load_so```. On success, 0
is returned and on failure -1 is returned.

## Usage Example
Here is how you might want to use it:
```c
	...

	void *so_handle = shobi_load_so(pid, so_path);
	if(so_handle == NULL) {
		fprintf(stderr, "[!] Injection failed\n");
		exit(EXIT_FAILURE);
	}
	printf("[*] Injection successful\n");

	...

	int ret = shobi_unload_so(pid, so_handle);
	if(ret != 0) {
		fprintf(stderr, "[!] Removal failed\n");
		exit(EXIT_FAILURE);
	}
	printf("[*] Removal successful\n");

	...
```

# Complete examples
The example folder currently only contains an example for the ```x86_64```
architecture.  Inside, you'll find a Makefile, a shared object file, a target
program, and a program that uses the ```shobi``` library to inject the shared
object into the target.

The shared object prints ```Hello, World!``` when its constructor is called and
```Goodbye, World!``` when its destructor is called. The target program is an
infinite loop that prints ```Test``` to ```stdout```.

### Running the example
To run the example follow these four steps:
1) Navigate to the example folder.
2) Run ```make x86_64```
3) Execute the the target program with ```./target```
4) Open another session and navigate to the example folder. Execute the injector
with ```sudo ./injector $(pidof target)```

After executing step 4, you should see ```Hello, World!``` being printed by the
target process.  To unload the shared object, press any key. This will also
terminate the injector program.  You should then see ```Goodbye, World!```
printed by the target process.


# Including and building
To use the shared object injector in your project, include the ```shobi.c``` file, 
as well as the appropriate assembly instruction file for your architecture, 
in your compilation and linking process. The assembly files can be found in 
the ```arch_asm``` folder. Currently, only ```x86_64``` is supported. Compilation of 
```shobi.c``` does not require special flags, but linking requires the ```-ldl``` flag.

# References and Reccoures
- [https://stackoverflow.com/questions/24355344/inject-shared-library-into-a-process](https://stackoverflow.com/questions/24355344/inject-shared-library-into-a-process)
- [https://www.codeproject.com/Articles/33340/Code-Injection-into-Running-Linux-Application](https://www.codeproject.com/Articles/33340/Code-Injection-into-Running-Linux-Application)
- [https://github.com/gaffe23/linux-inject/blob/master/inject-x86_64.c](https://github.com/gaffe23/linux-inject/blob/master/inject-x86_64.c)
- [https://en.wikipedia.org/wiki/INT_(x86_instruction)#INT3](https://en.wikipedia.org/wiki/INT_(x86_instruction)#INT3)
