CC=gcc
CFLAGS=-Wall -pedantic -std=c99 -Wextra -Wmissing-prototypes 
OPTIMIZE=-O0

INJECTOR=injector
TARGET=target
SO=shared_object.so
ARCH=asm_instr_x86_64.o
DEBUG=0


ifeq ($(DEBUG),1)
CFLAGS+=-ggdb
OPTIMIZE=-O0
endif


.PHONY: x86_64
x86_64: ARCH=asm_instr_x86_64.o
x86_64: CFLAGS+=-m64
x86_64: $(INJECTOR) $(TARGET) $(SO)


$(TARGET): target.c
	$(CC) $^ $(CFLAGS) -o $@

$(SO): shared_object.c
	$(CC) $^ $(CFLAGS) -shared -fPIC -o $@

$(INJECTOR): shobi.o injector.o $(ARCH)
	$(CC) $^ $(OPTIMIZE) -ldl -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(OPTIMIZE) -c $< -o $@

shobi.o: ../shobi.c ../shobi.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c $< -o $@


%.o: ../arch_asm/%.S
	$(CC) -c $< -o $@



.PHONY: clean
clean:
	rm -f $(INJECTOR)
	rm -f $(TARGET)
	rm -f $(SO) 
	rm -f *.o
