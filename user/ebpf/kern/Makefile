%.o: %.c
	clang-12 -target bpf -g -O1 -c -o $@ $<

all: context.o map.o time1.o get_regs.o get_regs_user.o

clean:
	rm -f *.o

.PHONY : all clean
