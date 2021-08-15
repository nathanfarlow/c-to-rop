
all: test unit

test: test.asm
	nasm -felf64 test.asm	
	ld test.o -o test

unit: unit.asm
	nasm -felf64 unit.asm
	ld unit.o -o unit

../elvm/out/8cc:
	$(MAKE) -C ../elvm out/8cc

vic_test.s: vic_test.c ../elvm/out/8cc
	../elvm/out/8cc -S vic_test.c

clean:
	rm -f *.o
	rm -f unit test vic_test.s
