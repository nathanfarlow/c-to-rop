a.out : entry.c rop.c
	gcc -g -DLOCKSCREEN_POC entry.c

chal: entry.c chal.asm rop.c
	gcc -no-pie -c entry.c
	nasm -felf64 chal.asm
	gcc -no-pie entry.o chal.o -o chal

	../elvm/out/8cc -S rop.c

clean:
	rm -f *.o
	rm -f a.out chal
