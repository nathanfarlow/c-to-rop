all: add

setregs.o: setregs.asm
	nasm -felf64 setregs.asm

add.o: add.asm
	nasm -felf64 add.asm	

add: add.o setregs.o 
	ld add.o setregs.o -o add

clean:
	rm -f *.o
	rm -f add core