
add: add.asm
	nasm -felf64 add.asm	
	ld add.o -o add

../elvm/out/8cc:
	cd ../elvm
	make out/8cc

vic_test.s: vic_test.c ../elvm/out/8cc
	../elvm/out/8cc -S vic_test.c

clean:
	rm -f *.o
	rm add vic_test.s
