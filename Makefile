all:
	# cd test && make && cd ..
	# /home/nathan/miniconda3/envs/rop/bin/python3 main.py ./test/test ./test.bin ./test/small.s 0x402000 0x502000 output.py
	# /home/nathan/miniconda3/bin/python3 export.py

	cd test && make && cd ..
	# objdump --syms chal | grep -E '(rop_data|rop_chain)'
	/home/nathan/miniconda3/envs/rop/bin/python3 main.py ./chal_code/chal ./chal.bin ./chal_code/rop.s 0x0000000000404070 0x0000000000414070 output.py 
	/home/nathan/miniconda3/bin/python3 export.py

clean:
	rm -f test.bin
	cd test
	make clean
