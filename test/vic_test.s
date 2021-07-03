	.data 0
a:
	.long 1
	.long 2
	.long 3
	.long 4
	.long 34
	.long 0
	.text
main:
	#{push:main}
	mov D, SP
	add D, -1
	store BP, D
	mov SP, D
	mov BP, SP
	sub SP, 1
	.file 1 "vic_test.c"
	.loc 1 4 0
	#     }
	.loc 1 3 0
	#         putchar(*i);
	mov A, 0
	mov B, SP
	mov A, a
	mov B, BP
	add B, 16777215
	store A, B
	.loc 1 4 0
	#     }
	.L0:
	.loc 1 3 0
	#         putchar(*i);
	mov B, BP
	add B, 16777215
	load A, B
	mov B, A
	load A, B
	jeq .L3, A, 0
	jmp .L4
	.L3:
	.loc 1 4 0
	#     }
	jmp .L2
	.L4:
	.loc 1 3 0
	#         putchar(*i);
	mov B, BP
	add B, 16777215
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 4 0
	#     }
	.L1:
	.loc 1 3 0
	#         putchar(*i);
	mov B, BP
	add B, 16777215
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, 16777215
	store A, B
	load A, SP
	add SP, 1
	.loc 1 4 0
	#     }
	jmp .L0
	.L2:
	#{pop:main}
	exit
