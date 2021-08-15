	.text
main:
	#{push:main}
	mov D, SP
	add D, -1
	store BP, D
	mov SP, D
	mov BP, SP
	sub SP, 47
	.file 1 "vic_test.c"
	.loc 1 37 0
	# }
	.loc 1 4 0
	# 
	.loc 1 1 0
	# 
	mov A, 0
	mov B, SP
.data
	.L16:
	.string "Please enter your name: "
.text
	mov A, .L16
	mov B, BP
	add B, -2
	store A, B
	.L0:
	mov B, BP
	add B, -2
	load A, B
	mov B, A
	load A, B
	jeq .L17, A, 0
	mov B, BP
	add B, -2
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -2
	store A, B
	load A, SP
	add SP, 1
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L18
	.L17:
	jmp .L1
	.L18:
	jmp .L0
	.L1:
	.loc 1 8 0
	#     char *fuck = "f";
	.loc 1 9 0
	# 
	mov A, 0
	mov B, SP
.data
	.L19:
	.string "f"
.text
	mov A, .L19
	mov B, BP
	add B, -43
	store A, B
	.loc 1 11 0
	#     while(1) {
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -44
	mov A, 0
	store A, B
	.loc 1 30 0
	#     }
	.L2:
	.loc 1 12 0
	#         c = getchar();
	mov A, 1
	jeq .L20, A, 0
	.loc 1 30 0
	#     }
	.loc 1 13 0
	# 
	getc A
	jne .L21, A, 0
	mov A, -1
	.L21:
	mov B, BP
	add B, -1
	store A, B
	.loc 1 16 0
	#         }
	.loc 1 15 0
	#             break;
	.loc 1 4 0
	# 
	mov B, BP
	add B, -1
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 15 0
	#             break;
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L22, A, 0
	.loc 1 16 0
	#         }
	jmp .L3
	.L22:
	.loc 1 27 0
	#         }
	.L4:
	.loc 1 19 0
	#             while (1 < 2) {
	mov A, 1
	jeq .L23, A, 0
	.loc 1 27 0
	#         }
	.loc 1 21 0
	#             }
	.L6:
	.loc 1 20 0
	#                 break;
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L24, A, 0
	.loc 1 21 0
	#             }
	jmp .L7
	jmp .L25
	.L24:
	jmp .L7
	.L25:
	jmp .L6
	.L7:
	.loc 1 24 0
	# 
	.L8:
	mov A, 4
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L26, A, 0
	jmp .L27
	.L26:
	jmp .L9
	.L27:
	jmp .L8
	.L9:
	.loc 1 27 0
	#         }
	jmp .L5
	jmp .L28
	.L23:
	jmp .L5
	.L28:
	jmp .L4
	.L5:
	.loc 1 30 0
	#     }
	.loc 1 4 0
	# 
	mov B, BP
	add B, -1
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     }
	.loc 1 8 0
	#     char *fuck = "f";
	mov A, BP
	add A, 16777174
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     }
	.loc 1 11 0
	#     while(1) {
	mov B, BP
	add B, -44
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -44
	store A, B
	load A, SP
	add SP, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	jmp .L29
	.L20:
	.loc 1 30 0
	#     }
	jmp .L3
	.L29:
	jmp .L2
	.L3:
	.loc 1 33 0
	# 
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 8 0
	#     char *fuck = "f";
	mov A, BP
	add A, 16777174
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 11 0
	#     while(1) {
	mov B, BP
	add B, -44
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 1 0
	# 
	mov A, 0
	mov B, SP
.data
	.L30:
	.string "Your name is "
.text
	mov A, .L30
	mov B, BP
	add B, -45
	store A, B
	.L10:
	mov B, BP
	add B, -45
	load A, B
	mov B, A
	load A, B
	jeq .L31, A, 0
	mov B, BP
	add B, -45
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -45
	store A, B
	load A, SP
	add SP, 1
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L32
	.L31:
	jmp .L11
	.L32:
	jmp .L10
	.L11:
	mov A, 0
	mov B, SP
	.loc 1 8 0
	#     char *fuck = "f";
	mov A, BP
	add A, 16777174
	mov B, BP
	add B, -46
	store A, B
	.loc 1 1 0
	# 
	.L12:
	mov B, BP
	add B, -46
	load A, B
	mov B, A
	load A, B
	jeq .L33, A, 0
	mov B, BP
	add B, -46
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -46
	store A, B
	load A, SP
	add SP, 1
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L34
	.L33:
	jmp .L13
	.L34:
	jmp .L12
	.L13:
	mov A, 0
	mov B, SP
.data
	.L35:
	.string "\n"
.text
	mov A, .L35
	mov B, BP
	add B, -47
	store A, B
	.L14:
	mov B, BP
	add B, -47
	load A, B
	mov B, A
	load A, B
	jeq .L36, A, 0
	mov B, BP
	add B, -47
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -47
	store A, B
	load A, SP
	add SP, 1
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L37
	.L36:
	jmp .L15
	.L37:
	jmp .L14
	.L15:
	#{pop:main}
	exit
