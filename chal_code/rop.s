	.text
main:
	#{push:main}
	mov D, SP
	add D, -1
	store BP, D
	mov SP, D
	mov BP, SP
	sub SP, 883
	.file 1 "rop.c"
	.loc 1 320 0
	#         } // switch(num_read)
	.loc 1 45 0
	#     const char line_10[]  = "\e[B~\e[B\e[D~\e[B\e[D~\e[B\e[D~";
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -12
	mov A, 27
	store A, B
	mov B, BP
	add B, -11
	mov A, 91
	store A, B
	mov B, BP
	add B, -10
	mov A, 50
	store A, B
	mov B, BP
	add B, -9
	mov A, 67
	store A, B
	mov B, BP
	add B, -8
	mov A, 126
	store A, B
	mov B, BP
	add B, -7
	mov A, 126
	store A, B
	mov B, BP
	add B, -6
	mov A, 126
	store A, B
	mov B, BP
	add B, -5
	mov A, 126
	store A, B
	mov B, BP
	add B, -4
	mov A, 126
	store A, B
	mov B, BP
	add B, -3
	mov A, 126
	store A, B
	mov B, BP
	add B, -2
	mov A, 126
	store A, B
	mov B, BP
	add B, -1
	mov A, 0
	store A, B
	.loc 1 46 0
	#     const char line_11[]  = "\e[B\e[C\e[C~\e[C\e[B~\e[C\e[B~\e[C\e[B~";
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -38
	mov A, 27
	store A, B
	mov B, BP
	add B, -37
	mov A, 91
	store A, B
	mov B, BP
	add B, -36
	mov A, 66
	store A, B
	mov B, BP
	add B, -35
	mov A, 126
	store A, B
	mov B, BP
	add B, -34
	mov A, 27
	store A, B
	mov B, BP
	add B, -33
	mov A, 91
	store A, B
	mov B, BP
	add B, -32
	mov A, 66
	store A, B
	mov B, BP
	add B, -31
	mov A, 27
	store A, B
	mov B, BP
	add B, -30
	mov A, 91
	store A, B
	mov B, BP
	add B, -29
	mov A, 68
	store A, B
	mov B, BP
	add B, -28
	mov A, 126
	store A, B
	mov B, BP
	add B, -27
	mov A, 27
	store A, B
	mov B, BP
	add B, -26
	mov A, 91
	store A, B
	mov B, BP
	add B, -25
	mov A, 66
	store A, B
	mov B, BP
	add B, -24
	mov A, 27
	store A, B
	mov B, BP
	add B, -23
	mov A, 91
	store A, B
	mov B, BP
	add B, -22
	mov A, 68
	store A, B
	mov B, BP
	add B, -21
	mov A, 126
	store A, B
	mov B, BP
	add B, -20
	mov A, 27
	store A, B
	mov B, BP
	add B, -19
	mov A, 91
	store A, B
	mov B, BP
	add B, -18
	mov A, 66
	store A, B
	mov B, BP
	add B, -17
	mov A, 27
	store A, B
	mov B, BP
	add B, -16
	mov A, 91
	store A, B
	mov B, BP
	add B, -15
	mov A, 68
	store A, B
	mov B, BP
	add B, -14
	mov A, 126
	store A, B
	mov B, BP
	add B, -13
	mov A, 0
	store A, B
	.loc 1 47 0
	#     const char line_11$[] = "\e[A\e[C\e[C~\e[C\e[A~\e[C\e[A~\e[C\e[A~";
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -70
	mov A, 27
	store A, B
	mov B, BP
	add B, -69
	mov A, 91
	store A, B
	mov B, BP
	add B, -68
	mov A, 66
	store A, B
	mov B, BP
	add B, -67
	mov A, 27
	store A, B
	mov B, BP
	add B, -66
	mov A, 91
	store A, B
	mov B, BP
	add B, -65
	mov A, 67
	store A, B
	mov B, BP
	add B, -64
	mov A, 27
	store A, B
	mov B, BP
	add B, -63
	mov A, 91
	store A, B
	mov B, BP
	add B, -62
	mov A, 67
	store A, B
	mov B, BP
	add B, -61
	mov A, 126
	store A, B
	mov B, BP
	add B, -60
	mov A, 27
	store A, B
	mov B, BP
	add B, -59
	mov A, 91
	store A, B
	mov B, BP
	add B, -58
	mov A, 67
	store A, B
	mov B, BP
	add B, -57
	mov A, 27
	store A, B
	mov B, BP
	add B, -56
	mov A, 91
	store A, B
	mov B, BP
	add B, -55
	mov A, 66
	store A, B
	mov B, BP
	add B, -54
	mov A, 126
	store A, B
	mov B, BP
	add B, -53
	mov A, 27
	store A, B
	mov B, BP
	add B, -52
	mov A, 91
	store A, B
	mov B, BP
	add B, -51
	mov A, 67
	store A, B
	mov B, BP
	add B, -50
	mov A, 27
	store A, B
	mov B, BP
	add B, -49
	mov A, 91
	store A, B
	mov B, BP
	add B, -48
	mov A, 66
	store A, B
	mov B, BP
	add B, -47
	mov A, 126
	store A, B
	mov B, BP
	add B, -46
	mov A, 27
	store A, B
	mov B, BP
	add B, -45
	mov A, 91
	store A, B
	mov B, BP
	add B, -44
	mov A, 67
	store A, B
	mov B, BP
	add B, -43
	mov A, 27
	store A, B
	mov B, BP
	add B, -42
	mov A, 91
	store A, B
	mov B, BP
	add B, -41
	mov A, 66
	store A, B
	mov B, BP
	add B, -40
	mov A, 126
	store A, B
	mov B, BP
	add B, -39
	mov A, 0
	store A, B
	.loc 1 48 0
	#     const char line_21[]  = "\e[B\e[C~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~";
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -102
	mov A, 27
	store A, B
	mov B, BP
	add B, -101
	mov A, 91
	store A, B
	mov B, BP
	add B, -100
	mov A, 65
	store A, B
	mov B, BP
	add B, -99
	mov A, 27
	store A, B
	mov B, BP
	add B, -98
	mov A, 91
	store A, B
	mov B, BP
	add B, -97
	mov A, 67
	store A, B
	mov B, BP
	add B, -96
	mov A, 27
	store A, B
	mov B, BP
	add B, -95
	mov A, 91
	store A, B
	mov B, BP
	add B, -94
	mov A, 67
	store A, B
	mov B, BP
	add B, -93
	mov A, 126
	store A, B
	mov B, BP
	add B, -92
	mov A, 27
	store A, B
	mov B, BP
	add B, -91
	mov A, 91
	store A, B
	mov B, BP
	add B, -90
	mov A, 67
	store A, B
	mov B, BP
	add B, -89
	mov A, 27
	store A, B
	mov B, BP
	add B, -88
	mov A, 91
	store A, B
	mov B, BP
	add B, -87
	mov A, 65
	store A, B
	mov B, BP
	add B, -86
	mov A, 126
	store A, B
	mov B, BP
	add B, -85
	mov A, 27
	store A, B
	mov B, BP
	add B, -84
	mov A, 91
	store A, B
	mov B, BP
	add B, -83
	mov A, 67
	store A, B
	mov B, BP
	add B, -82
	mov A, 27
	store A, B
	mov B, BP
	add B, -81
	mov A, 91
	store A, B
	mov B, BP
	add B, -80
	mov A, 65
	store A, B
	mov B, BP
	add B, -79
	mov A, 126
	store A, B
	mov B, BP
	add B, -78
	mov A, 27
	store A, B
	mov B, BP
	add B, -77
	mov A, 91
	store A, B
	mov B, BP
	add B, -76
	mov A, 67
	store A, B
	mov B, BP
	add B, -75
	mov A, 27
	store A, B
	mov B, BP
	add B, -74
	mov A, 91
	store A, B
	mov B, BP
	add B, -73
	mov A, 65
	store A, B
	mov B, BP
	add B, -72
	mov A, 126
	store A, B
	mov B, BP
	add B, -71
	mov A, 0
	store A, B
	.loc 1 49 0
	#     const char line_21$[] = "\e[A\e[C~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~";
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -142
	mov A, 27
	store A, B
	mov B, BP
	add B, -141
	mov A, 91
	store A, B
	mov B, BP
	add B, -140
	mov A, 66
	store A, B
	mov B, BP
	add B, -139
	mov A, 27
	store A, B
	mov B, BP
	add B, -138
	mov A, 91
	store A, B
	mov B, BP
	add B, -137
	mov A, 67
	store A, B
	mov B, BP
	add B, -136
	mov A, 126
	store A, B
	mov B, BP
	add B, -135
	mov A, 27
	store A, B
	mov B, BP
	add B, -134
	mov A, 91
	store A, B
	mov B, BP
	add B, -133
	mov A, 66
	store A, B
	mov B, BP
	add B, -132
	mov A, 126
	store A, B
	mov B, BP
	add B, -131
	mov A, 27
	store A, B
	mov B, BP
	add B, -130
	mov A, 91
	store A, B
	mov B, BP
	add B, -129
	mov A, 66
	store A, B
	mov B, BP
	add B, -128
	mov A, 126
	store A, B
	mov B, BP
	add B, -127
	mov A, 27
	store A, B
	mov B, BP
	add B, -126
	mov A, 91
	store A, B
	mov B, BP
	add B, -125
	mov A, 66
	store A, B
	mov B, BP
	add B, -124
	mov A, 126
	store A, B
	mov B, BP
	add B, -123
	mov A, 27
	store A, B
	mov B, BP
	add B, -122
	mov A, 91
	store A, B
	mov B, BP
	add B, -121
	mov A, 66
	store A, B
	mov B, BP
	add B, -120
	mov A, 126
	store A, B
	mov B, BP
	add B, -119
	mov A, 27
	store A, B
	mov B, BP
	add B, -118
	mov A, 91
	store A, B
	mov B, BP
	add B, -117
	mov A, 66
	store A, B
	mov B, BP
	add B, -116
	mov A, 126
	store A, B
	mov B, BP
	add B, -115
	mov A, 27
	store A, B
	mov B, BP
	add B, -114
	mov A, 91
	store A, B
	mov B, BP
	add B, -113
	mov A, 66
	store A, B
	mov B, BP
	add B, -112
	mov A, 126
	store A, B
	mov B, BP
	add B, -111
	mov A, 27
	store A, B
	mov B, BP
	add B, -110
	mov A, 91
	store A, B
	mov B, BP
	add B, -109
	mov A, 66
	store A, B
	mov B, BP
	add B, -108
	mov A, 126
	store A, B
	mov B, BP
	add B, -107
	mov A, 27
	store A, B
	mov B, BP
	add B, -106
	mov A, 91
	store A, B
	mov B, BP
	add B, -105
	mov A, 66
	store A, B
	mov B, BP
	add B, -104
	mov A, 126
	store A, B
	mov B, BP
	add B, -103
	mov A, 0
	store A, B
	.loc 1 50 0
	#     const char line_12[]  = "\e[B\e[C~~~~~\e[B~~~~~\e[B\e[D~~~~~\e[B~~~~~";
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -182
	mov A, 27
	store A, B
	mov B, BP
	add B, -181
	mov A, 91
	store A, B
	mov B, BP
	add B, -180
	mov A, 65
	store A, B
	mov B, BP
	add B, -179
	mov A, 27
	store A, B
	mov B, BP
	add B, -178
	mov A, 91
	store A, B
	mov B, BP
	add B, -177
	mov A, 67
	store A, B
	mov B, BP
	add B, -176
	mov A, 126
	store A, B
	mov B, BP
	add B, -175
	mov A, 27
	store A, B
	mov B, BP
	add B, -174
	mov A, 91
	store A, B
	mov B, BP
	add B, -173
	mov A, 65
	store A, B
	mov B, BP
	add B, -172
	mov A, 126
	store A, B
	mov B, BP
	add B, -171
	mov A, 27
	store A, B
	mov B, BP
	add B, -170
	mov A, 91
	store A, B
	mov B, BP
	add B, -169
	mov A, 65
	store A, B
	mov B, BP
	add B, -168
	mov A, 126
	store A, B
	mov B, BP
	add B, -167
	mov A, 27
	store A, B
	mov B, BP
	add B, -166
	mov A, 91
	store A, B
	mov B, BP
	add B, -165
	mov A, 65
	store A, B
	mov B, BP
	add B, -164
	mov A, 126
	store A, B
	mov B, BP
	add B, -163
	mov A, 27
	store A, B
	mov B, BP
	add B, -162
	mov A, 91
	store A, B
	mov B, BP
	add B, -161
	mov A, 65
	store A, B
	mov B, BP
	add B, -160
	mov A, 126
	store A, B
	mov B, BP
	add B, -159
	mov A, 27
	store A, B
	mov B, BP
	add B, -158
	mov A, 91
	store A, B
	mov B, BP
	add B, -157
	mov A, 65
	store A, B
	mov B, BP
	add B, -156
	mov A, 126
	store A, B
	mov B, BP
	add B, -155
	mov A, 27
	store A, B
	mov B, BP
	add B, -154
	mov A, 91
	store A, B
	mov B, BP
	add B, -153
	mov A, 65
	store A, B
	mov B, BP
	add B, -152
	mov A, 126
	store A, B
	mov B, BP
	add B, -151
	mov A, 27
	store A, B
	mov B, BP
	add B, -150
	mov A, 91
	store A, B
	mov B, BP
	add B, -149
	mov A, 65
	store A, B
	mov B, BP
	add B, -148
	mov A, 126
	store A, B
	mov B, BP
	add B, -147
	mov A, 27
	store A, B
	mov B, BP
	add B, -146
	mov A, 91
	store A, B
	mov B, BP
	add B, -145
	mov A, 65
	store A, B
	mov B, BP
	add B, -144
	mov A, 126
	store A, B
	mov B, BP
	add B, -143
	mov A, 0
	store A, B
	.loc 1 51 0
	#     const char line_12$[] = "\e[A\e[C~~~~~\e[A~~~~~\e[A\e[D~~~~~\e[A~~~~~";
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -221
	mov A, 27
	store A, B
	mov B, BP
	add B, -220
	mov A, 91
	store A, B
	mov B, BP
	add B, -219
	mov A, 66
	store A, B
	mov B, BP
	add B, -218
	mov A, 27
	store A, B
	mov B, BP
	add B, -217
	mov A, 91
	store A, B
	mov B, BP
	add B, -216
	mov A, 67
	store A, B
	mov B, BP
	add B, -215
	mov A, 126
	store A, B
	mov B, BP
	add B, -214
	mov A, 126
	store A, B
	mov B, BP
	add B, -213
	mov A, 126
	store A, B
	mov B, BP
	add B, -212
	mov A, 126
	store A, B
	mov B, BP
	add B, -211
	mov A, 126
	store A, B
	mov B, BP
	add B, -210
	mov A, 27
	store A, B
	mov B, BP
	add B, -209
	mov A, 91
	store A, B
	mov B, BP
	add B, -208
	mov A, 66
	store A, B
	mov B, BP
	add B, -207
	mov A, 126
	store A, B
	mov B, BP
	add B, -206
	mov A, 126
	store A, B
	mov B, BP
	add B, -205
	mov A, 126
	store A, B
	mov B, BP
	add B, -204
	mov A, 126
	store A, B
	mov B, BP
	add B, -203
	mov A, 126
	store A, B
	mov B, BP
	add B, -202
	mov A, 27
	store A, B
	mov B, BP
	add B, -201
	mov A, 91
	store A, B
	mov B, BP
	add B, -200
	mov A, 66
	store A, B
	mov B, BP
	add B, -199
	mov A, 27
	store A, B
	mov B, BP
	add B, -198
	mov A, 91
	store A, B
	mov B, BP
	add B, -197
	mov A, 68
	store A, B
	mov B, BP
	add B, -196
	mov A, 126
	store A, B
	mov B, BP
	add B, -195
	mov A, 126
	store A, B
	mov B, BP
	add B, -194
	mov A, 126
	store A, B
	mov B, BP
	add B, -193
	mov A, 126
	store A, B
	mov B, BP
	add B, -192
	mov A, 126
	store A, B
	mov B, BP
	add B, -191
	mov A, 27
	store A, B
	mov B, BP
	add B, -190
	mov A, 91
	store A, B
	mov B, BP
	add B, -189
	mov A, 66
	store A, B
	mov B, BP
	add B, -188
	mov A, 126
	store A, B
	mov B, BP
	add B, -187
	mov A, 126
	store A, B
	mov B, BP
	add B, -186
	mov A, 126
	store A, B
	mov B, BP
	add B, -185
	mov A, 126
	store A, B
	mov B, BP
	add B, -184
	mov A, 126
	store A, B
	mov B, BP
	add B, -183
	mov A, 0
	store A, B
	.loc 1 52 0
	#     
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -260
	mov A, 27
	store A, B
	mov B, BP
	add B, -259
	mov A, 91
	store A, B
	mov B, BP
	add B, -258
	mov A, 65
	store A, B
	mov B, BP
	add B, -257
	mov A, 27
	store A, B
	mov B, BP
	add B, -256
	mov A, 91
	store A, B
	mov B, BP
	add B, -255
	mov A, 67
	store A, B
	mov B, BP
	add B, -254
	mov A, 126
	store A, B
	mov B, BP
	add B, -253
	mov A, 126
	store A, B
	mov B, BP
	add B, -252
	mov A, 126
	store A, B
	mov B, BP
	add B, -251
	mov A, 126
	store A, B
	mov B, BP
	add B, -250
	mov A, 126
	store A, B
	mov B, BP
	add B, -249
	mov A, 27
	store A, B
	mov B, BP
	add B, -248
	mov A, 91
	store A, B
	mov B, BP
	add B, -247
	mov A, 65
	store A, B
	mov B, BP
	add B, -246
	mov A, 126
	store A, B
	mov B, BP
	add B, -245
	mov A, 126
	store A, B
	mov B, BP
	add B, -244
	mov A, 126
	store A, B
	mov B, BP
	add B, -243
	mov A, 126
	store A, B
	mov B, BP
	add B, -242
	mov A, 126
	store A, B
	mov B, BP
	add B, -241
	mov A, 27
	store A, B
	mov B, BP
	add B, -240
	mov A, 91
	store A, B
	mov B, BP
	add B, -239
	mov A, 65
	store A, B
	mov B, BP
	add B, -238
	mov A, 27
	store A, B
	mov B, BP
	add B, -237
	mov A, 91
	store A, B
	mov B, BP
	add B, -236
	mov A, 68
	store A, B
	mov B, BP
	add B, -235
	mov A, 126
	store A, B
	mov B, BP
	add B, -234
	mov A, 126
	store A, B
	mov B, BP
	add B, -233
	mov A, 126
	store A, B
	mov B, BP
	add B, -232
	mov A, 126
	store A, B
	mov B, BP
	add B, -231
	mov A, 126
	store A, B
	mov B, BP
	add B, -230
	mov A, 27
	store A, B
	mov B, BP
	add B, -229
	mov A, 91
	store A, B
	mov B, BP
	add B, -228
	mov A, 65
	store A, B
	mov B, BP
	add B, -227
	mov A, 126
	store A, B
	mov B, BP
	add B, -226
	mov A, 126
	store A, B
	mov B, BP
	add B, -225
	mov A, 126
	store A, B
	mov B, BP
	add B, -224
	mov A, 126
	store A, B
	mov B, BP
	add B, -223
	mov A, 126
	store A, B
	mov B, BP
	add B, -222
	mov A, 0
	store A, B
	.loc 1 54 0
	#     int row_last = -1;
	mov A, 0
	mov B, SP
.data
	.L245:
	.string "Draw pattern with mouse to get flag"
.text
	mov A, .L245
	mov B, BP
	add B, -261
	store A, B
	.loc 1 55 0
	#     int col_last = -1;
	mov A, 0
	mov B, SP
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -262
	store A, B
	.loc 1 56 0
	#     unsigned char entries[10];
	mov A, 0
	mov B, SP
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -263
	store A, B
	.loc 1 57 0
	#     int num_entries;
	.loc 1 58 0
	# 
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
.data
	.L246:
	.string "\x1b[?1002h"
.text
	mov A, .L246
	mov B, BP
	add B, -275
	store A, B
	.L0:
	mov B, BP
	add B, -275
	load A, B
	mov B, A
	load A, B
	jeq .L247, A, 0
	mov B, BP
	add B, -275
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -275
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
	jmp .L248
	.L247:
	jmp .L1
	.L248:
	jmp .L0
	.L1:
	mov A, 0
	mov B, SP
.data
	.L249:
	.string "\x1b[?25l"
.text
	mov A, .L249
	mov B, BP
	add B, -276
	store A, B
	.L2:
	mov B, BP
	add B, -276
	load A, B
	mov B, A
	load A, B
	jeq .L250, A, 0
	mov B, BP
	add B, -276
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -276
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
	jmp .L251
	.L250:
	jmp .L3
	.L251:
	jmp .L2
	.L3:
	.loc 1 62 0
	#     rop_puts("\e[H\e[2J\e[3J"); // clear screen
	.L244:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
.data
	.L252:
	.string "\x1b[H\x1b[2J\x1b[3J"
.text
	mov A, .L252
	mov B, BP
	add B, -277
	store A, B
	.L4:
	mov B, BP
	add B, -277
	load A, B
	mov B, A
	load A, B
	jeq .L253, A, 0
	mov B, BP
	add B, -277
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -277
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
	jmp .L254
	.L253:
	jmp .L5
	.L254:
	jmp .L4
	.L5:
	mov A, 0
	mov B, SP
	.loc 1 54 0
	#     int row_last = -1;
	mov B, BP
	add B, -261
	load A, B
	mov B, BP
	add B, -278
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L6:
	mov B, BP
	add B, -278
	load A, B
	mov B, A
	load A, B
	jeq .L255, A, 0
	mov B, BP
	add B, -278
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -278
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
	jmp .L256
	.L255:
	jmp .L7
	.L256:
	jmp .L6
	.L7:
	.loc 1 69 0
	#         }
	.loc 1 66 0
	#         for (int col = 0; col < 3; col++) {
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -279
	mov A, 0
	store A, B
	.loc 1 69 0
	#         }
	.L8:
	.loc 1 66 0
	#         for (int col = 0; col < 3; col++) {
	mov B, BP
	add B, -279
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L257, A, 0
	jmp .L258
	.L257:
	.loc 1 69 0
	#         }
	jmp .L10
	.L258:
	.loc 1 67 0
	#             rop_setpos(row, col);
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -280
	mov A, 0
	store A, B
	.loc 1 69 0
	#         }
	.L11:
	.loc 1 67 0
	#             rop_setpos(row, col);
	mov B, BP
	add B, -280
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L259, A, 0
	jmp .L260
	.L259:
	.loc 1 69 0
	#         }
	jmp .L13
	.L260:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	.loc 1 66 0
	#         for (int col = 0; col < 3; col++) {
	mov B, BP
	add B, -279
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -281
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -281
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -281
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -281
	load A, B
	mov B, BP
	add B, -282
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -282
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L261, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L262
	.L261:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -286
	mov A, 0
	store A, B
	mov B, BP
	add B, -285
	mov A, 0
	store A, B
	mov B, BP
	add B, -284
	mov A, 0
	store A, B
	mov B, BP
	add B, -283
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776930
	mov B, BP
	add B, -287
	store A, B
	.loc 1 15 0
	#         } \
	.L14:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -282
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L263, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -289
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -282
	load A, B
	mov B, BP
	add B, -290
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L16:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -290
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L264, A, 0
	mov B, BP
	add B, -290
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -290
	store A, B
	mov B, BP
	add B, -289
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -289
	store A, B
	load A, SP
	add SP, 1
	jmp .L265
	.L264:
	jmp .L17
	.L265:
	jmp .L16
	.L17:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -290
	load A, B
	mov B, BP
	add B, -288
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -289
	load A, B
	mov B, BP
	add B, -282
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -288
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -287
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -287
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -287
	store A, B
	load A, SP
	add SP, 1
	jmp .L266
	.L263:
	.loc 1 15 0
	#         } \
	jmp .L15
	.L266:
	jmp .L14
	.L15:
	.loc 1 19 0
	#         } while (i != s); \
	.L18:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -287
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -287
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -287
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -287
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776930
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L267, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L18
	.L267:
	.L19:
	.L262:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	.loc 1 67 0
	#             rop_setpos(row, col);
	mov B, BP
	add B, -280
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -281
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -281
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -281
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -281
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -281
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -281
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -281
	load A, B
	mov B, BP
	add B, -291
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -291
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L268, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L269
	.L268:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -295
	mov A, 0
	store A, B
	mov B, BP
	add B, -294
	mov A, 0
	store A, B
	mov B, BP
	add B, -293
	mov A, 0
	store A, B
	mov B, BP
	add B, -292
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776921
	mov B, BP
	add B, -296
	store A, B
	.loc 1 15 0
	#         } \
	.L20:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -291
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L270, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -298
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -291
	load A, B
	mov B, BP
	add B, -299
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L22:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -299
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L271, A, 0
	mov B, BP
	add B, -299
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -299
	store A, B
	mov B, BP
	add B, -298
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -298
	store A, B
	load A, SP
	add SP, 1
	jmp .L272
	.L271:
	jmp .L23
	.L272:
	jmp .L22
	.L23:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -299
	load A, B
	mov B, BP
	add B, -297
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -298
	load A, B
	mov B, BP
	add B, -291
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -297
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -296
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -296
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -296
	store A, B
	load A, SP
	add SP, 1
	jmp .L273
	.L270:
	.loc 1 15 0
	#         } \
	jmp .L21
	.L273:
	jmp .L20
	.L21:
	.loc 1 19 0
	#         } while (i != s); \
	.L24:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -296
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -296
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -296
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -296
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776921
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L274, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L24
	.L274:
	.L25:
	.L269:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 69 0
	#         }
	mov A, 35
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.L12:
	.loc 1 67 0
	#             rop_setpos(row, col);
	mov B, BP
	add B, -280
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -280
	store A, B
	load A, SP
	add SP, 1
	.loc 1 69 0
	#         }
	jmp .L11
	.L13:
	.L9:
	.loc 1 66 0
	#         for (int col = 0; col < 3; col++) {
	mov B, BP
	add B, -279
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -279
	store A, B
	load A, SP
	add SP, 1
	.loc 1 69 0
	#         }
	jmp .L8
	.L10:
	.loc 1 73 0
	#     int num_read = 0;
	mov A, 0
	mov B, BP
	add B, -274
	store A, B
	.loc 1 74 0
	#     char motion;
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -300
	mov A, 0
	store A, B
	.loc 1 75 0
	#     int row, col;
	.loc 1 76 0
	#     while (1) {
	.loc 1 320 0
	#         } // switch(num_read)
	.L26:
	.loc 1 77 0
	#         char input = getchar();
	mov A, 1
	jeq .L275, A, 0
	.loc 1 320 0
	#         } // switch(num_read)
	.loc 1 78 0
	#         switch (num_read) {
	mov A, 0
	mov B, SP
	getc A
	jne .L276, A, 0
	mov A, -1
	.L276:
	mov B, BP
	add B, -304
	store A, B
	.loc 1 320 0
	#         } // switch(num_read)
	.loc 1 74 0
	#     char motion;
	mov B, BP
	add B, -300
	load A, B
	mov B, BP
	add B, -883
	store A, B
	.loc 1 320 0
	#         } // switch(num_read)
	mov B, BP
	add B, -883
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L277, A, 0
	jmp .L29
	.L277:
	mov B, BP
	add B, -883
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L278, A, 0
	jmp .L30
	.L278:
	mov B, BP
	add B, -883
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L279, A, 0
	jmp .L31
	.L279:
	mov B, BP
	add B, -883
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L280, A, 0
	jmp .L32
	.L280:
	mov B, BP
	add B, -883
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 4
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L281, A, 0
	jmp .L33
	.L281:
	mov B, BP
	add B, -883
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 5
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L282, A, 0
	jmp .L34
	.L282:
	jmp .L28
	.loc 1 82 0
	#             }
	.loc 1 80 0
	#             if (input == '\x1b') {
	.L29:
	.loc 1 82 0
	#             }
	.loc 1 80 0
	#             if (input == '\x1b') {
	.loc 1 78 0
	#         switch (num_read) {
	mov B, BP
	add B, -304
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 80 0
	#             if (input == '\x1b') {
	mov A, 27
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L283, A, 0
	.loc 1 82 0
	#             }
	.loc 1 74 0
	#     char motion;
	mov B, BP
	add B, -300
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -300
	store A, B
	load A, SP
	add SP, 1
	.L283:
	.loc 1 84 0
	#         case 1:
	jmp .L28
	.loc 1 89 0
	#             }
	.loc 1 85 0
	#             if (input == '[') {
	.L30:
	.loc 1 89 0
	#             }
	.loc 1 85 0
	#             if (input == '[') {
	.loc 1 78 0
	#         switch (num_read) {
	mov B, BP
	add B, -304
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 85 0
	#             if (input == '[') {
	mov A, 91
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L284, A, 0
	.loc 1 87 0
	#             } else {
	.loc 1 74 0
	#     char motion;
	mov B, BP
	add B, -300
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -300
	store A, B
	load A, SP
	add SP, 1
	jmp .L285
	.L284:
	.loc 1 89 0
	#             }
	mov A, 0
	mov B, BP
	add B, -300
	store A, B
	.L285:
	.loc 1 91 0
	#         case 2:
	jmp .L28
	.loc 1 96 0
	#             }
	.loc 1 92 0
	#             if (input == 'M') {
	.L31:
	.loc 1 96 0
	#             }
	.loc 1 92 0
	#             if (input == 'M') {
	.loc 1 78 0
	#         switch (num_read) {
	mov B, BP
	add B, -304
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 92 0
	#             if (input == 'M') {
	mov A, 77
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L286, A, 0
	.loc 1 94 0
	#             } else {
	.loc 1 74 0
	#     char motion;
	mov B, BP
	add B, -300
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -300
	store A, B
	load A, SP
	add SP, 1
	jmp .L287
	.L286:
	.loc 1 96 0
	#             }
	mov A, 0
	mov B, BP
	add B, -300
	store A, B
	.L287:
	.loc 1 98 0
	#         case 3:
	jmp .L28
	.loc 1 99 0
	#             motion = input;
	.L32:
	.loc 1 78 0
	#         switch (num_read) {
	mov B, BP
	add B, -304
	load A, B
	mov B, BP
	add B, -301
	store A, B
	.loc 1 101 0
	#             break;
	.loc 1 74 0
	#     char motion;
	mov B, BP
	add B, -300
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -300
	store A, B
	load A, SP
	add SP, 1
	.loc 1 102 0
	#         case 4:
	jmp .L28
	.loc 1 103 0
	#             col = input - 32;
	.L33:
	.loc 1 78 0
	#         switch (num_read) {
	mov B, BP
	add B, -304
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 103 0
	#             col = input - 32;
	mov A, 32
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -303
	store A, B
	.loc 1 105 0
	#             break;
	.loc 1 74 0
	#     char motion;
	mov B, BP
	add B, -300
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -300
	store A, B
	load A, SP
	add SP, 1
	.loc 1 106 0
	#         case 5:
	jmp .L28
	.loc 1 107 0
	#             row = input - 32;
	.L34:
	.loc 1 78 0
	#         switch (num_read) {
	mov B, BP
	add B, -304
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 107 0
	#             row = input - 32;
	mov A, 32
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -302
	store A, B
	.loc 1 109 0
	#             /******************************
	mov A, 0
	mov B, BP
	add B, -300
	store A, B
	.loc 1 318 0
	#             }
	.loc 1 113 0
	#                 //printf("\e[Hrow: %2d col: %2d\n", row, col);
	.loc 1 75 0
	#     int row, col;
	mov B, BP
	add B, -301
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 113 0
	#                 //printf("\e[Hrow: %2d col: %2d\n", row, col);
	mov A, 64
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	mov B, 1
	jne .L288, A, 0
	.loc 1 75 0
	#     int row, col;
	mov B, BP
	add B, -301
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 113 0
	#                 //printf("\e[Hrow: %2d col: %2d\n", row, col);
	mov A, 32
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	mov B, A
	ne B, 0
	.L288:
	mov A, B
	jeq .L289, A, 0
	.loc 1 214 0
	#                 } // if motionevent on point
	.loc 1 115 0
	#                 switch (row) {
	mov A, 0
	mov B, SP
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -305
	store A, B
	mov A, 0
	mov B, SP
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -306
	store A, B
	.loc 1 119 0
	#                 }
	.loc 1 76 0
	#     while (1) {
	mov B, BP
	add B, -302
	load A, B
	mov B, BP
	add B, -307
	store A, B
	.loc 1 119 0
	#                 }
	mov B, BP
	add B, -307
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 5
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L290, A, 0
	jmp .L36
	.L290:
	mov B, BP
	add B, -307
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L291, A, 0
	jmp .L37
	.L291:
	mov B, BP
	add B, -307
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 15
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L292, A, 0
	jmp .L38
	.L292:
	jmp .L35
	.loc 1 117 0
	#                     case 10: row_small = 1; break;
	.L36:
	mov A, 0
	mov B, BP
	add B, -305
	store A, B
	jmp .L35
	.loc 1 118 0
	#                     case 15: row_small = 2; break;
	.L37:
	mov A, 1
	mov B, BP
	add B, -305
	store A, B
	jmp .L35
	.loc 1 119 0
	#                 }
	.L38:
	mov A, 2
	mov B, BP
	add B, -305
	store A, B
	jmp .L35
	.L35:
	.loc 1 124 0
	#                 }
	.loc 1 76 0
	#     while (1) {
	mov B, BP
	add B, -303
	load A, B
	mov B, BP
	add B, -308
	store A, B
	.loc 1 124 0
	#                 }
	mov B, BP
	add B, -308
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L293, A, 0
	jmp .L40
	.L293:
	mov B, BP
	add B, -308
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 20
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L294, A, 0
	jmp .L41
	.L294:
	mov B, BP
	add B, -308
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 30
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L295, A, 0
	jmp .L42
	.L295:
	jmp .L39
	.loc 1 122 0
	#                     case 20: col_small = 1; break;
	.L40:
	mov A, 0
	mov B, BP
	add B, -306
	store A, B
	jmp .L39
	.loc 1 123 0
	#                     case 30: col_small = 2; break;
	.L41:
	mov A, 1
	mov B, BP
	add B, -306
	store A, B
	jmp .L39
	.loc 1 124 0
	#                 }
	.L42:
	mov A, 2
	mov B, BP
	add B, -306
	store A, B
	jmp .L39
	.L39:
	.loc 1 214 0
	#                 } // if motionevent on point
	.loc 1 126 0
	#                     if (num_entries != sizeof(entries)) {
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -305
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 126 0
	#                     if (num_entries != sizeof(entries)) {
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	mov B, 0
	jeq .L297, A, 0
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -306
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 126 0
	#                     if (num_entries != sizeof(entries)) {
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	mov B, A
	ne B, 0
	.L297:
	mov A, B
	mov B, 0
	jeq .L296, A, 0
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -305
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 55 0
	#     int col_last = -1;
	mov B, BP
	add B, -262
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	mov B, 1
	jne .L298, A, 0
	.loc 1 126 0
	#                     if (num_entries != sizeof(entries)) {
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -306
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 56 0
	#     unsigned char entries[10];
	mov B, BP
	add B, -263
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	mov B, A
	ne B, 0
	.L298:
	mov A, B
	mov B, A
	ne B, 0
	.L296:
	mov A, B
	jeq .L299, A, 0
	.loc 1 214 0
	#                 } // if motionevent on point
	.loc 1 204 0
	#             assert(0);
	.loc 1 127 0
	#                         entries[num_entries] = row_small + row_small + row_small + col_small;
	.loc 1 58 0
	# 
	mov B, BP
	add B, -274
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 127 0
	#                         entries[num_entries] = row_small + row_small + row_small + col_small;
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L300, A, 0
	.loc 1 204 0
	#             assert(0);
	.loc 1 128 0
	#                         num_entries++;
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -305
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -305
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -305
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -306
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 128 0
	#                         num_entries++;
	.loc 1 57 0
	#     int num_entries;
	mov A, BP
	add A, 16776943
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 58 0
	# 
	mov B, BP
	add B, -274
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
	.loc 1 129 0
	#                         if (row_last != -1) {
	.loc 1 58 0
	# 
	mov B, BP
	add B, -274
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -274
	store A, B
	load A, SP
	add SP, 1
	.loc 1 204 0
	#             assert(0);
	.loc 1 130 0
	#                             /******************************
	.loc 1 55 0
	#     int col_last = -1;
	mov B, BP
	add B, -262
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 130 0
	#                             /******************************
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L301, A, 0
	.loc 1 204 0
	#             assert(0);
	.loc 1 134 0
	# int c1 = col_last;
	mov A, 0
	mov B, SP
	.loc 1 55 0
	#     int col_last = -1;
	mov B, BP
	add B, -262
	load A, B
	mov B, BP
	add B, -309
	store A, B
	.loc 1 135 0
	# int r2 = row_small;
	mov A, 0
	mov B, SP
	.loc 1 56 0
	#     unsigned char entries[10];
	mov B, BP
	add B, -263
	load A, B
	mov B, BP
	add B, -310
	store A, B
	.loc 1 136 0
	# int c2 = col_small;
	mov A, 0
	mov B, SP
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -305
	load A, B
	mov B, BP
	add B, -311
	store A, B
	.loc 1 137 0
	# if (c1 == c2) {
	mov A, 0
	mov B, SP
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -306
	load A, B
	mov B, BP
	add B, -312
	store A, B
	.loc 1 204 0
	#             assert(0);
	.loc 1 138 0
	#     // vertical
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L302, A, 0
	.loc 1 155 0
	#     }
	.loc 1 140 0
	#         case -2:
	.loc 1 136 0
	# int c2 = col_small;
	mov B, BP
	add B, -311
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 134 0
	# int c1 = col_last;
	mov B, BP
	add B, -309
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -393
	store A, B
	.loc 1 155 0
	#     }
	mov B, BP
	add B, -393
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 16777214
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L303, A, 0
	jmp .L44
	.L303:
	mov B, BP
	add B, -393
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L304, A, 0
	jmp .L45
	.L304:
	mov B, BP
	add B, -393
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 16777215
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L305, A, 0
	jmp .L74
	.L305:
	mov B, BP
	add B, -393
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L306, A, 0
	jmp .L89
	.L306:
	jmp .L43
	.loc 1 34 0
	# }
	.loc 1 141 0
	#         case 2:
	.L44:
	.loc 1 34 0
	# }
	.loc 1 141 0
	#         case 2:
	.L45:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -313
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -313
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -313
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -313
	load A, B
	mov B, BP
	add B, -314
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -314
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L307, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L308
	.L307:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -318
	mov A, 0
	store A, B
	mov B, BP
	add B, -317
	mov A, 0
	store A, B
	mov B, BP
	add B, -316
	mov A, 0
	store A, B
	mov B, BP
	add B, -315
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776898
	mov B, BP
	add B, -319
	store A, B
	.loc 1 15 0
	#         } \
	.L46:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -314
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L309, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -321
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -314
	load A, B
	mov B, BP
	add B, -322
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L48:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -322
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L310, A, 0
	mov B, BP
	add B, -322
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -322
	store A, B
	mov B, BP
	add B, -321
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -321
	store A, B
	load A, SP
	add SP, 1
	jmp .L311
	.L310:
	jmp .L49
	.L311:
	jmp .L48
	.L49:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -322
	load A, B
	mov B, BP
	add B, -320
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -321
	load A, B
	mov B, BP
	add B, -314
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -320
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -319
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -319
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -319
	store A, B
	load A, SP
	add SP, 1
	jmp .L312
	.L309:
	.loc 1 15 0
	#         } \
	jmp .L47
	.L312:
	jmp .L46
	.L47:
	.loc 1 19 0
	#         } while (i != s); \
	.L50:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -319
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -319
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -319
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -319
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776898
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L313, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L50
	.L313:
	.L51:
	.L308:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -313
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -313
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -313
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -313
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -313
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -313
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -313
	load A, B
	mov B, BP
	add B, -323
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -323
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L314, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L315
	.L314:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -327
	mov A, 0
	store A, B
	mov B, BP
	add B, -326
	mov A, 0
	store A, B
	mov B, BP
	add B, -325
	mov A, 0
	store A, B
	mov B, BP
	add B, -324
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776889
	mov B, BP
	add B, -328
	store A, B
	.loc 1 15 0
	#         } \
	.L52:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -323
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L316, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -330
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -323
	load A, B
	mov B, BP
	add B, -331
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L54:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -331
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L317, A, 0
	mov B, BP
	add B, -331
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -331
	store A, B
	mov B, BP
	add B, -330
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -330
	store A, B
	load A, SP
	add SP, 1
	jmp .L318
	.L317:
	jmp .L55
	.L318:
	jmp .L54
	.L55:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -331
	load A, B
	mov B, BP
	add B, -329
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -330
	load A, B
	mov B, BP
	add B, -323
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -329
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -328
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -328
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -328
	store A, B
	load A, SP
	add SP, 1
	jmp .L319
	.L316:
	.loc 1 15 0
	#         } \
	jmp .L53
	.L319:
	jmp .L52
	.L53:
	.loc 1 19 0
	#         } while (i != s); \
	.L56:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -328
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -328
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -328
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -328
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776889
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L320, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L56
	.L320:
	.L57:
	.L315:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 46 0
	#     const char line_11[]  = "\e[B\e[C\e[C~\e[C\e[B~\e[C\e[B~\e[C\e[B~";
	mov A, BP
	add A, 16777178
	mov B, BP
	add B, -332
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L58:
	mov B, BP
	add B, -332
	load A, B
	mov B, A
	load A, B
	jeq .L321, A, 0
	mov B, BP
	add B, -332
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -332
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
	jmp .L322
	.L321:
	jmp .L59
	.L322:
	jmp .L58
	.L59:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -333
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -333
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -333
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -333
	load A, B
	mov B, BP
	add B, -334
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -334
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L323, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L324
	.L323:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -338
	mov A, 0
	store A, B
	mov B, BP
	add B, -337
	mov A, 0
	store A, B
	mov B, BP
	add B, -336
	mov A, 0
	store A, B
	mov B, BP
	add B, -335
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776878
	mov B, BP
	add B, -339
	store A, B
	.loc 1 15 0
	#         } \
	.L60:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -334
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L325, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -341
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -334
	load A, B
	mov B, BP
	add B, -342
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L62:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -342
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L326, A, 0
	mov B, BP
	add B, -342
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -342
	store A, B
	mov B, BP
	add B, -341
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -341
	store A, B
	load A, SP
	add SP, 1
	jmp .L327
	.L326:
	jmp .L63
	.L327:
	jmp .L62
	.L63:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -342
	load A, B
	mov B, BP
	add B, -340
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -341
	load A, B
	mov B, BP
	add B, -334
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -340
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -339
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -339
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -339
	store A, B
	load A, SP
	add SP, 1
	jmp .L328
	.L325:
	.loc 1 15 0
	#         } \
	jmp .L61
	.L328:
	jmp .L60
	.L61:
	.loc 1 19 0
	#         } while (i != s); \
	.L64:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -339
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -339
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -339
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -339
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776878
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L329, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L64
	.L329:
	.L65:
	.L324:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -333
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -333
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -333
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -333
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -333
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -333
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -333
	load A, B
	mov B, BP
	add B, -343
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -343
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L330, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L331
	.L330:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -347
	mov A, 0
	store A, B
	mov B, BP
	add B, -346
	mov A, 0
	store A, B
	mov B, BP
	add B, -345
	mov A, 0
	store A, B
	mov B, BP
	add B, -344
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776869
	mov B, BP
	add B, -348
	store A, B
	.loc 1 15 0
	#         } \
	.L66:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -343
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L332, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -350
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -343
	load A, B
	mov B, BP
	add B, -351
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L68:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -351
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L333, A, 0
	mov B, BP
	add B, -351
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -351
	store A, B
	mov B, BP
	add B, -350
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -350
	store A, B
	load A, SP
	add SP, 1
	jmp .L334
	.L333:
	jmp .L69
	.L334:
	jmp .L68
	.L69:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -351
	load A, B
	mov B, BP
	add B, -349
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -350
	load A, B
	mov B, BP
	add B, -343
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -349
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -348
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -348
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -348
	store A, B
	load A, SP
	add SP, 1
	jmp .L335
	.L332:
	.loc 1 15 0
	#         } \
	jmp .L67
	.L335:
	jmp .L66
	.L67:
	.loc 1 19 0
	#         } while (i != s); \
	.L70:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -348
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -348
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -348
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -348
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776869
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L336, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L70
	.L336:
	.L71:
	.L331:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 46 0
	#     const char line_11[]  = "\e[B\e[C\e[C~\e[C\e[B~\e[C\e[B~\e[C\e[B~";
	mov A, BP
	add A, 16777178
	mov B, BP
	add B, -352
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L72:
	mov B, BP
	add B, -352
	load A, B
	mov B, A
	load A, B
	jeq .L337, A, 0
	mov B, BP
	add B, -352
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -352
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
	jmp .L338
	.L337:
	jmp .L73
	.L338:
	jmp .L72
	.L73:
	.loc 1 147 0
	#         case -1:
	jmp .L43
	.loc 1 34 0
	# }
	.loc 1 148 0
	#             rop_setpos(r2, c1);
	.L74:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	.loc 1 136 0
	# int c2 = col_small;
	mov B, BP
	add B, -311
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -353
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -353
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -353
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -353
	load A, B
	mov B, BP
	add B, -354
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -354
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L339, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L340
	.L339:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -358
	mov A, 0
	store A, B
	mov B, BP
	add B, -357
	mov A, 0
	store A, B
	mov B, BP
	add B, -356
	mov A, 0
	store A, B
	mov B, BP
	add B, -355
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776858
	mov B, BP
	add B, -359
	store A, B
	.loc 1 15 0
	#         } \
	.L75:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -354
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L341, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -361
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -354
	load A, B
	mov B, BP
	add B, -362
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L77:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -362
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L342, A, 0
	mov B, BP
	add B, -362
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -362
	store A, B
	mov B, BP
	add B, -361
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -361
	store A, B
	load A, SP
	add SP, 1
	jmp .L343
	.L342:
	jmp .L78
	.L343:
	jmp .L77
	.L78:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -362
	load A, B
	mov B, BP
	add B, -360
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -361
	load A, B
	mov B, BP
	add B, -354
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -360
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -359
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -359
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -359
	store A, B
	load A, SP
	add SP, 1
	jmp .L344
	.L341:
	.loc 1 15 0
	#         } \
	jmp .L76
	.L344:
	jmp .L75
	.L76:
	.loc 1 19 0
	#         } while (i != s); \
	.L79:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -359
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -359
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -359
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -359
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776858
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L345, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L79
	.L345:
	.L80:
	.L340:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -353
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -353
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -353
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -353
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -353
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -353
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -353
	load A, B
	mov B, BP
	add B, -363
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -363
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L346, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L347
	.L346:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -367
	mov A, 0
	store A, B
	mov B, BP
	add B, -366
	mov A, 0
	store A, B
	mov B, BP
	add B, -365
	mov A, 0
	store A, B
	mov B, BP
	add B, -364
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776849
	mov B, BP
	add B, -368
	store A, B
	.loc 1 15 0
	#         } \
	.L81:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -363
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L348, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -370
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -363
	load A, B
	mov B, BP
	add B, -371
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L83:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -371
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L349, A, 0
	mov B, BP
	add B, -371
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -371
	store A, B
	mov B, BP
	add B, -370
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -370
	store A, B
	load A, SP
	add SP, 1
	jmp .L350
	.L349:
	jmp .L84
	.L350:
	jmp .L83
	.L84:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -371
	load A, B
	mov B, BP
	add B, -369
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -370
	load A, B
	mov B, BP
	add B, -363
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -369
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -368
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -368
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -368
	store A, B
	load A, SP
	add SP, 1
	jmp .L351
	.L348:
	.loc 1 15 0
	#         } \
	jmp .L82
	.L351:
	jmp .L81
	.L82:
	.loc 1 19 0
	#         } while (i != s); \
	.L85:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -368
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -368
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -368
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -368
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776849
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L352, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L85
	.L352:
	.L86:
	.L347:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 46 0
	#     const char line_11[]  = "\e[B\e[C\e[C~\e[C\e[B~\e[C\e[B~\e[C\e[B~";
	mov A, BP
	add A, 16777178
	mov B, BP
	add B, -372
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L87:
	mov B, BP
	add B, -372
	load A, B
	mov B, A
	load A, B
	jeq .L353, A, 0
	mov B, BP
	add B, -372
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -372
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
	jmp .L354
	.L353:
	jmp .L88
	.L354:
	jmp .L87
	.L88:
	.loc 1 151 0
	#         case 1:
	jmp .L43
	.loc 1 34 0
	# }
	.loc 1 152 0
	#             rop_setpos(r1, c1);
	.L89:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	.loc 1 134 0
	# int c1 = col_last;
	mov B, BP
	add B, -309
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -373
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -373
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -373
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -373
	load A, B
	mov B, BP
	add B, -374
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -374
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L355, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L356
	.L355:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -378
	mov A, 0
	store A, B
	mov B, BP
	add B, -377
	mov A, 0
	store A, B
	mov B, BP
	add B, -376
	mov A, 0
	store A, B
	mov B, BP
	add B, -375
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776838
	mov B, BP
	add B, -379
	store A, B
	.loc 1 15 0
	#         } \
	.L90:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -374
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L357, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -381
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -374
	load A, B
	mov B, BP
	add B, -382
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L92:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -382
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L358, A, 0
	mov B, BP
	add B, -382
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -382
	store A, B
	mov B, BP
	add B, -381
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -381
	store A, B
	load A, SP
	add SP, 1
	jmp .L359
	.L358:
	jmp .L93
	.L359:
	jmp .L92
	.L93:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -382
	load A, B
	mov B, BP
	add B, -380
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -381
	load A, B
	mov B, BP
	add B, -374
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -380
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -379
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -379
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -379
	store A, B
	load A, SP
	add SP, 1
	jmp .L360
	.L357:
	.loc 1 15 0
	#         } \
	jmp .L91
	.L360:
	jmp .L90
	.L91:
	.loc 1 19 0
	#         } while (i != s); \
	.L94:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -379
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -379
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -379
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -379
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776838
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L361, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L94
	.L361:
	.L95:
	.L356:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -373
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -373
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -373
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -373
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -373
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -373
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -373
	load A, B
	mov B, BP
	add B, -383
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -383
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L362, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L363
	.L362:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -387
	mov A, 0
	store A, B
	mov B, BP
	add B, -386
	mov A, 0
	store A, B
	mov B, BP
	add B, -385
	mov A, 0
	store A, B
	mov B, BP
	add B, -384
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776829
	mov B, BP
	add B, -388
	store A, B
	.loc 1 15 0
	#         } \
	.L96:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -383
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L364, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -390
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -383
	load A, B
	mov B, BP
	add B, -391
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L98:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -391
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L365, A, 0
	mov B, BP
	add B, -391
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -391
	store A, B
	mov B, BP
	add B, -390
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -390
	store A, B
	load A, SP
	add SP, 1
	jmp .L366
	.L365:
	jmp .L99
	.L366:
	jmp .L98
	.L99:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -391
	load A, B
	mov B, BP
	add B, -389
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -390
	load A, B
	mov B, BP
	add B, -383
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -389
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -388
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -388
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -388
	store A, B
	load A, SP
	add SP, 1
	jmp .L367
	.L364:
	.loc 1 15 0
	#         } \
	jmp .L97
	.L367:
	jmp .L96
	.L97:
	.loc 1 19 0
	#         } while (i != s); \
	.L100:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -388
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -388
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -388
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -388
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776829
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L368, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L100
	.L368:
	.L101:
	.L363:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 46 0
	#     const char line_11[]  = "\e[B\e[C\e[C~\e[C\e[B~\e[C\e[B~\e[C\e[B~";
	mov A, BP
	add A, 16777178
	mov B, BP
	add B, -392
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L102:
	mov B, BP
	add B, -392
	load A, B
	mov B, A
	load A, B
	jeq .L369, A, 0
	mov B, BP
	add B, -392
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -392
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
	jmp .L370
	.L369:
	jmp .L103
	.L370:
	jmp .L102
	.L103:
	.loc 1 155 0
	#     }
	jmp .L43
	.L43:
	jmp .L371
	.L302:
	.loc 1 204 0
	#             assert(0);
	.loc 1 164 0
	#     }
	.loc 1 158 0
	#         int temp = c1;
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L372, A, 0
	.loc 1 164 0
	#     }
	.loc 1 159 0
	#         c1 = c2;
	mov A, 0
	mov B, SP
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov B, BP
	add B, -394
	store A, B
	.loc 1 160 0
	#         c2 = temp;
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov B, BP
	add B, -310
	store A, B
	.loc 1 161 0
	#         temp = r1;
	.loc 1 159 0
	#         c1 = c2;
	mov B, BP
	add B, -394
	load A, B
	mov B, BP
	add B, -312
	store A, B
	.loc 1 162 0
	#         r1 = r2;
	.loc 1 134 0
	# int c1 = col_last;
	mov B, BP
	add B, -309
	load A, B
	mov B, BP
	add B, -394
	store A, B
	.loc 1 163 0
	#         r2 = temp;
	.loc 1 136 0
	# int c2 = col_small;
	mov B, BP
	add B, -311
	load A, B
	mov B, BP
	add B, -309
	store A, B
	.loc 1 164 0
	#     }
	.loc 1 159 0
	#         c1 = c2;
	mov B, BP
	add B, -394
	load A, B
	mov B, BP
	add B, -311
	store A, B
	.L372:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	.loc 1 134 0
	# int c1 = col_last;
	mov B, BP
	add B, -309
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -395
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -395
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -395
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -395
	load A, B
	mov B, BP
	add B, -396
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -396
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L373, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L374
	.L373:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -400
	mov A, 0
	store A, B
	mov B, BP
	add B, -399
	mov A, 0
	store A, B
	mov B, BP
	add B, -398
	mov A, 0
	store A, B
	mov B, BP
	add B, -397
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776816
	mov B, BP
	add B, -401
	store A, B
	.loc 1 15 0
	#         } \
	.L104:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -396
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L375, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -403
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -396
	load A, B
	mov B, BP
	add B, -404
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L106:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -404
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L376, A, 0
	mov B, BP
	add B, -404
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -404
	store A, B
	mov B, BP
	add B, -403
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -403
	store A, B
	load A, SP
	add SP, 1
	jmp .L377
	.L376:
	jmp .L107
	.L377:
	jmp .L106
	.L107:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -404
	load A, B
	mov B, BP
	add B, -402
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -403
	load A, B
	mov B, BP
	add B, -396
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -402
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -401
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -401
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -401
	store A, B
	load A, SP
	add SP, 1
	jmp .L378
	.L375:
	.loc 1 15 0
	#         } \
	jmp .L105
	.L378:
	jmp .L104
	.L105:
	.loc 1 19 0
	#         } while (i != s); \
	.L108:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -401
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -401
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -401
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -401
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776816
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L379, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L108
	.L379:
	.L109:
	.L374:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -395
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -395
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -395
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -395
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -395
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -395
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -395
	load A, B
	mov B, BP
	add B, -405
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -405
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L380, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L381
	.L380:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -409
	mov A, 0
	store A, B
	mov B, BP
	add B, -408
	mov A, 0
	store A, B
	mov B, BP
	add B, -407
	mov A, 0
	store A, B
	mov B, BP
	add B, -406
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776807
	mov B, BP
	add B, -410
	store A, B
	.loc 1 15 0
	#         } \
	.L110:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -405
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L382, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -412
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -405
	load A, B
	mov B, BP
	add B, -413
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L112:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -413
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L383, A, 0
	mov B, BP
	add B, -413
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -413
	store A, B
	mov B, BP
	add B, -412
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -412
	store A, B
	load A, SP
	add SP, 1
	jmp .L384
	.L383:
	jmp .L113
	.L384:
	jmp .L112
	.L113:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -413
	load A, B
	mov B, BP
	add B, -411
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -412
	load A, B
	mov B, BP
	add B, -405
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -411
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -410
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -410
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -410
	store A, B
	load A, SP
	add SP, 1
	jmp .L385
	.L382:
	.loc 1 15 0
	#         } \
	jmp .L111
	.L385:
	jmp .L110
	.L111:
	.loc 1 19 0
	#         } while (i != s); \
	.L114:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -410
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -410
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -410
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -410
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776807
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L386, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L114
	.L386:
	.L115:
	.L381:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 204 0
	#             assert(0);
	.loc 1 168 0
	#         case -2:
	.loc 1 136 0
	# int c2 = col_small;
	mov B, BP
	add B, -311
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 134 0
	# int c1 = col_last;
	mov B, BP
	add B, -309
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -488
	store A, B
	.loc 1 204 0
	#             assert(0);
	mov B, BP
	add B, -488
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 16777214
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L387, A, 0
	jmp .L117
	.L387:
	mov B, BP
	add B, -488
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 16777215
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L388, A, 0
	jmp .L140
	.L388:
	mov B, BP
	add B, -488
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L389, A, 0
	jmp .L149
	.L389:
	mov B, BP
	add B, -488
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L390, A, 0
	jmp .L169
	.L390:
	mov B, BP
	add B, -488
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L391, A, 0
	jmp .L178
	.L391:
	jmp .L201
	.loc 1 173 0
	#             }
	.loc 1 169 0
	#             switch (c2 - c1) {
	.L117:
	.loc 1 173 0
	#             }
	.loc 1 169 0
	#             switch (c2 - c1) {
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -436
	store A, B
	.loc 1 173 0
	#             }
	mov B, BP
	add B, -436
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L392, A, 0
	jmp .L119
	.L392:
	mov B, BP
	add B, -436
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L393, A, 0
	jmp .L122
	.L393:
	jmp .L139
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 171 0
	#                 case 2: rop_puts(line_11$); rop_setpos(1, 1); rop_puts(line_11$); break;
	.L119:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 50 0
	#     const char line_12[]  = "\e[B\e[C~~~~~\e[B~~~~~\e[B\e[D~~~~~\e[B~~~~~";
	mov A, BP
	add A, 16777034
	mov B, BP
	add B, -414
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L120:
	mov B, BP
	add B, -414
	load A, B
	mov B, A
	load A, B
	jeq .L394, A, 0
	mov B, BP
	add B, -414
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -414
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
	jmp .L395
	.L394:
	jmp .L121
	.L395:
	jmp .L120
	.L121:
	.loc 1 171 0
	#                 case 2: rop_puts(line_11$); rop_setpos(1, 1); rop_puts(line_11$); break;
	jmp .L118
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 172 0
	#                 default: assert(0);
	.L122:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 48 0
	#     const char line_21[]  = "\e[B\e[C~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~";
	mov A, BP
	add A, 16777114
	mov B, BP
	add B, -415
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L123:
	mov B, BP
	add B, -415
	load A, B
	mov B, A
	load A, B
	jeq .L396, A, 0
	mov B, BP
	add B, -415
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -415
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
	jmp .L397
	.L396:
	jmp .L124
	.L397:
	jmp .L123
	.L124:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -416
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -416
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -416
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -416
	load A, B
	mov B, BP
	add B, -417
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -417
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L398, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L399
	.L398:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -421
	mov A, 0
	store A, B
	mov B, BP
	add B, -420
	mov A, 0
	store A, B
	mov B, BP
	add B, -419
	mov A, 0
	store A, B
	mov B, BP
	add B, -418
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776795
	mov B, BP
	add B, -422
	store A, B
	.loc 1 15 0
	#         } \
	.L125:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -417
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L400, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -424
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -417
	load A, B
	mov B, BP
	add B, -425
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L127:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -425
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L401, A, 0
	mov B, BP
	add B, -425
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -425
	store A, B
	mov B, BP
	add B, -424
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -424
	store A, B
	load A, SP
	add SP, 1
	jmp .L402
	.L401:
	jmp .L128
	.L402:
	jmp .L127
	.L128:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -425
	load A, B
	mov B, BP
	add B, -423
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -424
	load A, B
	mov B, BP
	add B, -417
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -423
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -422
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -422
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -422
	store A, B
	load A, SP
	add SP, 1
	jmp .L403
	.L400:
	.loc 1 15 0
	#         } \
	jmp .L126
	.L403:
	jmp .L125
	.L126:
	.loc 1 19 0
	#         } while (i != s); \
	.L129:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -422
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -422
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -422
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -422
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776795
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L404, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L129
	.L404:
	.L130:
	.L399:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -416
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -416
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -416
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -416
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -416
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -416
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -416
	load A, B
	mov B, BP
	add B, -426
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -426
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L405, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L406
	.L405:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -430
	mov A, 0
	store A, B
	mov B, BP
	add B, -429
	mov A, 0
	store A, B
	mov B, BP
	add B, -428
	mov A, 0
	store A, B
	mov B, BP
	add B, -427
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776786
	mov B, BP
	add B, -431
	store A, B
	.loc 1 15 0
	#         } \
	.L131:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -426
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L407, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -433
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -426
	load A, B
	mov B, BP
	add B, -434
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L133:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -434
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L408, A, 0
	mov B, BP
	add B, -434
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -434
	store A, B
	mov B, BP
	add B, -433
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -433
	store A, B
	load A, SP
	add SP, 1
	jmp .L409
	.L408:
	jmp .L134
	.L409:
	jmp .L133
	.L134:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -434
	load A, B
	mov B, BP
	add B, -432
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -433
	load A, B
	mov B, BP
	add B, -426
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -432
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -431
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -431
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -431
	store A, B
	load A, SP
	add SP, 1
	jmp .L410
	.L407:
	.loc 1 15 0
	#         } \
	jmp .L132
	.L410:
	jmp .L131
	.L132:
	.loc 1 19 0
	#         } while (i != s); \
	.L135:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -431
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -431
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -431
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -431
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776786
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L411, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L135
	.L411:
	.L136:
	.L406:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 48 0
	#     const char line_21[]  = "\e[B\e[C~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~";
	mov A, BP
	add A, 16777114
	mov B, BP
	add B, -435
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L137:
	mov B, BP
	add B, -435
	load A, B
	mov B, A
	load A, B
	jeq .L412, A, 0
	mov B, BP
	add B, -435
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -435
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
	jmp .L413
	.L412:
	jmp .L138
	.L413:
	jmp .L137
	.L138:
	.loc 1 172 0
	#                 default: assert(0);
	jmp .L118
	.loc 1 173 0
	#             }
	.L139:
	.L118:
	.loc 1 175 0
	#         case -1:
	jmp .L116
	.loc 1 180 0
	#             }
	.loc 1 176 0
	#             switch (c2 - c1) {
	.L140:
	.loc 1 180 0
	#             }
	.loc 1 176 0
	#             switch (c2 - c1) {
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -439
	store A, B
	.loc 1 180 0
	#             }
	mov B, BP
	add B, -439
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L414, A, 0
	jmp .L142
	.L414:
	mov B, BP
	add B, -439
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L415, A, 0
	jmp .L145
	.L415:
	jmp .L148
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 178 0
	#                 case 2: rop_puts(line_12$); break;
	.L142:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 48 0
	#     const char line_21[]  = "\e[B\e[C~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~";
	mov A, BP
	add A, 16777114
	mov B, BP
	add B, -437
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L143:
	mov B, BP
	add B, -437
	load A, B
	mov B, A
	load A, B
	jeq .L416, A, 0
	mov B, BP
	add B, -437
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -437
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
	jmp .L417
	.L416:
	jmp .L144
	.L417:
	jmp .L143
	.L144:
	.loc 1 178 0
	#                 case 2: rop_puts(line_12$); break;
	jmp .L141
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 179 0
	#                 default: assert(0);
	.L145:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 52 0
	#     
	mov A, BP
	add A, 16776956
	mov B, BP
	add B, -438
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L146:
	mov B, BP
	add B, -438
	load A, B
	mov B, A
	load A, B
	jeq .L418, A, 0
	mov B, BP
	add B, -438
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -438
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
	jmp .L419
	.L418:
	jmp .L147
	.L419:
	jmp .L146
	.L147:
	.loc 1 179 0
	#                 default: assert(0);
	jmp .L141
	.loc 1 180 0
	#             }
	.L148:
	.L141:
	.loc 1 182 0
	#         case 0:
	jmp .L116
	.loc 1 186 0
	#                 // case 0: do nothing
	.loc 1 183 0
	#             switch (c2 - c1) {
	.L149:
	.loc 1 186 0
	#                 // case 0: do nothing
	.loc 1 183 0
	#             switch (c2 - c1) {
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -461
	store A, B
	.loc 1 186 0
	#                 // case 0: do nothing
	mov B, BP
	add B, -461
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L420, A, 0
	jmp .L151
	.L420:
	mov B, BP
	add B, -461
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L421, A, 0
	jmp .L166
	.L421:
	jmp .L150
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 185 0
	#                 case 1: rop_puts(line_01); break;
	.L151:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 45 0
	#     const char line_10[]  = "\e[B~\e[B\e[D~\e[B\e[D~\e[B\e[D~";
	mov A, BP
	add A, 16777204
	mov B, BP
	add B, -440
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L152:
	mov B, BP
	add B, -440
	load A, B
	mov B, A
	load A, B
	jeq .L422, A, 0
	mov B, BP
	add B, -440
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -440
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
	jmp .L423
	.L422:
	jmp .L153
	.L423:
	jmp .L152
	.L153:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	.loc 1 134 0
	# int c1 = col_last;
	mov B, BP
	add B, -309
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -441
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -441
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -441
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -441
	load A, B
	mov B, BP
	add B, -442
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -442
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L424, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L425
	.L424:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -446
	mov A, 0
	store A, B
	mov B, BP
	add B, -445
	mov A, 0
	store A, B
	mov B, BP
	add B, -444
	mov A, 0
	store A, B
	mov B, BP
	add B, -443
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776770
	mov B, BP
	add B, -447
	store A, B
	.loc 1 15 0
	#         } \
	.L154:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -442
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L426, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -449
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -442
	load A, B
	mov B, BP
	add B, -450
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L156:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -450
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L427, A, 0
	mov B, BP
	add B, -450
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -450
	store A, B
	mov B, BP
	add B, -449
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -449
	store A, B
	load A, SP
	add SP, 1
	jmp .L428
	.L427:
	jmp .L157
	.L428:
	jmp .L156
	.L157:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -450
	load A, B
	mov B, BP
	add B, -448
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -449
	load A, B
	mov B, BP
	add B, -442
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -448
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -447
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -447
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -447
	store A, B
	load A, SP
	add SP, 1
	jmp .L429
	.L426:
	.loc 1 15 0
	#         } \
	jmp .L155
	.L429:
	jmp .L154
	.L155:
	.loc 1 19 0
	#         } while (i != s); \
	.L158:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -447
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -447
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -447
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -447
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776770
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L430, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L158
	.L430:
	.L159:
	.L425:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -441
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -441
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -441
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -441
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -441
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -441
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -441
	load A, B
	mov B, BP
	add B, -451
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -451
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L431, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L432
	.L431:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -455
	mov A, 0
	store A, B
	mov B, BP
	add B, -454
	mov A, 0
	store A, B
	mov B, BP
	add B, -453
	mov A, 0
	store A, B
	mov B, BP
	add B, -452
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776761
	mov B, BP
	add B, -456
	store A, B
	.loc 1 15 0
	#         } \
	.L160:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -451
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L433, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -458
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -451
	load A, B
	mov B, BP
	add B, -459
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L162:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -459
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L434, A, 0
	mov B, BP
	add B, -459
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -459
	store A, B
	mov B, BP
	add B, -458
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -458
	store A, B
	load A, SP
	add SP, 1
	jmp .L435
	.L434:
	jmp .L163
	.L435:
	jmp .L162
	.L163:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -459
	load A, B
	mov B, BP
	add B, -457
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -458
	load A, B
	mov B, BP
	add B, -451
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -457
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -456
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -456
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -456
	store A, B
	load A, SP
	add SP, 1
	jmp .L436
	.L433:
	.loc 1 15 0
	#         } \
	jmp .L161
	.L436:
	jmp .L160
	.L161:
	.loc 1 19 0
	#         } while (i != s); \
	.L164:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -456
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -456
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -456
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -456
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776761
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L437, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L164
	.L437:
	.L165:
	.L432:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 186 0
	#                 // case 0: do nothing
	.L166:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 45 0
	#     const char line_10[]  = "\e[B~\e[B\e[D~\e[B\e[D~\e[B\e[D~";
	mov A, BP
	add A, 16777204
	mov B, BP
	add B, -460
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L167:
	mov B, BP
	add B, -460
	load A, B
	mov B, A
	load A, B
	jeq .L438, A, 0
	mov B, BP
	add B, -460
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -460
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
	jmp .L439
	.L438:
	jmp .L168
	.L439:
	jmp .L167
	.L168:
	.loc 1 186 0
	#                 // case 0: do nothing
	jmp .L150
	.L150:
	.loc 1 189 0
	#         case 1:
	jmp .L116
	.loc 1 194 0
	#             }
	.loc 1 190 0
	#             switch (c2 - c1) {
	.L169:
	.loc 1 194 0
	#             }
	.loc 1 190 0
	#             switch (c2 - c1) {
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -464
	store A, B
	.loc 1 194 0
	#             }
	mov B, BP
	add B, -464
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L440, A, 0
	jmp .L171
	.L440:
	mov B, BP
	add B, -464
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L441, A, 0
	jmp .L174
	.L441:
	jmp .L177
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 192 0
	#                 case 2: rop_puts(line_12); break;
	.L171:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 47 0
	#     const char line_11$[] = "\e[A\e[C\e[C~\e[C\e[A~\e[C\e[A~\e[C\e[A~";
	mov A, BP
	add A, 16777146
	mov B, BP
	add B, -462
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L172:
	mov B, BP
	add B, -462
	load A, B
	mov B, A
	load A, B
	jeq .L442, A, 0
	mov B, BP
	add B, -462
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -462
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
	jmp .L443
	.L442:
	jmp .L173
	.L443:
	jmp .L172
	.L173:
	.loc 1 192 0
	#                 case 2: rop_puts(line_12); break;
	jmp .L170
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 193 0
	#                 default: assert(0);
	.L174:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 51 0
	#     const char line_12$[] = "\e[A\e[C~~~~~\e[A~~~~~\e[A\e[D~~~~~\e[A~~~~~";
	mov A, BP
	add A, 16776995
	mov B, BP
	add B, -463
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L175:
	mov B, BP
	add B, -463
	load A, B
	mov B, A
	load A, B
	jeq .L444, A, 0
	mov B, BP
	add B, -463
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -463
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
	jmp .L445
	.L444:
	jmp .L176
	.L445:
	jmp .L175
	.L176:
	.loc 1 193 0
	#                 default: assert(0);
	jmp .L170
	.loc 1 194 0
	#             }
	.L177:
	.L170:
	.loc 1 196 0
	#         case 2:
	jmp .L116
	.loc 1 201 0
	#             }
	.loc 1 197 0
	#             switch (c2 - c1) {
	.L178:
	.loc 1 201 0
	#             }
	.loc 1 197 0
	#             switch (c2 - c1) {
	.loc 1 137 0
	# if (c1 == c2) {
	mov B, BP
	add B, -312
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 135 0
	# int r2 = row_small;
	mov B, BP
	add B, -310
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -487
	store A, B
	.loc 1 201 0
	#             }
	mov B, BP
	add B, -487
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L446, A, 0
	jmp .L180
	.L446:
	mov B, BP
	add B, -487
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L447, A, 0
	jmp .L183
	.L447:
	jmp .L200
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 199 0
	#                 case 2: rop_puts(line_11); rop_setpos(1, 1); rop_puts(line_11); break;
	.L180:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 49 0
	#     const char line_21$[] = "\e[A\e[C~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~";
	mov A, BP
	add A, 16777074
	mov B, BP
	add B, -465
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L181:
	mov B, BP
	add B, -465
	load A, B
	mov B, A
	load A, B
	jeq .L448, A, 0
	mov B, BP
	add B, -465
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -465
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
	jmp .L449
	.L448:
	jmp .L182
	.L449:
	jmp .L181
	.L182:
	.loc 1 199 0
	#                 case 2: rop_puts(line_11); rop_setpos(1, 1); rop_puts(line_11); break;
	jmp .L179
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.loc 1 200 0
	#                 default: assert(0);
	.L183:
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 47 0
	#     const char line_11$[] = "\e[A\e[C\e[C~\e[C\e[A~\e[C\e[A~\e[C\e[A~";
	mov A, BP
	add A, 16777146
	mov B, BP
	add B, -466
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L184:
	mov B, BP
	add B, -466
	load A, B
	mov B, A
	load A, B
	jeq .L450, A, 0
	mov B, BP
	add B, -466
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -466
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
	jmp .L451
	.L450:
	jmp .L185
	.L451:
	jmp .L184
	.L185:
	.loc 1 34 0
	# }
	.loc 1 24 0
	#     putchar('['); \
	mov A, 27
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 25 0
	#     int cpp_temp = (r) + 1; \
	mov A, 91
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov A, 0
	mov B, SP
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -467
	store A, B
	.loc 1 27 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -467
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -467
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -467
	load A, B
	mov B, BP
	add B, -468
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -468
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L452, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L453
	.L452:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -472
	mov A, 0
	store A, B
	mov B, BP
	add B, -471
	mov A, 0
	store A, B
	mov B, BP
	add B, -470
	mov A, 0
	store A, B
	mov B, BP
	add B, -469
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776744
	mov B, BP
	add B, -473
	store A, B
	.loc 1 15 0
	#         } \
	.L186:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -468
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L454, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -475
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -468
	load A, B
	mov B, BP
	add B, -476
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L188:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -476
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L455, A, 0
	mov B, BP
	add B, -476
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -476
	store A, B
	mov B, BP
	add B, -475
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -475
	store A, B
	load A, SP
	add SP, 1
	jmp .L456
	.L455:
	jmp .L189
	.L456:
	jmp .L188
	.L189:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -476
	load A, B
	mov B, BP
	add B, -474
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -475
	load A, B
	mov B, BP
	add B, -468
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -474
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -473
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -473
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -473
	store A, B
	load A, SP
	add SP, 1
	jmp .L457
	.L454:
	.loc 1 15 0
	#         } \
	jmp .L187
	.L457:
	jmp .L186
	.L187:
	.loc 1 19 0
	#         } while (i != s); \
	.L190:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -473
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -473
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -473
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -473
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776744
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L458, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L190
	.L458:
	.L191:
	.L453:
	.loc 1 29 0
	#     cpp_temp = (c) + 1; \
	mov A, 59
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 30 0
	#     cpp_temp += cpp_temp; \
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -467
	store A, B
	.loc 1 31 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -467
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -467
	store A, B
	.loc 1 32 0
	#     rop_putint(cpp_temp); \
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -467
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -467
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -467
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov A, 0
	mov B, SP
	.loc 1 26 0
	#     cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
	mov B, BP
	add B, -467
	load A, B
	mov B, BP
	add B, -477
	store A, B
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 6 0
	#         putchar('0'); \
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -477
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 6 0
	#         putchar('0'); \
	mov A, 0
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L459, A, 0
	.loc 1 7 0
	#     } else { \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	jmp .L460
	.L459:
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -481
	mov A, 0
	store A, B
	mov B, BP
	add B, -480
	mov A, 0
	store A, B
	mov B, BP
	add B, -479
	mov A, 0
	store A, B
	mov B, BP
	add B, -478
	mov A, 0
	store A, B
	.loc 1 10 0
	#         while (0 < x) { \
	mov A, 0
	mov B, SP
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776735
	mov B, BP
	add B, -482
	store A, B
	.loc 1 15 0
	#         } \
	.L192:
	.loc 1 11 0
	#             int rem; \
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -477
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L461, A, 0
	.loc 1 15 0
	#         } \
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -484
	mov A, 0
	store A, B
	mov A, 0
	mov B, SP
	.loc 1 5 0
	#     if (x == 0) { \
	mov B, BP
	add B, -477
	load A, B
	mov B, BP
	add B, -485
	store A, B
	.loc 1 3 0
	# #define rop_putint(xx) {\
	.L194:
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov B, BP
	add B, -485
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L462, A, 0
	mov B, BP
	add B, -485
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -485
	store A, B
	mov B, BP
	add B, -484
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -484
	store A, B
	load A, SP
	add SP, 1
	jmp .L463
	.L462:
	jmp .L195
	.L463:
	jmp .L194
	.L195:
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -485
	load A, B
	mov B, BP
	add B, -483
	store A, B
	.loc 1 13 0
	#             *i = '0' + rem; \
	.loc 1 3 0
	# #define rop_putint(xx) {\
	mov B, BP
	add B, -484
	load A, B
	mov B, BP
	add B, -477
	store A, B
	.loc 1 14 0
	#             i++; \
	mov A, 48
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 12 0
	#             rop_divmod(x, 10, rem); \
	mov B, BP
	add B, -483
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -482
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 15 0
	#         } \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -482
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -482
	store A, B
	load A, SP
	add SP, 1
	jmp .L464
	.L461:
	.loc 1 15 0
	#         } \
	jmp .L193
	.L464:
	jmp .L192
	.L193:
	.loc 1 19 0
	#         } while (i != s); \
	.L196:
	.loc 1 18 0
	#             putchar(*i); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -482
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	sub A, 1
	mov B, BP
	add B, -482
	store A, B
	load A, SP
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -482
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 10 0
	#         while (0 < x) { \
	mov B, BP
	add B, -482
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 19 0
	#         } while (i != s); \
	.loc 1 9 0
	#         char *i = s; \
	mov A, BP
	add A, 16776735
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L465, A, 0
	.loc 1 19 0
	#         } while (i != s); \
	jmp .L196
	.L465:
	.L197:
	.L460:
	.loc 1 34 0
	# }
	mov A, 72
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	putc A
	add SP, 1
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	mov A, 0
	mov B, SP
	.loc 1 47 0
	#     const char line_11$[] = "\e[A\e[C\e[C~\e[C\e[A~\e[C\e[A~\e[C\e[A~";
	mov A, BP
	add A, 16777146
	mov B, BP
	add B, -486
	store A, B
	.loc 1 2 0
	# #define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
	.L198:
	mov B, BP
	add B, -486
	load A, B
	mov B, A
	load A, B
	jeq .L466, A, 0
	mov B, BP
	add B, -486
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -486
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
	jmp .L467
	.L466:
	jmp .L199
	.L467:
	jmp .L198
	.L199:
	.loc 1 200 0
	#                 default: assert(0);
	jmp .L179
	.loc 1 201 0
	#             }
	.L200:
	.L179:
	.loc 1 203 0
	#         default:
	jmp .L116
	.loc 1 204 0
	#             assert(0);
	.L201:
	.L116:
	.L371:
	.L301:
	.L300:
	.loc 1 213 0
	#                     col_last = col_small;
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -305
	load A, B
	mov B, BP
	add B, -262
	store A, B
	.loc 1 214 0
	#                 } // if motionevent on point
	.loc 1 115 0
	#                 switch (row) {
	mov B, BP
	add B, -306
	load A, B
	mov B, BP
	add B, -263
	store A, B
	.L299:
	jmp .L468
	.L289:
	.loc 1 318 0
	#             }
	.loc 1 214 0
	#                 } // if motionevent on point
	.loc 1 75 0
	#     int row, col;
	mov B, BP
	add B, -301
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 214 0
	#                 } // if motionevent on point
	mov A, 35
	mov B, A
	load A, SP
	add SP, 1
	eq A, B
	jeq .L469, A, 0
	.loc 1 318 0
	#             }
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -569
	mov A, 7777853
	store A, B
	mov B, BP
	add B, -568
	mov A, 6222378
	store A, B
	mov B, BP
	add B, -567
	mov A, 3546017
	store A, B
	mov B, BP
	add B, -566
	mov A, 4445136
	store A, B
	mov B, BP
	add B, -565
	mov A, 7780945
	store A, B
	mov B, BP
	add B, -564
	mov A, 3462586
	store A, B
	mov B, BP
	add B, -563
	mov A, 3111820
	store A, B
	mov B, BP
	add B, -562
	mov A, 2405140
	store A, B
	mov B, BP
	add B, -561
	mov A, 3624625
	store A, B
	mov B, BP
	add B, -560
	mov A, 6968615
	store A, B
	mov B, BP
	add B, -559
	mov A, 3176867
	store A, B
	mov B, BP
	add B, -558
	mov A, 3710589
	store A, B
	mov B, BP
	add B, -557
	mov A, 7702269
	store A, B
	mov B, BP
	add B, -556
	mov A, 3192178
	store A, B
	mov B, BP
	add B, -555
	mov A, 649731
	store A, B
	mov B, BP
	add B, -554
	mov A, 7800749
	store A, B
	mov B, BP
	add B, -553
	mov A, 6017677
	store A, B
	mov B, BP
	add B, -552
	mov A, 6189630
	store A, B
	mov B, BP
	add B, -551
	mov A, 1975056
	store A, B
	mov B, BP
	add B, -550
	mov A, 2694116
	store A, B
	mov B, BP
	add B, -549
	mov A, 3038398
	store A, B
	mov B, BP
	add B, -548
	mov A, 1663188
	store A, B
	mov B, BP
	add B, -547
	mov A, 6543815
	store A, B
	mov B, BP
	add B, -546
	mov A, 4176440
	store A, B
	mov B, BP
	add B, -545
	mov A, 1696171
	store A, B
	mov B, BP
	add B, -544
	mov A, 2471993
	store A, B
	mov B, BP
	add B, -543
	mov A, 1030495
	store A, B
	mov B, BP
	add B, -542
	mov A, 1229599
	store A, B
	mov B, BP
	add B, -541
	mov A, 6638142
	store A, B
	mov B, BP
	add B, -540
	mov A, 7858312
	store A, B
	mov B, BP
	add B, -539
	mov A, 5114362
	store A, B
	mov B, BP
	add B, -538
	mov A, 6754064
	store A, B
	mov B, BP
	add B, -537
	mov A, 5507984
	store A, B
	mov B, BP
	add B, -536
	mov A, 2092153
	store A, B
	mov B, BP
	add B, -535
	mov A, 4221209
	store A, B
	mov B, BP
	add B, -534
	mov A, 3125287
	store A, B
	mov B, BP
	add B, -533
	mov A, 3738908
	store A, B
	mov B, BP
	add B, -532
	mov A, 4746424
	store A, B
	mov B, BP
	add B, -531
	mov A, 7514587
	store A, B
	mov B, BP
	add B, -530
	mov A, 3209489
	store A, B
	mov B, BP
	add B, -529
	mov A, 5982099
	store A, B
	mov B, BP
	add B, -528
	mov A, 5252558
	store A, B
	mov B, BP
	add B, -527
	mov A, 2931922
	store A, B
	mov B, BP
	add B, -526
	mov A, 7955762
	store A, B
	mov B, BP
	add B, -525
	mov A, 1710208
	store A, B
	mov B, BP
	add B, -524
	mov A, 296028
	store A, B
	mov B, BP
	add B, -523
	mov A, 3099603
	store A, B
	mov B, BP
	add B, -522
	mov A, 1923308
	store A, B
	mov B, BP
	add B, -521
	mov A, 1816384
	store A, B
	mov B, BP
	add B, -520
	mov A, 7460259
	store A, B
	mov B, BP
	add B, -519
	mov A, 4688990
	store A, B
	mov B, BP
	add B, -518
	mov A, 3698787
	store A, B
	mov B, BP
	add B, -517
	mov A, 8063985
	store A, B
	mov B, BP
	add B, -516
	mov A, 2904281
	store A, B
	mov B, BP
	add B, -515
	mov A, 2387354
	store A, B
	mov B, BP
	add B, -514
	mov A, 1096597
	store A, B
	mov B, BP
	add B, -513
	mov A, 7513812
	store A, B
	mov B, BP
	add B, -512
	mov A, 6846883
	store A, B
	mov B, BP
	add B, -511
	mov A, 1839444
	store A, B
	mov B, BP
	add B, -510
	mov A, 3299084
	store A, B
	mov B, BP
	add B, -509
	mov A, 631091
	store A, B
	mov B, BP
	add B, -508
	mov A, 8290017
	store A, B
	mov B, BP
	add B, -507
	mov A, 7160748
	store A, B
	mov B, BP
	add B, -506
	mov A, 1179054
	store A, B
	mov B, BP
	add B, -505
	mov A, 2243030
	store A, B
	mov B, BP
	add B, -504
	mov A, 1709908
	store A, B
	mov B, BP
	add B, -503
	mov A, 1675438
	store A, B
	mov B, BP
	add B, -502
	mov A, 240870
	store A, B
	mov B, BP
	add B, -501
	mov A, 5979594
	store A, B
	mov B, BP
	add B, -500
	mov A, 213499
	store A, B
	mov B, BP
	add B, -499
	mov A, 2931947
	store A, B
	mov B, BP
	add B, -498
	mov A, 6795798
	store A, B
	mov B, BP
	add B, -497
	mov A, 3096344
	store A, B
	mov B, BP
	add B, -496
	mov A, 6255267
	store A, B
	mov B, BP
	add B, -495
	mov A, 3628236
	store A, B
	mov B, BP
	add B, -494
	mov A, 1266072
	store A, B
	mov B, BP
	add B, -493
	mov A, 416109
	store A, B
	mov B, BP
	add B, -492
	mov A, 145294
	store A, B
	mov B, BP
	add B, -491
	mov A, 3209749
	store A, B
	mov B, BP
	add B, -490
	mov A, 7941896
	store A, B
	mov B, BP
	add B, -489
	mov A, 4764432
	store A, B
	.loc 1 219 0
	#                 const int more_entropy[] = {4035960, 4418458, 5209189, 1108639, 4342160, 1331397, 4310812, 1590852, 3567457, 2988487, 6401034, 3601701, 917254, 4908399, 6845483, 3467160, 4871614, 313048, 410405, 4304715};
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -620
	mov A, 296145
	store A, B
	mov B, BP
	add B, -619
	mov A, 7955867
	store A, B
	mov B, BP
	add B, -618
	mov A, 2932039
	store A, B
	mov B, BP
	add B, -617
	mov A, 296127
	store A, B
	mov B, BP
	add B, -616
	mov A, 2932038
	store A, B
	mov B, BP
	add B, -615
	mov A, 3209591
	store A, B
	mov B, BP
	add B, -614
	mov A, 5982222
	store A, B
	mov B, BP
	add B, -613
	mov A, 3209608
	store A, B
	mov B, BP
	add B, -612
	mov A, 7514691
	store A, B
	mov B, BP
	add B, -611
	mov A, 3209594
	store A, B
	mov B, BP
	add B, -610
	mov A, 296127
	store A, B
	mov B, BP
	add B, -609
	mov A, 7955866
	store A, B
	mov B, BP
	add B, -608
	mov A, 2932017
	store A, B
	mov B, BP
	add B, -607
	mov A, 296143
	store A, B
	mov B, BP
	add B, -606
	mov A, 2932026
	store A, B
	mov B, BP
	add B, -605
	mov A, 3209600
	store A, B
	mov B, BP
	add B, -604
	mov A, 5982218
	store A, B
	mov B, BP
	add B, -603
	mov A, 3209604
	store A, B
	mov B, BP
	add B, -602
	mov A, 7514682
	store A, B
	mov B, BP
	add B, -601
	mov A, 3209605
	store A, B
	mov B, BP
	add B, -600
	mov A, 296132
	store A, B
	mov B, BP
	add B, -599
	mov A, 7955859
	store A, B
	mov B, BP
	add B, -598
	mov A, 2932038
	store A, B
	mov B, BP
	add B, -597
	mov A, 296123
	store A, B
	mov B, BP
	add B, -596
	mov A, 2932036
	store A, B
	mov B, BP
	add B, -595
	mov A, 3209600
	store A, B
	mov B, BP
	add B, -594
	mov A, 5982211
	store A, B
	mov B, BP
	add B, -593
	mov A, 3209584
	store A, B
	mov B, BP
	add B, -592
	mov A, 7514692
	store A, B
	mov B, BP
	add B, -591
	mov A, 3209604
	store A, B
	mov B, BP
	add B, -590
	mov A, 296123
	store A, B
	mov B, BP
	add B, -589
	mov A, 7955878
	store A, B
	mov B, BP
	add B, -588
	mov A, 2932039
	store A, B
	mov B, BP
	add B, -587
	mov A, 296142
	store A, B
	mov B, BP
	add B, -586
	mov A, 2932027
	store A, B
	mov B, BP
	add B, -585
	mov A, 3209599
	store A, B
	mov B, BP
	add B, -584
	mov A, 5982202
	store A, B
	mov B, BP
	add B, -583
	mov A, 3209584
	store A, B
	mov B, BP
	add B, -582
	mov A, 7514686
	store A, B
	mov B, BP
	add B, -581
	mov A, 3209600
	store A, B
	mov B, BP
	add B, -580
	mov A, 296137
	store A, B
	mov B, BP
	add B, -579
	mov A, 7955874
	store A, B
	mov B, BP
	add B, -578
	mov A, 2932030
	store A, B
	mov B, BP
	add B, -577
	mov A, 296129
	store A, B
	mov B, BP
	add B, -576
	mov A, 2932038
	store A, B
	mov B, BP
	add B, -575
	mov A, 3209590
	store A, B
	mov B, BP
	add B, -574
	mov A, 5982194
	store A, B
	mov B, BP
	add B, -573
	mov A, 3209570
	store A, B
	mov B, BP
	add B, -572
	mov A, 7514656
	store A, B
	mov B, BP
	add B, -571
	mov A, 3209557
	store A, B
	mov B, BP
	add B, -570
	mov A, 296153
	store A, B
	.loc 1 220 0
	#                 const int sudoku_encrypted[] = {-4764425, -7941890, -3209749, -145291, -416101, -1266067, -3628235, -6255267, -3096335, -6795790, -2931943, -213490, -5979593, -240868, -1675432, -1709901, -2243025, -1179051, -7160747, -8290017, -631088, -3299080, -1839437, -6846874, -7513804, -1096595, -2387348, -2904275, -8063978, -3698786, -4688982, -7460250, -1816382, -1923304, -3099600, -296023, -1710199, -7955759, -2931918, -5252553, -5982098, -3209482, -7514587, -4746418, -3738900, -3125287, -4221207, -2092145, -5507978, -6754060, -5114359, -7858303, -6638141, -1229592, -1030491, -2471993, -1696165, -4176440, -6543812, -1663187, -3038393, -2694107, -1975054, -6189627, -6017668, -7800742, -649729, -3192173, -7702265, -3710583, -3176867, -6968614, -3624623, -2405139, -3111815, -3462586, -7780939, -4445136, -3546014, -6222371, -7777849};
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -640
	mov A, 4035960
	store A, B
	mov B, BP
	add B, -639
	mov A, 4418458
	store A, B
	mov B, BP
	add B, -638
	mov A, 5209189
	store A, B
	mov B, BP
	add B, -637
	mov A, 1108639
	store A, B
	mov B, BP
	add B, -636
	mov A, 4342160
	store A, B
	mov B, BP
	add B, -635
	mov A, 1331397
	store A, B
	mov B, BP
	add B, -634
	mov A, 4310812
	store A, B
	mov B, BP
	add B, -633
	mov A, 1590852
	store A, B
	mov B, BP
	add B, -632
	mov A, 3567457
	store A, B
	mov B, BP
	add B, -631
	mov A, 2988487
	store A, B
	mov B, BP
	add B, -630
	mov A, 6401034
	store A, B
	mov B, BP
	add B, -629
	mov A, 3601701
	store A, B
	mov B, BP
	add B, -628
	mov A, 917254
	store A, B
	mov B, BP
	add B, -627
	mov A, 4908399
	store A, B
	mov B, BP
	add B, -626
	mov A, 6845483
	store A, B
	mov B, BP
	add B, -625
	mov A, 3467160
	store A, B
	mov B, BP
	add B, -624
	mov A, 4871614
	store A, B
	mov B, BP
	add B, -623
	mov A, 313048
	store A, B
	mov B, BP
	add B, -622
	mov A, 410405
	store A, B
	mov B, BP
	add B, -621
	mov A, 4304715
	store A, B
	.loc 1 221 0
	# 
	mov A, 0
	mov B, SP
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 4764425
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -721
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7941890
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -720
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3209749
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -719
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 145291
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -718
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 416101
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -717
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1266067
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -716
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3628235
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -715
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6255267
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -714
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3096335
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -713
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6795790
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -712
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2931943
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -711
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 213490
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -710
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 5979593
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -709
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 240868
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -708
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1675432
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -707
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1709901
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -706
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2243025
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -705
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1179051
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -704
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7160747
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -703
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 8290017
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -702
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 631088
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -701
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3299080
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -700
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1839437
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -699
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6846874
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -698
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7513804
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -697
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1096595
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -696
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2387348
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -695
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2904275
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -694
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 8063978
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -693
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3698786
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -692
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 4688982
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -691
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7460250
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -690
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1816382
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -689
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1923304
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -688
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3099600
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -687
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 296023
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -686
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1710199
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -685
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7955759
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -684
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2931918
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -683
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 5252553
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -682
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 5982098
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -681
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3209482
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -680
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7514587
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -679
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 4746418
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -678
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3738900
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -677
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3125287
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -676
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 4221207
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -675
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2092145
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -674
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 5507978
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -673
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6754060
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -672
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 5114359
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -671
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7858303
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -670
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6638141
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -669
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1229592
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -668
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1030491
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -667
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2471993
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -666
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1696165
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -665
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 4176440
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -664
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6543812
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -663
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1663187
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -662
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3038393
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -661
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2694107
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -660
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1975054
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -659
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6189627
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -658
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6017668
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -657
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7800742
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -656
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 649729
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -655
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3192173
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -654
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7702265
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -653
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3710583
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -652
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3176867
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -651
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6968614
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -650
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3624623
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -649
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 2405139
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -648
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3111815
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -647
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3462586
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -646
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7780939
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -645
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 4445136
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -644
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3546014
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -643
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 6222371
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -642
	store A, B
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 7777849
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -641
	store A, B
	.loc 1 223 0
	#                 
	.loc 1 225 0
	#                 col_last = -1;
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -262
	store A, B
	.loc 1 226 0
	# 
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -263
	store A, B
	.loc 1 229 0
	#                 }
	.loc 1 228 0
	#                     goto fail;
	.loc 1 58 0
	# 
	mov B, BP
	add B, -274
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 228 0
	#                     goto fail;
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	ne A, B
	jeq .L470, A, 0
	.loc 1 229 0
	#                 }
	jmp .L243
	.L470:
	.loc 1 236 0
	#                 unsigned char *entry_ptr = entries;
	.loc 1 237 0
	#                 for (int i = 0; i < 81; i++) {
	mov A, 0
	mov B, SP
	.loc 1 57 0
	#     int num_entries;
	mov A, BP
	add A, 16776943
	mov B, BP
	add B, -855
	store A, B
	.loc 1 244 0
	#                     }
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -856
	mov A, 0
	store A, B
	.loc 1 244 0
	#                     }
	.L202:
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 81
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L471, A, 0
	jmp .L472
	.L471:
	.loc 1 244 0
	#                     }
	jmp .L204
	.L472:
	.loc 1 239 0
	#                     if (number) {
	mov A, 0
	mov B, SP
	.loc 1 221 0
	# 
	mov A, BP
	add A, 16776495
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
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
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 239 0
	#                     if (number) {
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, BP
	add A, 16776647
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 239 0
	#                     if (number) {
	mov A, 80
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -857
	store A, B
	.loc 1 244 0
	#                     }
	.loc 1 239 0
	#                     if (number) {
	mov B, BP
	add B, -857
	load A, B
	jeq .L473, A, 0
	.loc 1 241 0
	#                     } else {
	.loc 1 239 0
	#                     if (number) {
	mov B, BP
	add B, -857
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 241 0
	#                     } else {
	mov A, 1
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, BP
	add A, 16776647
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 241 0
	#                     } else {
	mov A, 80
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 241 0
	#                     } else {
	.loc 1 236 0
	#                 unsigned char *entry_ptr = entries;
	mov A, BP
	add A, 16776362
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
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
	jmp .L474
	.L473:
	.loc 1 244 0
	#                     }
	.loc 1 243 0
	#                         entry_ptr++;
	.loc 1 237 0
	#                 for (int i = 0; i < 81; i++) {
	mov B, BP
	add B, -855
	load A, B
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 243 0
	#                         entry_ptr++;
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, BP
	add A, 16776647
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 243 0
	#                         entry_ptr++;
	mov A, 80
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 243 0
	#                         entry_ptr++;
	.loc 1 236 0
	#                 unsigned char *entry_ptr = entries;
	mov A, BP
	add A, 16776362
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
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
	.loc 1 244 0
	#                     }
	.loc 1 237 0
	#                 for (int i = 0; i < 81; i++) {
	mov B, BP
	add B, -855
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -855
	store A, B
	load A, SP
	add SP, 1
	.L474:
	.loc 1 244 0
	#                     }
	.L203:
	.loc 1 238 0
	#                     int number = decrypt(sudoku_encrypted, i);
	mov B, BP
	add B, -856
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -856
	store A, B
	load A, SP
	add SP, 1
	.loc 1 244 0
	#                     }
	jmp .L202
	.L204:
	.loc 1 248 0
	#                 // rows
	.loc 1 260 0
	#                     }
	.loc 1 250 0
	#                     for (int j = 0; j < 9; j++) {
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -867
	mov A, 0
	store A, B
	.loc 1 260 0
	#                     }
	.L205:
	.loc 1 250 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -867
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 81
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L475, A, 0
	jmp .L476
	.L475:
	.loc 1 260 0
	#                     }
	jmp .L207
	.L476:
	.loc 1 252 0
	#                     }
	.loc 1 251 0
	#                         seen[j] = 0;
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -868
	mov A, 0
	store A, B
	.loc 1 252 0
	#                     }
	.L208:
	.loc 1 251 0
	#                         seen[j] = 0;
	mov B, BP
	add B, -868
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L477, A, 0
	jmp .L478
	.L477:
	.loc 1 252 0
	#                     }
	jmp .L210
	.L478:
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 248 0
	#                 // rows
	mov A, BP
	add A, 16776350
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 251 0
	#                         seen[j] = 0;
	mov B, BP
	add B, -868
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
	.loc 1 252 0
	#                     }
	.L209:
	.loc 1 251 0
	#                         seen[j] = 0;
	mov B, BP
	add B, -868
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -868
	store A, B
	load A, SP
	add SP, 1
	.loc 1 252 0
	#                     }
	jmp .L208
	.L210:
	.loc 1 260 0
	#                     }
	.loc 1 254 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -869
	mov A, 0
	store A, B
	.loc 1 260 0
	#                     }
	.L211:
	.loc 1 254 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -869
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L479, A, 0
	jmp .L480
	.L479:
	.loc 1 260 0
	#                     }
	jmp .L213
	.L480:
	.loc 1 255 0
	#                         if (*num_seen) {
	mov A, 0
	mov B, SP
	.loc 1 248 0
	#                 // rows
	mov A, BP
	add A, 16776350
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 255 0
	#                         if (*num_seen) {
	.loc 1 236 0
	#                 unsigned char *entry_ptr = entries;
	mov A, BP
	add A, 16776362
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 255 0
	#                         if (*num_seen) {
	.loc 1 250 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -867
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 254 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -869
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 255 0
	#                         if (*num_seen) {
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, BP
	add A, 16776647
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 255 0
	#                         if (*num_seen) {
	mov A, 80
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 250 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -867
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 254 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -869
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, BP
	add B, -870
	store A, B
	.loc 1 258 0
	#                         }
	.loc 1 256 0
	#                             //dprintf(2, "fail 239, %d %d %d\n", i, j, sudoku[i + j]);
	.loc 1 255 0
	#                         if (*num_seen) {
	mov B, BP
	add B, -870
	load A, B
	mov B, A
	load A, B
	jeq .L481, A, 0
	.loc 1 258 0
	#                         }
	jmp .L243
	.L481:
	.loc 1 260 0
	#                     }
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 255 0
	#                         if (*num_seen) {
	mov B, BP
	add B, -870
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 260 0
	#                     }
	.L212:
	.loc 1 254 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -869
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -869
	store A, B
	load A, SP
	add SP, 1
	.loc 1 260 0
	#                     }
	jmp .L211
	.L213:
	.L206:
	.loc 1 250 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -867
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -867
	store A, B
	.loc 1 260 0
	#                     }
	jmp .L205
	.L207:
	.loc 1 274 0
	#                     }
	.loc 1 264 0
	#                     for (int j = 0; j < 9; j++) {
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -871
	mov A, 0
	store A, B
	.loc 1 274 0
	#                     }
	.L214:
	.loc 1 264 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -871
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L482, A, 0
	jmp .L483
	.L482:
	.loc 1 274 0
	#                     }
	jmp .L216
	.L483:
	.loc 1 266 0
	#                     }
	.loc 1 265 0
	#                         seen[j] = 0;
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -872
	mov A, 0
	store A, B
	.loc 1 266 0
	#                     }
	.L217:
	.loc 1 265 0
	#                         seen[j] = 0;
	mov B, BP
	add B, -872
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L484, A, 0
	jmp .L485
	.L484:
	.loc 1 266 0
	#                     }
	jmp .L219
	.L485:
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 248 0
	#                 // rows
	mov A, BP
	add A, 16776350
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 265 0
	#                         seen[j] = 0;
	mov B, BP
	add B, -872
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
	.loc 1 266 0
	#                     }
	.L218:
	.loc 1 265 0
	#                         seen[j] = 0;
	mov B, BP
	add B, -872
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -872
	store A, B
	load A, SP
	add SP, 1
	.loc 1 266 0
	#                     }
	jmp .L217
	.L219:
	.loc 1 274 0
	#                     }
	.loc 1 268 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -873
	mov A, 0
	store A, B
	.loc 1 274 0
	#                     }
	.L220:
	.loc 1 268 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -873
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 81
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L486, A, 0
	jmp .L487
	.L486:
	.loc 1 274 0
	#                     }
	jmp .L222
	.L487:
	.loc 1 269 0
	#                         if (*num_seen) {
	mov A, 0
	mov B, SP
	.loc 1 248 0
	#                 // rows
	mov A, BP
	add A, 16776350
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 269 0
	#                         if (*num_seen) {
	.loc 1 236 0
	#                 unsigned char *entry_ptr = entries;
	mov A, BP
	add A, 16776362
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 269 0
	#                         if (*num_seen) {
	.loc 1 264 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -871
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 268 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -873
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 269 0
	#                         if (*num_seen) {
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, BP
	add A, 16776647
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 269 0
	#                         if (*num_seen) {
	mov A, 80
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 264 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -871
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 268 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -873
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, BP
	add B, -874
	store A, B
	.loc 1 272 0
	#                         }
	.loc 1 270 0
	#                             //dprintf(2, "fail 253, %d %d\n", i, j);
	.loc 1 269 0
	#                         if (*num_seen) {
	mov B, BP
	add B, -874
	load A, B
	mov B, A
	load A, B
	jeq .L488, A, 0
	.loc 1 272 0
	#                         }
	jmp .L243
	.L488:
	.loc 1 274 0
	#                     }
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 269 0
	#                         if (*num_seen) {
	mov B, BP
	add B, -874
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 274 0
	#                     }
	.L221:
	.loc 1 268 0
	#                         int *num_seen = seen + (decrypt(sudoku, i + j));
	mov B, BP
	add B, -873
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -873
	store A, B
	.loc 1 274 0
	#                     }
	jmp .L220
	.L222:
	.L215:
	.loc 1 264 0
	#                     for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -871
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -871
	store A, B
	load A, SP
	add SP, 1
	.loc 1 274 0
	#                     }
	jmp .L214
	.L216:
	.loc 1 290 0
	#                             }
	.loc 1 278 0
	#                     for (int jj = 0; jj < 9; jj += 3) { // box c
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -875
	mov A, 0
	store A, B
	.loc 1 290 0
	#                             }
	.L223:
	.loc 1 278 0
	#                     for (int jj = 0; jj < 9; jj += 3) { // box c
	mov B, BP
	add B, -875
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 81
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L489, A, 0
	jmp .L490
	.L489:
	.loc 1 290 0
	#                             }
	jmp .L225
	.L490:
	.loc 1 279 0
	#                         for (int j = 0; j < 9; j++) {
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -876
	mov A, 0
	store A, B
	.loc 1 290 0
	#                             }
	.L226:
	.loc 1 279 0
	#                         for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -876
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L491, A, 0
	jmp .L492
	.L491:
	.loc 1 290 0
	#                             }
	jmp .L228
	.L492:
	.loc 1 281 0
	#                         }
	.loc 1 280 0
	#                             seen[j] = 0;
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -877
	mov A, 0
	store A, B
	.loc 1 281 0
	#                         }
	.L229:
	.loc 1 280 0
	#                             seen[j] = 0;
	mov B, BP
	add B, -877
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L493, A, 0
	jmp .L494
	.L493:
	.loc 1 281 0
	#                         }
	jmp .L231
	.L494:
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 248 0
	#                 // rows
	mov A, BP
	add A, 16776350
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 280 0
	#                             seen[j] = 0;
	mov B, BP
	add B, -877
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
	.loc 1 281 0
	#                         }
	.L230:
	.loc 1 280 0
	#                             seen[j] = 0;
	mov B, BP
	add B, -877
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -877
	store A, B
	load A, SP
	add SP, 1
	.loc 1 281 0
	#                         }
	jmp .L229
	.L231:
	.loc 1 290 0
	#                             }
	.loc 1 283 0
	#                             for (int j = 0; j < 3; j++) { // c within box
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -878
	mov A, 0
	store A, B
	.loc 1 290 0
	#                             }
	.L232:
	.loc 1 283 0
	#                             for (int j = 0; j < 3; j++) { // c within box
	mov B, BP
	add B, -878
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 27
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L495, A, 0
	jmp .L496
	.L495:
	.loc 1 290 0
	#                             }
	jmp .L234
	.L496:
	.loc 1 284 0
	#                                 int *num_seen = seen + (decrypt(sudoku, ii + jj + i + j));
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -879
	mov A, 0
	store A, B
	.loc 1 290 0
	#                             }
	.L235:
	.loc 1 284 0
	#                                 int *num_seen = seen + (decrypt(sudoku, ii + jj + i + j));
	mov B, BP
	add B, -879
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L497, A, 0
	jmp .L498
	.L497:
	.loc 1 290 0
	#                             }
	jmp .L237
	.L498:
	.loc 1 285 0
	#                                 if (*num_seen) {
	mov A, 0
	mov B, SP
	.loc 1 248 0
	#                 // rows
	mov A, BP
	add A, 16776350
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 285 0
	#                                 if (*num_seen) {
	.loc 1 236 0
	#                 unsigned char *entry_ptr = entries;
	mov A, BP
	add A, 16776362
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 285 0
	#                                 if (*num_seen) {
	.loc 1 278 0
	#                     for (int jj = 0; jj < 9; jj += 3) { // box c
	mov B, BP
	add B, -875
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 279 0
	#                         for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -876
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 283 0
	#                             for (int j = 0; j < 3; j++) { // c within box
	mov B, BP
	add B, -878
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 284 0
	#                                 int *num_seen = seen + (decrypt(sudoku, ii + jj + i + j));
	mov B, BP
	add B, -879
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 285 0
	#                                 if (*num_seen) {
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, BP
	add A, 16776647
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 285 0
	#                                 if (*num_seen) {
	mov A, 80
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 278 0
	#                     for (int jj = 0; jj < 9; jj += 3) { // box c
	mov B, BP
	add B, -875
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 279 0
	#                         for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -876
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 283 0
	#                             for (int j = 0; j < 3; j++) { // c within box
	mov B, BP
	add B, -878
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 284 0
	#                                 int *num_seen = seen + (decrypt(sudoku, ii + jj + i + j));
	mov B, BP
	add B, -879
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, BP
	add B, -880
	store A, B
	.loc 1 288 0
	#                                 }
	.loc 1 286 0
	#                                     //dprintf(2, "fail 269, %d %d %d %d", ii, jj, i, j);
	.loc 1 285 0
	#                                 if (*num_seen) {
	mov B, BP
	add B, -880
	load A, B
	mov B, A
	load A, B
	jeq .L499, A, 0
	.loc 1 288 0
	#                                 }
	jmp .L243
	.L499:
	.loc 1 290 0
	#                             }
	mov A, 1
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 285 0
	#                                 if (*num_seen) {
	mov B, BP
	add B, -880
	load A, B
	mov C, A
	load A, SP
	mov B, A
	mov A, C
	store B, A
	load A, SP
	add SP, 1
	.loc 1 290 0
	#                             }
	.L236:
	.loc 1 284 0
	#                                 int *num_seen = seen + (decrypt(sudoku, ii + jj + i + j));
	mov B, BP
	add B, -879
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -879
	store A, B
	load A, SP
	add SP, 1
	.loc 1 290 0
	#                             }
	jmp .L235
	.L237:
	.L233:
	.loc 1 283 0
	#                             for (int j = 0; j < 3; j++) { // c within box
	mov B, BP
	add B, -878
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 9
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -878
	store A, B
	.loc 1 290 0
	#                             }
	jmp .L232
	.L234:
	.L227:
	.loc 1 279 0
	#                         for (int j = 0; j < 9; j++) {
	mov B, BP
	add B, -876
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 3
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -876
	store A, B
	.loc 1 290 0
	#                             }
	jmp .L226
	.L228:
	.L224:
	.loc 1 278 0
	#                     for (int jj = 0; jj < 9; jj += 3) { // box c
	mov B, BP
	add B, -875
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 27
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov B, BP
	add B, -875
	store A, B
	.loc 1 290 0
	#                             }
	jmp .L223
	.L225:
	.loc 1 309 0
	#                 }
	.loc 1 302 0
	#                     int rem = i;
	mov A, 0
	mov B, SP
	mov B, BP
	add B, -881
	mov A, 0
	store A, B
	.loc 1 309 0
	#                 }
	.L238:
	.loc 1 302 0
	#                     int rem = i;
	mov B, BP
	add B, -881
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	mov A, 51
	mov B, A
	load A, SP
	add SP, 1
	lt A, B
	jeq .L500, A, 0
	jmp .L501
	.L500:
	.loc 1 309 0
	#                 }
	jmp .L240
	.L501:
	.loc 1 303 0
	#                     while(rem >= 10) {
	mov A, 0
	mov B, SP
	.loc 1 302 0
	#                     int rem = i;
	mov B, BP
	add B, -881
	load A, B
	mov B, BP
	add B, -882
	store A, B
	.loc 1 305 0
	#                     }
	.L241:
	.loc 1 304 0
	#                         rem -= 10;
	mov A, 10
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 303 0
	#                     while(rem >= 10) {
	mov B, BP
	add B, -882
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	le A, B
	jeq .L502, A, 0
	.loc 1 305 0
	#                     }
	.loc 1 303 0
	#                     while(rem >= 10) {
	mov B, BP
	add B, -882
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 305 0
	#                     }
	mov A, 10
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, BP
	add B, -882
	store A, B
	jmp .L503
	.L502:
	jmp .L242
	.L503:
	jmp .L241
	.L242:
	.loc 1 309 0
	#                 }
	.loc 1 219 0
	#                 const int more_entropy[] = {4035960, 4418458, 5209189, 1108639, 4342160, 1331397, 4310812, 1590852, 3567457, 2988487, 6401034, 3601701, 917254, 4908399, 6845483, 3467160, 4871614, 313048, 410405, 4304715};
	mov A, BP
	add A, 16776596
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 302 0
	#                     int rem = i;
	mov B, BP
	add B, -881
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
	mov B, A
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 309 0
	#                 }
	.loc 1 218 0
	#                 const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
	mov A, BP
	add A, 16776647
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 309 0
	#                 }
	mov A, 46
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 57 0
	#     int num_entries;
	mov A, BP
	add A, 16776943
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 303 0
	#                     while(rem >= 10) {
	mov B, BP
	add B, -882
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
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov B, A
	load A, SP
	add SP, 1
	add A, B
	mov C, A
	load A, SP
	add SP, 1
	mov B, A
	mov A, C
	mov B, A
	load A, B
	mov B, A
	load A, SP
	add SP, 1
	sub A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 309 0
	#                 }
	.loc 1 223 0
	#                 
	mov A, BP
	add A, 16776443
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 302 0
	#                     int rem = i;
	mov B, BP
	add B, -881
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
	.loc 1 309 0
	#                 }
	.L239:
	.loc 1 302 0
	#                     int rem = i;
	mov B, BP
	add B, -881
	load A, B
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	add A, 1
	mov B, BP
	add B, -881
	store A, B
	load A, SP
	add SP, 1
	.loc 1 309 0
	#                 }
	jmp .L238
	.L240:
	.loc 1 312 0
	# 
	mov A, 0
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 223 0
	#                 
	mov A, BP
	add A, 16776443
	mov D, SP
	add D, -1
	store B, D
	mov SP, D
	mov D, SP
	add D, -1
	store A, D
	mov SP, D
	.loc 1 312 0
	# 
	mov A, 51
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
	.loc 1 314 0
	#                 goto clear;
	.loc 1 223 0
	#                 
	mov A, BP
	add A, 16776443
	mov B, BP
	add B, -261
	store A, B
	.loc 1 315 0
	#                 fail:
	jmp .L244
	.loc 1 316 0
	#                 greeting = "Sorry, try again!";
	.L243:
.data
	.L504:
	.string "Sorry, try again!"
.text
	mov A, .L504
	mov B, BP
	add B, -261
	store A, B
	.loc 1 318 0
	#             }
	jmp .L244
	.L469:
	.L468:
	.loc 1 320 0
	#         } // switch(num_read)
	jmp .L28
	.L28:
	jmp .L505
	.L275:
	jmp .L27
	.L505:
	jmp .L26
	.L27:
	#{pop:main}
	exit
