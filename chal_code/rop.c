#define assert(...)
#define rop_puts(s) {const char*cpp_temp=(s);while (*cpp_temp) putchar(*(cpp_temp++));}
#define rop_divmod(a, b, c) {int result = 0; int i = a; while (i >= b) {i -= b; result++;} c = i; a = result;}
#define rop_putint(xx) {\
    int x = (xx); \
    if (x == 0) { \
        putchar('0'); \
    } else { \
        char s[4] = "\0\0\0\0"; \
        char *i = s; \
        while (0 < x) { \
            int rem; \
            rop_divmod(x, 10, rem); \
            *i = '0' + rem; \
            i++; \
        } \
        do { \
            i--; \
            putchar(*i); \
        } while (i != s); \
    } \
}
#define rop_setpos(r, c) {\
    putchar('\e'); \
    putchar('['); \
    int cpp_temp = (r) + 1; \
    cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
    rop_putint(cpp_temp); \
    putchar(';'); \
    cpp_temp = (c) + 1; \
    cpp_temp += cpp_temp; \
    cpp_temp = cpp_temp + cpp_temp + cpp_temp + cpp_temp + cpp_temp; \
    rop_putint(cpp_temp); \
    putchar('H'); \
}

#define decrypt(puzzle, k) ((puzzle)[(k)] + entropy[80 - (k)])
#define encrypt(value, k) ((value) - entropy[80 - (k)])

#ifdef LOCKSCREEN_POC
void rop() {
#else
void main() {
#endif
    const char line_01[]  = "\e[2C~~~~~~~";
    const char line_10[]  = "\e[B~\e[B\e[D~\e[B\e[D~\e[B\e[D~";
    const char line_11[]  = "\e[B\e[C\e[C~\e[C\e[B~\e[C\e[B~\e[C\e[B~";
    const char line_11$[] = "\e[A\e[C\e[C~\e[C\e[A~\e[C\e[A~\e[C\e[A~";
    const char line_21[]  = "\e[B\e[C~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~";
    const char line_21$[] = "\e[A\e[C~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~";
    const char line_12[]  = "\e[B\e[C~~~~~\e[B~~~~~\e[B\e[D~~~~~\e[B~~~~~";
    const char line_12$[] = "\e[A\e[C~~~~~\e[A~~~~~\e[A\e[D~~~~~\e[A~~~~~";
    
    char *greeting = "Draw pattern with mouse to get flag";
    int row_last = -1;
    int col_last = -1;
    unsigned char entries[10];
    int num_entries;

    rop_puts("\e[?1002h"); // mouse mode
    rop_puts("\e[?25l"); // hide cursor
    clear:
    rop_puts("\e[H\e[2J\e[3J"); // clear screen
    rop_puts(greeting);
    // print dots
    for (int row = 0; row < 3; row++) {
        for (int col = 0; col < 3; col++) {
            rop_setpos(row, col);
            putchar('#');
        }
    }

    num_entries = 0;
    int num_read = 0;
    char motion;
    int row, col;
    while (1) {
        char input = getchar();
        switch (num_read) {
        case 0:
            if (input == '\x1b') {
                num_read++;
            }
            break;
        case 1:
            if (input == '[') {
                num_read++;
            } else {
                num_read = 0;
            }
            break;
        case 2:
            if (input == 'M') {
                num_read++;
            } else {
                num_read = 0;
            }
            break;
        case 3:
            motion = input;
            num_read++;
            break;
        case 4:
            col = input - 32;
            num_read++;
            break;
        case 5:
            row = input - 32;
            num_read = 0;
            /******************************
            * on_mouse_event              *
            ******************************/
            if (motion == '@' || motion == ' ') { // mouse button 1
                //printf("\e[Hrow: %2d col: %2d\n", row, col);
                int row_small = -1, col_small = -1;
                switch (row) {
                    case  5: row_small = 0; break;
                    case 10: row_small = 1; break;
                    case 15: row_small = 2; break;
                }
                switch (col) {
                    case 10: col_small = 0; break;
                    case 20: col_small = 1; break;
                    case 30: col_small = 2; break;
                }
                if (row_small != -1 && col_small != -1 && (row_small != row_last || col_small != col_last)) {
                    if (num_entries != sizeof(entries)) {
                        entries[num_entries] = row_small + row_small + row_small + col_small;
                        num_entries++;
                        if (row_last != -1) {
                            /******************************
                            * draw_line                   *
                            ******************************/
int r1 = row_last;
int c1 = col_last;
int r2 = row_small;
int c2 = col_small;
if (c1 == c2) {
    // vertical
    switch (r2 - r1) {
        case -2:
        case 2:
            rop_setpos(0, c1);
            rop_puts(line_10);
            rop_setpos(1, c1);
            rop_puts(line_10);
            break;
        case -1:
            rop_setpos(r2, c1);
            rop_puts(line_10);
            break;
        case 1:
            rop_setpos(r1, c1);
            rop_puts(line_10);
            break;
    }
} else {
    if (c2 < c1) {
        int temp = c1;
        c1 = c2;
        c2 = temp;
        temp = r1;
        r1 = r2;
        r2 = temp;
    }
    // now it's left to right
    rop_setpos(r1, c1);
    switch (r2 - r1) {
        case -2:
            switch (c2 - c1) {
                case 1: rop_puts(line_21$); break;
                case 2: rop_puts(line_11$); rop_setpos(1, 1); rop_puts(line_11$); break;
                default: assert(0);
            }
            break;
        case -1:
            switch (c2 - c1) {
                case 1: rop_puts(line_11$); break;
                case 2: rop_puts(line_12$); break;
                default: assert(0);
            }
            break;
        case 0:
            switch (c2 - c1) {
                case 2: rop_puts(line_01); rop_setpos(r1, 1); // fallthrough
                case 1: rop_puts(line_01); break;
                // case 0: do nothing
            }
            break;
        case 1:
            switch (c2 - c1) {
                case 1: rop_puts(line_11); break;
                case 2: rop_puts(line_12); break;
                default: assert(0);
            }
            break;
        case 2:
            switch (c2 - c1) {
                case 1: rop_puts(line_21); break;
                case 2: rop_puts(line_11); rop_setpos(1, 1); rop_puts(line_11); break;
                default: assert(0);
            }
            break;
        default:
            assert(0);
    }
}
                            /******************************
                            * draw_line (end)             *
                            ******************************/
                        }
                    } // if (num_entries < sizeof(entries))
                    row_last = row_small;
                    col_last = col_small;
                } // if motionevent on point
            } else if (motion == '#') { // release

                const int entropy[] = {7777853, 6222378, 3546017, 4445136, 7780945, 3462586, 3111820, 2405140, 3624625, 6968615, 3176867, 3710589, 7702269, 3192178, 649731, 7800749, 6017677, 6189630, 1975056, 2694116, 3038398, 1663188, 6543815, 4176440, 1696171, 2471993, 1030495, 1229599, 6638142, 7858312, 5114362, 6754064, 5507984, 2092153, 4221209, 3125287, 3738908, 4746424, 7514587, 3209489, 5982099, 5252558, 2931922, 7955762, 1710208, 296028, 3099603, 1923308, 1816384, 7460259, 4688990, 3698787, 8063985, 2904281, 2387354, 1096597, 7513812, 6846883, 1839444, 3299084, 631091, 8290017, 7160748, 1179054, 2243030, 1709908, 1675438, 240870, 5979594, 213499, 2931947, 6795798, 3096344, 6255267, 3628236, 1266072, 416109, 145294, 3209749, 7941896, 4764432};
                const int encrypted_flag[] = {296145, 7955867, 2932039, 296127, 2932038, 3209591, 5982222, 3209608, 7514691, 3209594, 296127, 7955866, 2932017, 296143, 2932026, 3209600, 5982218, 3209604, 7514682, 3209605, 296132, 7955859, 2932038, 296123, 2932036, 3209600, 5982211, 3209584, 7514692, 3209604, 296123, 7955878, 2932039, 296142, 2932027, 3209599, 5982202, 3209584, 7514686, 3209600, 296137, 7955874, 2932030, 296129, 2932038, 3209590, 5982194, 3209570, 7514656, 3209557, 296153};
                const int more_entropy[] = {4035960, 4418458, 5209189, 1108639, 4342160, 1331397, 4310812, 1590852, 3567457, 2988487, 6401034, 3601701, 917254, 4908399, 6845483, 3467160, 4871614, 313048, 410405, 4304715};
                const int sudoku_encrypted[] = {-4764425, -7941890, -3209749, -145291, -416101, -1266067, -3628235, -6255267, -3096335, -6795790, -2931943, -213490, -5979593, -240868, -1675432, -1709901, -2243025, -1179051, -7160747, -8290017, -631088, -3299080, -1839437, -6846874, -7513804, -1096595, -2387348, -2904275, -8063978, -3698786, -4688982, -7460250, -1816382, -1923304, -3099600, -296023, -1710199, -7955759, -2931918, -5252553, -5982098, -3209482, -7514587, -4746418, -3738900, -3125287, -4221207, -2092145, -5507978, -6754060, -5114359, -7858303, -6638141, -1229592, -1030491, -2471993, -1696165, -4176440, -6543812, -1663187, -3038393, -2694107, -1975054, -6189627, -6017668, -7800742, -649729, -3192173, -7702265, -3710583, -3176867, -6968614, -3624623, -2405139, -3111815, -3462586, -7780939, -4445136, -3546014, -6222371, -7777849};

                char decrypted[52];
                
                row_last = -1;
                col_last = -1;

                if(num_entries != 10) {
                    goto fail;
                }


                /******************************
                * validate                    *
                ******************************/
                int sudoku[81];
                unsigned char *entry_ptr = entries;
                for (int i = 0; i < 81; i++) {
                    int number = decrypt(sudoku_encrypted, i);
                    if (number) {
                        sudoku[i] = encrypt(number - 1, i);
                    } else {
                        sudoku[i] = encrypt(*entry_ptr, i);
                        entry_ptr++;
                    }
                    // printf("%d\n", decrypt(sudoku, i));
                }
                int seen[9];
                // rows
                for (int i = 0; i < 81; i += 9) {
                    for (int j = 0; j < 9; j++) {
                        seen[j] = 0;
                    }
                    for (int j = 0; j < 9; j++) {
                        int *num_seen = seen + (decrypt(sudoku, i + j));
                        if (*num_seen) {
                            //dprintf(2, "fail 239, %d %d %d\n", i, j, sudoku[i + j]);
                            goto fail;
                        }
                        *num_seen = 1;
                    }
                }
                // cols
                for (int i = 0; i < 9; i++) {
                    for (int j = 0; j < 9; j++) {
                        seen[j] = 0;
                    }
                    for (int j = 0; j < 81; j += 9) {
                        int *num_seen = seen + (decrypt(sudoku, i + j));
                        if (*num_seen) {
                            //dprintf(2, "fail 253, %d %d\n", i, j);
                            goto fail;
                        }
                        *num_seen = 1;
                    }
                }
                // boxes
                for (int ii = 0; ii < 81; ii += 27) { // box r
                    for (int jj = 0; jj < 9; jj += 3) { // box c
                        for (int j = 0; j < 9; j++) {
                            seen[j] = 0;
                        }
                        for (int i = 0; i < 27; i += 9) { // r within box
                            for (int j = 0; j < 3; j++) { // c within box
                                int *num_seen = seen + (decrypt(sudoku, ii + jj + i + j));
                                if (*num_seen) {
                                    //dprintf(2, "fail 269, %d %d %d %d", ii, jj, i, j);
                                    goto fail;
                                }
                                *num_seen = 1;
                            }
                        }
                    }
                }

                /******************************
                * win                         *
                ******************************/
               //password is 2 4 5 2 5 8 7 8 9 8
               //was 9 7 8 2 4 5

                for(int i = 0; i < 51; i++) {
                    int rem = i;
                    while(rem >= 10) {
                        rem -= 10;
                    }
                    
                    // printf("%d\n", remainder);
                    decrypted[i] = encrypted_flag[i] - entropy[46 - entries[rem]];
                }

                decrypted[51] = 0;

                greeting = decrypted;
                goto clear;
                fail:
                greeting = "Sorry, try again!";
                goto clear;
            }
            break;
        } // switch(num_read)
    }
}