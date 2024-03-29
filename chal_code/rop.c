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

void rop() {
    const char line_01[]  = "\e[2C~~~~~~~";
    const char line_10[]  = "\e[B~\e[B\e[D~\e[B\e[D~\e[B\e[D~";
    const char line_11[]  = "\e[B\e[C\e[C~\e[C\e[B~\e[C\e[B~\e[C\e[B~";
    const char line_11$[] = "\e[A\e[C\e[C~\e[C\e[A~\e[C\e[A~\e[C\e[A~";
    const char line_21[]  = "\e[B\e[C~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~\e[B~";
    const char line_21$[] = "\e[A\e[C~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~\e[A~";
    const char line_12[]  = "\e[B\e[C~~~~~\e[B~~~~~\e[B\e[D~~~~~\e[B~~~~~";
    const char line_12$[] = "\e[A\e[C~~~~~\e[A~~~~~\e[A\e[D~~~~~\e[A~~~~~";

    char *greeting = "Draw pattern to get flag";
    int row_last = -1;
    int col_last = -1;
    unsigned char entries[10];
    int num_entries;

    int sudoku_orig[] = {7,6,2,3,8,5,1,4,0,
                         8,4,9,1,2,6,0,5,3,
                         1,5,3,4,7,9,8,2,6,
                         6,7,1,0,9,2,4,3,5,
                         9,3,4,5,1,7,0,6,8,
                         5,2,8,6,0,3,9,1,7,
                         4,8,6,7,3,1,0,9,2,
                         3,9,7,2,5,4,6,8,1,
                         2,1,5,9,6,8,3,7,4};

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
                row_last = -1;
                col_last = -1;
                /******************************
                * validate                    *
                ******************************/
                int sudoku[81];
                unsigned char *entry_ptr = entries;
                for (int i = 0; i < 81; i++) {
                    int number = sudoku_orig[i];
                    if (number) {
                        sudoku[i] = number - 1;
                    } else {
                        sudoku[i] = *entry_ptr;
                        entry_ptr++;
                    }
                }
                int seen[9];
                // rows
                for (int i = 0; i < 81; i += 9) {
                    for (int j = 0; j < 9; j++) {
                        seen[j] = 0;
                    }
                    for (int j = 0; j < 9; j++) {
                        int *num_seen = seen + (sudoku[i + j]);
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
                        int *num_seen = seen + (sudoku[i + j]);
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
                                int *num_seen = seen + (sudoku[ii + jj + i + j]);
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
                greeting = "uiuctf{fake_flag}";
                goto clear;
                fail:
                greeting = "Sorry, try again!";
                goto clear;
            }
            break;
        } // switch(num_read)
    }
}
