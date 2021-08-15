#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

void die(int signum) __attribute__ ((noreturn));
int main() __attribute__ ((noreturn));

struct termios original_mode;

void die(int signum) {
    const char *s = "\x1b[?1002l";
    write(STDOUT_FILENO, s, strlen(s));
    tcsetattr(STDIN_FILENO, TCSANOW, &original_mode);
    exit(signum);
}

int main() {
    struct termios mode;
    if (tcgetattr(STDIN_FILENO, &mode)) {
        printf("Couldn't access terminal mode");
        die(1);
    }
    memcpy(&original_mode, &mode, sizeof(original_mode));

    tcflag_t flags_removed = ICANON | ECHO;
    mode.c_lflag &= ~flags_removed;
    tcsetattr(STDIN_FILENO, TCSANOW, &mode);

    signal(SIGINT, die);

    const char *s = "\x1b[?1002h";
    write(STDOUT_FILENO, s, strlen(s));

    char c;
    int num_read = 0;
    char motion;
    int x, y;
    while (read(STDIN_FILENO, &c, 1)) {
        switch (num_read) {
          case 0:
            if (c == '\x1b') {
                num_read++;
            }
            break;
          case 1:
            if (c == '[') {
                num_read++;
            } else {
                num_read = 0;
            }
            break;
          case 2:
            if (c == 'M') {
                num_read++;
            } else {
                num_read = 0;
            }
            break;
          case 3:
            motion = c;
            num_read++;
            break;
          case 4:
            x = c - 32;
            num_read++;
            break;
          case 5:
            y = c - 32;
            num_read = 0;
            printf("Type: '%c' x: %2d y: %2d\n", motion, x, y);
            break;
        }
    }
    die(1);
}