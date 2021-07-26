#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

void die(int signum) __attribute__ ((noreturn));
int main() __attribute__ ((noreturn));
void rop();

struct termios original_mode;

void die(int signum) {
    const char *s = "\e[?1002l\e[?25h";
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

    rop();

    die(1);
}

#ifdef LOCKSCREEN_POC
#include "rop.c"
#endif
