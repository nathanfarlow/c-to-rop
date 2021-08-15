
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

void elvm_putchar(char c) {
    write(1, &c, sizeof(char));
}

char elvm_getchar() {
    char c;
    read(0, &c, sizeof(char));
    return c;
}

void elvm_puts(char *buf) {
    while(*buf) elvm_putchar(*buf++);
}

int main() {
    setbuf(stdin, NULL);


    // Game code here
    elvm_puts("Hello world\n");

    char c;
    while((c = getch()) != '\n') {
        putchar(c);
    }
    return 0;
}