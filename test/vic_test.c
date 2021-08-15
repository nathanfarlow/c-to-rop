#define puts(s) {const char *temp=(s);while (*temp) putchar(*(temp++));}

int main() {
    char c;

    puts("Please enter your name: ")

    char name[40];
    char *fuck = "f";

    int index = 0;
    while(1) {
        c = getchar();

        if(c == '\n') {
            break;
        }

        while(1) {
            while (1 < 2) {
                break;
            }

            while(3 > 4) {

            }
            break;
        }

        name[index++] = c;
    }

    name[index] = 0;

    puts("Your name is ");
    puts(name);
    puts("\n");
}

// void main() {
//     puts("Hi!");
// }
