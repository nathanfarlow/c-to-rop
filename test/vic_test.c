char a[] = "\1\2\3\4\"";
int main() {
    for (char *i = a; *i; i++) {
        putchar(*i);
    }
}
