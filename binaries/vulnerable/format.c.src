#include <stdio.h>

void vuln(char *input) {
    printf(input);
}

int main(int argc, char *argv[]) {
    if (argc > 1)
        vuln(argv[1]);
    return 0;
}
