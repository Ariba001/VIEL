#include <stdio.h>
#include <stdlib.h>

void vuln(int a, int b) {
    int size = a * b;
    char *p = malloc(size);
    fgets(p, 1024, stdin);
}

int main() {
    vuln(100000, 100000);
    return 0;
}
