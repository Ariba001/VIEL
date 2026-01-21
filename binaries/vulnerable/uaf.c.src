#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char *p = malloc(32);
    free(p);
    printf("%s\n", p);
}

int main() {
    vuln();
    return 0;
}
