#include <stdio.h>
void vuln() {
    char buf[64];
    fgets(buf, 64, stdin);
}
int main() {
    vuln();
    return 0;
}
