
#include <stdio.h>
int main(){
    char buf[128];
    fgets(buf,128,stdin);
    printf(buf);
    return 0;
}
