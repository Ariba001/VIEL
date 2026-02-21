
#include <stdio.h>
int main(){
    char buf[128];
    fgets(buf,128,stdin);
    printf("%s",buf);
    return 0;
}
