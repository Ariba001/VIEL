
#include <stdio.h>
#include <string.h>

void asm_noise(){
    __asm__(
        "mov $5, %%eax\n\t"
        "add $3, %%eax\n\t"
        :
        :
        : "eax"
    );
}

void safe(char *input){
    char buf[32];
    asm_noise();
    strncpy(buf,input,31);
    buf[31]='\0';
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
