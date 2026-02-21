
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

void vulnerable(char *input){
    char buf[32];
    asm_noise();
    strcpy(buf,input);  // vuln
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
