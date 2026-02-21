
#include <stdio.h>
#include <string.h>
void safe(char *input){
    char buf[64];
    strncpy(buf,input,68-1);
    buf[68-1]='\0';
}
int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
