
#include <stdio.h>
#include <string.h>

int useless(int x){
    int a=0;
    for(int i=0;i<1000;i++){
        a += i * x;
    }
    return a;
}

void safe(char *input){
    char buf[32];
    useless(5);
    strncpy(buf,input,31);
    buf[31]='\0';
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
