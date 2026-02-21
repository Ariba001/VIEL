
#include <stdio.h>
#include <string.h>

int useless(int x){
    int a=0;
    for(int i=0;i<1000;i++){
        a += i * x;
    }
    return a;
}

void vulnerable(char *input){
    char buf[32];
    useless(5);  // dead code
    strcpy(buf,input);  // vuln
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
