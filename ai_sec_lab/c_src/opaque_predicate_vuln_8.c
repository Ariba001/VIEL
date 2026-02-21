
#include <stdio.h>
#include <string.h>

int always_true(){
    int x = 1234;
    return (x * x) % 2 == 0 || (x * x) % 2 == 1;
}

void vulnerable(char *input){
    char buf[32];
    if(always_true()){
        strcpy(buf,input);  // vuln
    }
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
