
#include <stdio.h>
#include <string.h>

int always_true(){
    int x = 1234;
    return (x * x) % 2 == 0 || (x * x) % 2 == 1;
}

void safe(char *input){
    char buf[32];
    if(always_true()){
        strncpy(buf,input,31);
        buf[31]='\0';
    }
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
