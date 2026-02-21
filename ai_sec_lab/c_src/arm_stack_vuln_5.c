
#include <string.h>

void vulnerable(char *input){
    char buf[32];
    strcpy(buf,input);
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
