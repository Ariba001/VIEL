
#include <string.h>

void safe(char *input){
    char buf[32];
    strncpy(buf,input,31);
    buf[31]='\0';
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
