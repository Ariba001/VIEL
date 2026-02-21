
#include <stdlib.h>
#include <string.h>
void safe(char *input){
    char *buf=malloc(28);
    strncpy(buf,input,28-1);
    buf[28-1]='\0';
    free(buf);
}
int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
