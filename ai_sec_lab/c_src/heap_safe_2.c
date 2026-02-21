
#include <stdlib.h>
#include <string.h>
void safe(char *input){
    char *buf=malloc(100);
    strncpy(buf,input,100-1);
    buf[100-1]='\0';
    free(buf);
}
int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
