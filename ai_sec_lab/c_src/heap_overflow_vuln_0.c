
#include <stdlib.h>
#include <string.h>
void vuln(char *input){
    char *buf=malloc(24);
    strcpy(buf,input);
    free(buf);
}
int main(int argc,char *argv[]){
    if(argc>1) vuln(argv[1]);
    return 0;
}
