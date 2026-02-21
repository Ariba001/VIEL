
#include <stdio.h>
#include <string.h>

void vulnerable(char *input){
    char buf[32];
    int state = 0;

    while(1){
        switch(state){
            case 0:
                state = 1;
                break;

            case 1:
                strcpy(buf,input);  // vuln
                state = 2;
                break;

            case 2:
                printf("%s",buf);
                return;
        }
    }
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
