
#include <stdio.h>
#include <string.h>

void safe(char *input){
    char buf[32];
    int state = 0;

    while(1){
        switch(state){
            case 0:
                state = 1;
                break;

            case 1:
                strncpy(buf,input,31);
                buf[31]='\0';
                state = 2;
                break;

            case 2:
                printf("%s",buf);
                return;
        }
    }
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
