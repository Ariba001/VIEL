
#include <stdlib.h>
int main(){
    int *p=malloc(sizeof(int));
    free(p);
    p=NULL;
    return 0;
}
