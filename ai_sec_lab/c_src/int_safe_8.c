
#include <stdio.h>
#include <limits.h>
int safe_mul(int a,int b){
    if(a>INT_MAX/b) return -1;
    return a*b;
}
int main(){
    printf("%d",safe_mul(1000,1000));
    return 0;
}
