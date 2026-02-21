
#include <pthread.h>
int counter=0;
void* inc(void* arg){
    for(int i=0;i<158341;i++) counter++;
    return NULL;
}
int main(){
    pthread_t t1,t2;
    pthread_create(&t1,NULL,inc,NULL);
    pthread_create(&t2,NULL,inc,NULL);
    pthread_join(t1,NULL);
    pthread_join(t2,NULL);
    return 0;
}
