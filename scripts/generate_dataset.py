import os
import subprocess
import csv
import random

BASE_DIR = "ai_sec_lab"
SRC_DIR = os.path.join(BASE_DIR, "c_src")
BIN_DIR = os.path.join(BASE_DIR, "binaries")
LABEL_FILE = os.path.join(BASE_DIR, "labels.csv")

os.makedirs(SRC_DIR, exist_ok=True)
os.makedirs(BIN_DIR, exist_ok=True)

optimization_flags = ["-O0", "-O1", "-O2", "-O3"]

architectures = {
    "x86": "gcc"
}

templates = {

# ================= STACK OVERFLOW =================
"stack_overflow_vuln": ("""
#include <stdio.h>
#include <string.h>
void vuln(char *input){
    char buf[64];
    strcpy(buf,input);
}
int main(int argc,char *argv[]){
    if(argc>1) vuln(argv[1]);
    return 0;
}
""", 1),

"stack_safe": ("""
#include <stdio.h>
#include <string.h>
void safe(char *input){
    char buf[64];
    strncpy(buf,input,{size}-1);
    buf[{size}-1]='\\0';
}
int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
""", 0),

# ================= HEAP OVERFLOW =================
"heap_overflow_vuln": ("""
#include <stdlib.h>
#include <string.h>
void vuln(char *input){
    char *buf=malloc({size});
    strcpy(buf,input);
    free(buf);
}
int main(int argc,char *argv[]){
    if(argc>1) vuln(argv[1]);
    return 0;
}
""", 1),

"heap_safe": ("""
#include <stdlib.h>
#include <string.h>
void safe(char *input){
    char *buf=malloc({size});
    strncpy(buf,input,{size}-1);
    buf[{size}-1]='\\0';
    free(buf);
}
int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
""", 0),

# ================= FORMAT STRING =================
"format_vuln": ("""
#include <stdio.h>
int main(){
    char buf[128];
    fgets(buf,128,stdin);
    printf(buf);
    return 0;
}
""", 1),

"format_safe": ("""
#include <stdio.h>
int main(){
    char buf[128];
    fgets(buf,128,stdin);
    printf("%s",buf);
    return 0;
}
""", 0),

# ================= DOUBLE FREE =================
"double_free_vuln": ("""
#include <stdlib.h>
int main(){
    int *p=malloc(sizeof(int));
    free(p);
    free(p);
    return 0;
}
""", 1),

"double_free_safe": ("""
#include <stdlib.h>
int main(){
    int *p=malloc(sizeof(int));
    free(p);
    p=NULL;
    return 0;
}
""", 0),

# ================= USE AFTER FREE =================
"use_after_free_vuln": ("""
#include <stdlib.h>
#include <stdio.h>
int main(){
    int *p=malloc(sizeof(int));
    *p=10;
    free(p);
    printf("%d",*p);
    return 0;
}
""", 1),

"use_after_free_safe": ("""
#include <stdlib.h>
int main(){
    int *p=malloc(sizeof(int));
    free(p);
    p=NULL;
    return 0;
}
""", 0),

# ================= INTEGER OVERFLOW =================
"int_overflow_vuln": ("""
#include <stdio.h>
int main(){
    int a={size};
    int b={size};
    int c=a*b;
    printf("%d",c);
    return 0;
}
""", 1),

"int_safe": ("""
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
""", 0),

# ================= NULL DEREFERENCE =================
"null_deref_vuln": ("""
#include <stdio.h>
int main(){
    int *p=NULL;
    printf("%d",*p);
    return 0;
}
""", 1),

"null_deref_safe": ("""
#include <stdio.h>
int main(){
    int *p=NULL;
    if(p) printf("%d",*p);
    return 0;
}
""", 0),

# ================= OUT OF BOUNDS =================
"oob_vuln": ("""
#include <stdio.h>
int main(){
    int arr[10];
    arr[20]=5;
    return 0;
}
""", 1),

"oob_safe": ("""
#include <stdio.h>
int main(){
    int arr[10];
    arr[5]=5;
    return 0;
}
""", 0),

# ================= RACE CONDITION =================
"race_vuln": ("""
#include <pthread.h>
int counter=0;
void* inc(void* arg){
    for(int i=0;i<{loops};i++) counter++;
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
""", 1),

"race_safe": ("""
#include <pthread.h>
pthread_mutex_t lock;
int counter=0;
void* inc(void* arg){
    for(int i=0;i<{loops};i++){
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}
int main(){
    pthread_t t1,t2;
    pthread_mutex_init(&lock,NULL);
    pthread_create(&t1,NULL,inc,NULL);
    pthread_create(&t2,NULL,inc,NULL);
    pthread_join(t1,NULL);
    pthread_join(t2,NULL);
    pthread_mutex_destroy(&lock);
    return 0;
}
""", 0),

# ================= COMMAND INJECTION =================
"cmd_injection_vuln": ("""
#include <stdlib.h>
int main(int argc,char *argv[]){
    if(argc>1){
        system(argv[1]);
    }
    return 0;
}
""", 1),

"cmd_injection_safe": ("""
#include <stdlib.h>
int main(){
    system("ls");
    return 0;
}
""", 0),

"arm_stack_vuln":("""
#include <string.h>

void vulnerable(char *input){
    char buf[32];
    strcpy(buf,input);
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
""", 1),

"arm_stack_safe": ("""
#include <string.h>

void safe(char *input){
    char buf[32];
    strncpy(buf,input,31);
    buf[31]='\\0';
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
""", 0),

"inline_asm_vuln": ("""
#include <stdio.h>
#include <string.h>

void asm_noise(){
    __asm__(
        "mov $5, %%eax\\n\\t"
        "add $3, %%eax\\n\\t"
        :
        :
        : "eax"
    );
}

void vulnerable(char *input){
    char buf[32];
    asm_noise();
    strcpy(buf,input);  // vuln
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
""",1),

"inline_asm_safe": ("""
#include <stdio.h>
#include <string.h>

void asm_noise(){
    __asm__(
        "mov $5, %%eax\\n\\t"
        "add $3, %%eax\\n\\t"
        :
        :
        : "eax"
    );
}

void safe(char *input){
    char buf[32];
    asm_noise();
    strncpy(buf,input,31);
    buf[31]='\\0';
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
""", 0),

"opaque_predicate_vuln": ("""
#include <stdio.h>
#include <string.h>

int always_true(){
    int x = 1234;
    return (x * x) % 2 == 0 || (x * x) % 2 == 1;
}

void vulnerable(char *input){
    char buf[32];
    if(always_true()){
        strcpy(buf,input);  // vuln
    }
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
""",1),

"opaque_predicate_safe": ("""
#include <stdio.h>
#include <string.h>

int always_true(){
    int x = 1234;
    return (x * x) % 2 == 0 || (x * x) % 2 == 1;
}

void safe(char *input){
    char buf[32];
    if(always_true()){
        strncpy(buf,input,31);
        buf[31]='\\0';
    }
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
""", 0),

"dead_code_vuln":("""
#include <stdio.h>
#include <string.h>

int useless(int x){
    int a=0;
    for(int i=0;i<1000;i++){
        a += i * x;
    }
    return a;
}

void vulnerable(char *input){
    char buf[32];
    useless(5);  // dead code
    strcpy(buf,input);  // vuln
}

int main(int argc,char *argv[]){
    if(argc>1) vulnerable(argv[1]);
    return 0;
}
""",1),

"dead_code_safe": ("""
#include <stdio.h>
#include <string.h>

int useless(int x){
    int a=0;
    for(int i=0;i<1000;i++){
        a += i * x;
    }
    return a;
}

void safe(char *input){
    char buf[32];
    useless(5);
    strncpy(buf,input,31);
    buf[31]='\\0';
}

int main(int argc,char *argv[]){
    if(argc>1) safe(argv[1]);
    return 0;
}
""", 0),

"control_flow_flatten_vuln":("""
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
""",1),

"control_flow_flatten_safe": ("""
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
                buf[31]='\\0';
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
""", 0),
}

rows = []

for name, (template, label) in templates.items():

    for i in range(10):  # 10 variations

        size = random.randint(16, 128)
        loops = random.randint(10000, 200000)

        # Safe formatting even if template doesn't use size/loops
        code = template
        code = code.replace("{size}", str(size))
        code = code.replace("{loops}", str(loops))


        src_file = os.path.join(SRC_DIR, f"{name}_{i}.c")

        with open(src_file, "w") as f:
            f.write(code)

        for arch_name, compiler in architectures.items():

            for opt in optimization_flags:

                bin_name = f"{name}_{i}_{arch_name}_{opt.replace('-', '')}"
                bin_path = os.path.join(BIN_DIR, bin_name)

                compile_cmd = [
                    compiler,
                    src_file,
                    "-o", bin_path,
                    opt,
                    "-fno-stack-protector",
                    "-no-pie"
                ]

                # Add pthread if race condition
                if "race" in name:
                    compile_cmd.append("-lpthread")

                result = subprocess.run(
                    compile_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                if result.returncode != 0:
                    print(f"[ERROR] Failed compiling {bin_name}")
                    print(result.stderr.decode())
                    continue

                rows.append([bin_name, label])

with open(LABEL_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["filename", "label"])
    writer.writerows(rows)

print("Dataset generation complete.")
print(f"Binaries saved in: {BIN_DIR}")
print(f"Labels saved in: {LABEL_FILE}")