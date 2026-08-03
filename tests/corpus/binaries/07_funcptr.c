
#include <stdio.h>
static int add(int a,int b){ return a+b; }
static int sub(int a,int b){ return a-b; }
static int mul(int a,int b){ return a*b; }
int main(void){
    int (*ops[3])(int,int) = { add, sub, mul };
    int acc = 7;
    for (int i = 0; i < 3; i++) acc = ops[i](acc, 3);
    printf("%d\n", acc);
    return 0;
}
