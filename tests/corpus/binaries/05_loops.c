
#include <stdio.h>
int main(void){
    long acc = 0;
    for (int i = 1; i <= 100; i++){
        int n = i;
        while (n != 1){ n = (n % 2 == 0) ? n/2 : 3*n + 1; acc++; }
    }
    printf("%ld\n", acc);
    return 0;
}
