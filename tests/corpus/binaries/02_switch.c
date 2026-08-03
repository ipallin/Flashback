
#include <stdio.h>
int main(void){
    int total = 0;
    for (int i = 0; i < 5; i++){
        switch (i){
            case 0: total += 10; break;
            case 1: total += 20; break;
            case 2: total += 30; break;
            case 3: total += 40; break;
            default: total += 50; break;
        }
    }
    printf("%d\n", total);
    return 0;
}
