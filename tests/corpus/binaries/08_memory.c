
#include <stdio.h>
#include <stdlib.h>
int main(void){
    int *p = malloc(8 * sizeof(int));
    for (int i = 0; i < 8; i++) p[i] = i * i;
    p = realloc(p, 16 * sizeof(int));
    long s = 0; for (int i = 0; i < 8; i++) s += p[i];
    free(p);
    printf("%ld\n", s);
    return 0;
}
