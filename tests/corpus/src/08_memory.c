/* 08_memory.c
 * Asignación dinámica: malloc/free/realloc, acceso a heap.
 * Valida: llamadas externas de gestión de memoria, múltiples bloques. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int *build_array(int n) {
    int *arr = (int *)malloc(n * sizeof(int));
    if (!arr) return NULL;
    for (int i = 0; i < n; i++)
        arr[i] = i * i;
    return arr;
}

int main(void) {
    int n = 8;
    int *arr = build_array(n);
    if (!arr) { fprintf(stderr, "malloc failed\n"); return 1; }

    int sum = 0;
    for (int i = 0; i < n; i++) sum += arr[i];
    printf("sum_of_squares(%d)=%d\n", n, sum);

    arr = (int *)realloc(arr, (n + 4) * sizeof(int));
    for (int i = n; i < n + 4; i++) arr[i] = i;
    printf("arr[%d]=%d\n", n + 3, arr[n + 3]);

    free(arr);
    return 0;
}
