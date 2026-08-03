/* 01_hello_nopie.c
 * Caso base: llamada a printf, función auxiliar, retorno de valor.
 * Compila sin PIE para obtener direcciones absolutas en la tabla de salto. */
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main(void) {
    int r = add(6, 7);
    printf("result: %d\n", r);
    return 0;
}
