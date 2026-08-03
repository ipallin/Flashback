/* 03_recursive.c
 * Recursión mutua: fib() y is_even() se llaman entre sí.
 * Valida: manejo de llamadas recursivas, bloques de retorno, epilogos. */
#include <stdio.h>

long fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

int is_even(int n) {
    if (n == 0) return 1;
    return !is_even(n - 1);
}

int main(void) {
    for (int i = 0; i < 10; i++)
        printf("fib(%d)=%ld even=%d\n", i, fib(i), is_even(i));
    return 0;
}
