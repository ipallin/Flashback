/* 05_loops.c
 * Bucles: for, while, do-while anidados.
 * Valida: loop_header detection, back-edges, bloques condicionales. */
#include <stdio.h>

int sum_matrix(int rows, int cols) {
    int total = 0;
    for (int i = 0; i < rows; i++) {
        int row_sum = 0;
        int j = 0;
        while (j < cols) {
            row_sum += i * cols + j;
            j++;
        }
        total += row_sum;
    }
    return total;
}

int collatz(int n) {
    int steps = 0;
    do {
        if (n % 2 == 0) n /= 2;
        else n = 3 * n + 1;
        steps++;
    } while (n != 1);
    return steps;
}

int main(void) {
    printf("matrix_sum(4,4)=%d\n", sum_matrix(4, 4));
    for (int n = 1; n <= 10; n++)
        printf("collatz(%d)=%d\n", n, collatz(n));
    return 0;
}
