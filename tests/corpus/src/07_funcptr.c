/* 07_funcptr.c
 * Punteros a función pasados como argumento (dispatch table).
 * Valida Fase 2: backward slice resuelve 'mov rax, &func; call rax'. */
#include <stdio.h>

typedef int (*op_fn)(int, int);

int op_add(int a, int b) { return a + b; }
int op_sub(int a, int b) { return a - b; }
int op_mul(int a, int b) { return a * b; }

int apply(op_fn fn, int a, int b) {
    return fn(a, b);
}

int main(void) {
    op_fn ops[] = {op_add, op_sub, op_mul};
    const char *names[] = {"add", "sub", "mul"};
    int a = 12, b = 4;
    for (int i = 0; i < 3; i++)
        printf("%s(%d,%d)=%d\n", names[i], a, b, apply(ops[i], a, b));
    return 0;
}
