/* 02_switch.c
 * Switch con 5 casos → GCC genera tabla de salto indexada (jmp [rax*8+table]).
 * Valida Fase 1: resolución de jump tables. */
#include <stdio.h>
#include <stdlib.h>

const char *day_name(int d) {
    switch (d) {
        case 0: return "lunes";
        case 1: return "martes";
        case 2: return "miercoles";
        case 3: return "jueves";
        case 4: return "viernes";
        default: return "fin de semana";
    }
}

int main(void) {
    for (int i = 0; i <= 5; i++)
        printf("%d: %s\n", i, day_name(i));
    return 0;
}
