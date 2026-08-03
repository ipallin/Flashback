/* 04_strings.c
 * Operaciones de cadena: strlen, strcpy, strcmp, strcat, sprintf.
 * Valida: múltiples llamadas externas, bloques external_call_site. */
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Hola, %s!", name);
    printf("%s (len=%zu)\n", buf, strlen(buf));
}

int main(void) {
    const char *names[] = {"Alice", "Bob", "Carlos"};
    for (int i = 0; i < 3; i++)
        greet(names[i]);

    char a[32] = "foo";
    char b[32] = "bar";
    strcat(a, b);
    printf("concat: %s cmp=%d\n", a, strcmp(a, "foobar"));
    return 0;
}
