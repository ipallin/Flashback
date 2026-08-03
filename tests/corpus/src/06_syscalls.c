/* 06_syscalls.c
 * Syscalls directas sin libc wrapper: write y exit vía syscall.
 * Valida: SyscallAnnotation, recuperación del número de syscall desde rax. */
#include <unistd.h>

static void write_str(const char *s) {
    long len = 0;
    while (s[len]) len++;
    /* syscall write(1, s, len) */
    __asm__ volatile (
        "syscall"
        : : "a"(1), "D"(1), "S"(s), "d"(len)
        : "rcx", "r11", "memory"
    );
}

int main(void) {
    write_str("syscall: write directo\n");
    write_str("syscall: segunda linea\n");
    /* syscall exit(0) */
    __asm__ volatile (
        "syscall"
        : : "a"(60), "D"(0)
    );
    return 0;
}
