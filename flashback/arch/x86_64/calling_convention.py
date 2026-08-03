"""
Convención de llamada System V AMD64 ABI.
"""

# Registros de argumentos en orden (enteros y punteros)
ARG_REGISTERS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

# Registro de retorno
RETURN_REGISTER = 'rax'

# Registros preservados por el llamado (callee-saved)
CALLEE_SAVED = ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15']

# Registros que el llamador puede asumir destruidos (caller-saved)
CALLER_SAVED = ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']


def arg_register(position: int) -> str | None:
    """Devuelve el nombre del registro para el argumento en la posición dada (0-based)."""
    return ARG_REGISTERS[position] if position < len(ARG_REGISTERS) else None
