"""
Convención de llamada AAPCS64 (ARM64 Procedure Call Standard).
"""

# Registros de argumentos en orden (enteros, punteros y resultados)
ARG_REGISTERS = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']

# Registro de retorno
RETURN_REGISTER = 'x0'

# Registros preservados por el llamado (callee-saved)
CALLEE_SAVED = ['x19', 'x20', 'x21', 'x22', 'x23', 'x24',
                'x25', 'x26', 'x27', 'x28', 'x29', 'x30']

# Registros que el llamador puede asumir destruidos (caller-saved)
CALLER_SAVED = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
                'x16', 'x17', 'x18']

# Registro de número de syscall
SYSCALL_NUM_REGISTER = 'x8'


def arg_register(position: int) -> str | None:
    """Devuelve el nombre del registro para el argumento en la posición dada (0-based)."""
    return ARG_REGISTERS[position] if position < len(ARG_REGISTERS) else None
