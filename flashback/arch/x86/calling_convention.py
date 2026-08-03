"""
Convención de llamada cdecl (x86 32-bit Linux).

cdecl: argumentos empujados en la pila en orden inverso, retorno en eax.
Syscalls int 0x80: número en eax, args en ebx, ecx, edx, esi, edi, ebp.
"""

# Registros de argumentos para syscalls int 0x80
SYSCALL_ARG_REGISTERS = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']

# Registro del número de syscall
SYSCALL_NUM_REGISTER = 'eax'

# Registro de retorno
RETURN_REGISTER = 'eax'

# Callee-saved (cdecl)
CALLEE_SAVED = ['ebx', 'esi', 'edi', 'ebp', 'esp']

# Caller-saved
CALLER_SAVED = ['eax', 'ecx', 'edx']
