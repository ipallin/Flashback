"""
Convención de llamada AAPCS (ARM 32-bit Linux).

r0-r3: argumentos (primeros 4); adicionales en la pila.
r0: retorno (r0-r1 para valores 64-bit).
r7: número de syscall en EABI (svc #0).
r0-r5: argumentos de syscall.
"""

ARG_REGISTERS = ['r0', 'r1', 'r2', 'r3']

RETURN_REGISTER = 'r0'

SYSCALL_NUM_REGISTER = 'r7'

SYSCALL_ARG_REGISTERS = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5']

# Callee-saved: r4-r11, sp(r13), lr(r14) cuando se usa como frame
CALLEE_SAVED = ['r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11']

# Caller-saved (scratch)
CALLER_SAVED = ['r0', 'r1', 'r2', 'r3', 'r12']
