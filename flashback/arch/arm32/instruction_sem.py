"""
Clasificación semántica de instrucciones ARM32.

ARM32 tiene ejecución condicional en casi todas las instrucciones.
Los sufijos de condición (eq, ne, lt, gt, etc.) forman parte del mnemónico
tal como los devuelve capstone: beq, bne, addlt, movgt, etc.
"""

from __future__ import annotations

# Ramas incondicionales (terminan bloque sin condición)
UNCOND_JUMP_MNEMONICS = frozenset({'b', 'bx', 'bxj'})

# Ramas condicionales (capstone las devuelve con sufijo de condición)
COND_BRANCH_MNEMONICS = frozenset({
    'beq', 'bne', 'bcs', 'bcc', 'bmi', 'bpl', 'bvs', 'bvc',
    'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'bal',
    'bhs', 'blo',                   # alias de bcs/bcc
})

# Llamadas (branch with link)
CALL_MNEMONICS = frozenset({'bl', 'blx', 'blxns'})

# Retornos (bx lr, pop {pc}, ldm sp!,{...,pc})
RET_MNEMONICS = frozenset({'bx', 'pop'})   # heurística: bx lr, pop {...,pc}

# Syscall ARM EABI: svc #0 (supervisor call)
SYSCALL_MNEMONICS = frozenset({'svc', 'swi'})

# Condiciones ARM32 → expresión C usando flags NZCV
ARM32_COND_TO_C: dict[str, str] = {
    'eq': 'Z',                      # Equal (Z=1)
    'ne': '!Z',                     # Not Equal (Z=0)
    'cs': 'C',  'hs': 'C',         # Carry Set / Unsigned Higher or Same
    'cc': '!C', 'lo': '!C',        # Carry Clear / Unsigned Lower
    'mi': 'N',                      # Minus / Negative
    'pl': '!N',                     # Plus / Positive
    'vs': 'V',                      # Overflow
    'vc': '!V',                     # No Overflow
    'hi': '(C && !Z)',              # Unsigned Higher
    'ls': '(!C || Z)',              # Unsigned Lower or Same
    'ge': '(N == V)',               # Signed >=
    'lt': '(N != V)',               # Signed <
    'gt': '(!Z && N == V)',         # Signed >
    'le': '(Z || N != V)',          # Signed <=
    'al': '1',                      # Always
}


def _extract_condition(mnemonic: str) -> str | None:
    """Extrae el sufijo de condición ARM32 de un mnemónico como 'beq', 'addne'."""
    for suffix in sorted(ARM32_COND_TO_C.keys(), key=len, reverse=True):
        if mnemonic.endswith(suffix):
            return suffix
    return None


def is_prologue_block(mnemonics: list[str], operands: list[str]) -> bool:
    """Heurística: push {r4, lr} o push {fp, lr} al inicio."""
    for m, o in zip(mnemonics, operands):
        if m in ('push', 'stmfd', 'stmdb'):
            if 'lr' in o or 'r14' in o:
                return True
    return False


def is_epilogue_block(mnemonics: list[str], operands: list[str]) -> bool:
    """Heurística: pop {pc} o bx lr al final."""
    if not mnemonics:
        return False
    last_m = mnemonics[-1]
    last_o = operands[-1] if operands else ''
    if last_m in ('bx', 'bxeq', 'bxne') and 'lr' in last_o:
        return True
    if last_m in ('pop', 'ldmfd', 'ldmia') and 'pc' in last_o:
        return True
    return False
