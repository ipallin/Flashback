"""
Clasificación semántica de instrucciones ARM32.

ARM32 tiene ejecución condicional en casi todas las instrucciones.
Los sufijos de condición (eq, ne, lt, gt, etc.) forman parte del mnemónico
tal como los devuelve capstone: beq, bne, addlt, movgt, etc.
"""

from __future__ import annotations

import re

from flashback.core.cfg_builder import Flow

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


# ---------------------------------------------------------------------------
# Clasificación de flujo de control (ARM y Thumb-2)
# ---------------------------------------------------------------------------

# Mnemónicos base (sin sufijo de condición ni de anchura) relevantes para el flujo
_FLOW_BASES = frozenset({
    'b', 'bl', 'blx', 'blxns', 'bx', 'bxj', 'bxns', 'cbz', 'cbnz', 'tbb', 'tbh',
    'pop', 'ldm', 'ldmia', 'ldmfd', 'ldmdb', 'ldmea', 'ldmib', 'ldmed', 'ldmda', 'ldmfa',
    'ldr', 'mov', 'movs', 'add', 'adds', 'sub', 'subs',
    'svc', 'swi', 'udf', 'bkpt',
})

_COND_SUFFIXES = frozenset(ARM32_COND_TO_C)


def split_arm_mnemonic(mnemonic: str) -> tuple[str, str | None]:
    """
    Separa un mnemónico ARM/Thumb en (base, condición).

    Elimina el calificador de anchura Thumb-2 ('.w', '.n') y el sufijo de
    condición (incluido el que capstone añade dentro de bloques IT):
      'beq.w' → ('b', 'eq'),  'popne' → ('pop', 'ne'),  'bls' → ('b', 'ls'),
      'bleq' → ('bl', 'eq'),  'blx' → ('blx', None),    'bal' → ('b', None).
    Los mnemónicos ajenos al flujo de control se devuelven sin tocar.
    """
    m = mnemonic.lower()
    if m.endswith(('.w', '.n')):
        m = m[:-2]
    if m in _FLOW_BASES:
        return m, None
    base, cond = m[:-2], m[-2:]
    if base in _FLOW_BASES and cond in _COND_SUFFIXES:
        return base, (None if cond == 'al' else cond)
    return m, None


def _reglist(operands: str) -> list[str]:
    if '{' not in operands:
        return []
    inner = operands[operands.index('{') + 1: operands.rindex('}')]
    return [r.strip().lower() for r in inner.split(',')]


def classify_arm_flow(mnemonic: str, operands: str, *, syscalls: bool = True):
    """
    Clasifica una instrucción ARM/Thumb-2 para el CFGBuilder.

    Devuelve un Flow o None si la instrucción no altera el flujo. Las escrituras
    en pc se detectan por operando: 'pop {..., pc}', 'ldm sp!, {..., pc}' y
    'ldr pc, [sp], #4' son retornos; 'bx lr' y 'mov pc, lr' también; 'bx rN',
    'ldr pc, [rB, rI, lsl #2]', 'add pc, rN' y 'tbb/tbh' son saltos indirectos.
    'svc' solo termina bloque si syscalls=True (en bare-metal es una llamada
    al kernel/RTOS que continúa en la siguiente instrucción).
    """
    base, cond = split_arm_mnemonic(mnemonic)
    conditional = cond is not None
    ops = operands.strip().lower()
    parts = [p.strip() for p in ops.split(',')]
    dst = parts[0]
    src = parts[1] if len(parts) > 1 else ''

    if base == 'b':
        return Flow('branch', conditional)
    if base in ('cbz', 'cbnz'):
        return Flow('branch', True)
    if base in ('bl', 'blx', 'blxns'):
        return Flow('call', conditional)
    if base in ('bx', 'bxj', 'bxns'):
        kind = 'return' if dst in ('lr', 'r14') else 'indirect_jump'
        return Flow(kind, conditional)
    if base in ('tbb', 'tbh'):
        return Flow('indirect_jump', conditional)
    if base == 'pop' or base.startswith('ldm'):
        if 'pc' in _reglist(ops) or 'r15' in _reglist(ops):
            from_stack = base == 'pop' or dst.rstrip('!') in ('sp', 'r13')
            return Flow('return' if from_stack else 'indirect_jump', conditional)
        return None
    if dst in ('pc', 'r15'):
        if base == 'ldr':
            # ldr pc, [sp], #4  ≡  pop {pc}
            is_pop = ops.replace(' ', '').startswith('pc,[sp],#4')
            return Flow('return' if is_pop else 'indirect_jump', conditional)
        if base in ('mov', 'movs', 'subs') and src in ('lr', 'r14'):
            # mov pc, lr  /  subs pc, lr, #imm (retorno de excepción)
            return Flow('return', conditional)
        if base in ('mov', 'movs', 'add', 'adds', 'sub', 'subs'):
            return Flow('indirect_jump', conditional)
        return None
    if base in ('svc', 'swi'):
        return Flow('syscall', conditional) if syscalls else None
    if base in ('udf', 'bkpt'):
        return Flow('halt', conditional)
    return None


def resolve_arm_branch_target(mnemonic: str, operands: str) -> int | None:
    """
    Resuelve el destino inmediato de una rama ARM/Thumb.

    El destino es siempre el último operando: 'b #0x8000' pero también
    'cbz r3, #0x8000'. Los operandos de registro ('bx lr', 'blx r3') → None.
    """
    o = operands.strip()
    if not o:
        return None
    o = o.rsplit(',', 1)[-1].strip()
    if o.startswith('#'):
        o = o[1:]
    try:
        if o.startswith('0x') or o.startswith('-0x'):
            return int(o, 16)
        if o.lstrip('-').isdigit():
            return int(o)
    except ValueError:
        pass
    return None


# ---------------------------------------------------------------------------
# Cargas relativas a pc (literal pools)
# ---------------------------------------------------------------------------

# Tamaño del dato que lee cada carga relativa a pc
_LITERAL_LOAD_SIZES = {
    'ldr': 4, 'ldrh': 2, 'ldrsh': 2, 'ldrb': 1, 'ldrsb': 1, 'ldrd': 8,
}
_PC_REL_RE = re.compile(r'\[pc,\s*#(-?0x[0-9a-f]+|-?\d+)\]$')


def literal_reference(mnemonic: str, operands: str, address: int,
                      thumb: bool = True) -> tuple[int, int] | None:
    """
    (dirección, tamaño) del literal que lee una carga relativa a pc, o None.

    'ldr r0, [pc, #0x1c]' en Thumb lee de Align(address + 4, 4) + 0x1c; en
    modo ARM, de address + 8 + 0x1c. 'vldr d6, [pc, #8]' lee 8 bytes.
    """
    ops = operands.strip().lower()
    m = _PC_REL_RE.search(ops)
    if not m:
        return None
    mnem = mnemonic.lower().split('.')[0]
    if mnem[-2:] in ARM32_COND_TO_C and mnem[:-2] in _LITERAL_LOAD_SIZES | {'vldr': 0}:
        mnem = mnem[:-2]                    # sufijo de condición (bloque IT)
    if mnem == 'vldr':
        size = 8 if ops.startswith('d') else 4
    elif mnem in _LITERAL_LOAD_SIZES:
        size = _LITERAL_LOAD_SIZES[mnem]
    else:
        return None
    base = ((address + 4) & ~3) if thumb else address + 8
    return base + int(m.group(1), 0), size
