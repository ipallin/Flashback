"""
Clasificación semántica de instrucciones ARM64 (AArch64).
Usado por el Enricher para determinar el tipo funcional de cada bloque.
"""

from __future__ import annotations

# Instrucciones de transferencia de control que terminan un bloque
BRANCH_MNEMONICS = frozenset({
    # Ramas incondicionales directas e indirectas
    'b', 'br',
    # Llamadas directas e indirectas
    'bl', 'blr', 'blraa', 'blrab', 'blraaz', 'blrabz',
    # Retornos
    'ret', 'retaa', 'retab',
    # Ramas condicionales
    'b.eq', 'b.ne', 'b.cs', 'b.cc', 'b.mi', 'b.pl', 'b.vs', 'b.vc',
    'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le', 'b.al',
    'b.hs', 'b.lo',  # aliases de b.cs / b.cc
    # Compare-and-branch
    'cbz', 'cbnz',
    # Test-and-branch
    'tbz', 'tbnz',
    # Syscall y halt
    'svc', 'hlt', 'brk', 'udf',
})

CALL_MNEMONICS = frozenset({'bl', 'blr', 'blraa', 'blrab', 'blraaz', 'blrabz'})
RET_MNEMONICS  = frozenset({'ret', 'retaa', 'retab'})

COND_BRANCH_MNEMONICS = frozenset({
    'b.eq', 'b.ne', 'b.cs', 'b.cc', 'b.mi', 'b.pl', 'b.vs', 'b.vc',
    'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le', 'b.al',
    'b.hs', 'b.lo',
    'cbz', 'cbnz',
    'tbz', 'tbnz',
})


def is_prologue_block(mnemonics: list[str], operands: list[str]) -> bool:
    """
    Heurística: bloque que guarda x29 (fp) y x30 (lr) en el stack.
    Patrón típico: stp x29, x30, [sp, #-N]!  +  mov x29, sp
    """
    for i, (m, ops) in enumerate(zip(mnemonics, operands)):
        if m == 'stp' and 'x29' in ops and 'x30' in ops and 'sp' in ops:
            # Buscar 'mov x29, sp' o 'add x29, sp, #0' en las instrucciones siguientes
            for j in range(i + 1, min(i + 4, len(mnemonics))):
                if mnemonics[j] in ('mov', 'add') and 'x29' in operands[j] and 'sp' in operands[j]:
                    return True
    return False


def is_epilogue_block(mnemonics: list[str]) -> bool:
    """Heurística: bloque que termina con ret tras restaurar registros."""
    return bool(mnemonics) and mnemonics[-1] in ('ret', 'retaa', 'retab')


def get_condition_string(mnemonic: str) -> str | None:
    """Devuelve la condición legible de un salto condicional ARM64."""
    conditions = {
        'b.eq': 'Z == 1',   'b.ne': 'Z == 0',
        'b.cs': 'C == 1',   'b.cc': 'C == 0',
        'b.hs': 'C == 1',   'b.lo': 'C == 0',
        'b.mi': 'N == 1',   'b.pl': 'N == 0',
        'b.vs': 'V == 1',   'b.vc': 'V == 0',
        'b.hi': 'C == 1 && Z == 0',
        'b.ls': 'C == 0 || Z == 1',
        'b.ge': 'N == V',   'b.lt': 'N != V',
        'b.gt': 'Z == 0 && N == V',
        'b.le': 'Z == 1 || N != V',
        'b.al': '1',
    }
    return conditions.get(mnemonic)
