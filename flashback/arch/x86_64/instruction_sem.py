"""
Clasificación semántica de instrucciones x86-64.
Usado por el Enricher para determinar el tipo funcional de cada bloque.
"""

from __future__ import annotations

# Prólogo típico de función (push rbp; mov rbp, rsp)
PROLOGUE_SEQUENCE = [('push', 'rbp'), ('mov', 'rbp, rsp')]

# Epílogo típico (leave / pop rbp seguido de ret, o solo ret)
EPILOGUE_MNEMONICS = frozenset({'leave', 'ret', 'retn'})

# Instrucciones de transferencia de control que terminan un bloque
BRANCH_MNEMONICS = frozenset({
    'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
    'jb', 'jbe', 'ja', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
    'jrcxz', 'jecxz', 'loop', 'loope', 'loopne',
    'ret', 'retn', 'retf', 'syscall', 'int', 'hlt', 'call',
})


def is_prologue_block(mnemonics: list[str], operands: list[str]) -> bool:
    """Heurística: bloque que contiene push rbp + mov rbp, rsp."""
    pairs = list(zip(mnemonics, operands))
    for i in range(len(pairs) - 1):
        if (pairs[i] == ('push', 'rbp')
                and pairs[i + 1][0] == 'mov'
                and 'rbp' in pairs[i + 1][1]
                and 'rsp' in pairs[i + 1][1]):
            return True
    return False


def is_epilogue_block(mnemonics: list[str]) -> bool:
    """Heurística: bloque que termina con leave/ret."""
    return bool(mnemonics) and mnemonics[-1] in ('ret', 'retn', 'retf')


def get_condition_string(mnemonic: str) -> str | None:
    """Devuelve la condición legible de un salto condicional."""
    conditions = {
        'je': 'ZF == 1', 'jz': 'ZF == 1',
        'jne': 'ZF == 0', 'jnz': 'ZF == 0',
        'jl': 'SF != OF', 'jnge': 'SF != OF',
        'jge': 'SF == OF', 'jnl': 'SF == OF',
        'jg': 'ZF == 0 && SF == OF', 'jnle': 'ZF == 0 && SF == OF',
        'jle': 'ZF == 1 || SF != OF', 'jng': 'ZF == 1 || SF != OF',
        'jb': 'CF == 1', 'jnae': 'CF == 1', 'jc': 'CF == 1',
        'jae': 'CF == 0', 'jnb': 'CF == 0', 'jnc': 'CF == 0',
        'ja': 'CF == 0 && ZF == 0', 'jnbe': 'CF == 0 && ZF == 0',
        'jbe': 'CF == 1 || ZF == 1', 'jna': 'CF == 1 || ZF == 1',
        'js': 'SF == 1', 'jns': 'SF == 0',
        'jo': 'OF == 1', 'jno': 'OF == 0',
    }
    return conditions.get(mnemonic)
