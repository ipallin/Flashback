"""
Clasificación semántica de instrucciones x86 (32-bit).
"""

from __future__ import annotations

BRANCH_MNEMONICS = frozenset({
    'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
    'jb', 'jbe', 'ja', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
    'jcxz', 'jecxz', 'loop', 'loope', 'loopne',
    'ret', 'retn', 'retf', 'int', 'hlt', 'call',
})

COND_BRANCH_MNEMONICS = frozenset({
    'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
    'jb', 'jbe', 'ja', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
    'jcxz', 'jecxz', 'loop', 'loope', 'loopne',
})


def is_prologue_block(mnemonics: list[str], operands: list[str]) -> bool:
    """Heurística: push ebp + mov ebp, esp."""
    pairs = list(zip(mnemonics, operands))
    for i in range(len(pairs) - 1):
        if (pairs[i] == ('push', 'ebp')
                and pairs[i + 1][0] == 'mov'
                and 'ebp' in pairs[i + 1][1]
                and 'esp' in pairs[i + 1][1]):
            return True
    return False


def is_epilogue_block(mnemonics: list[str]) -> bool:
    return bool(mnemonics) and mnemonics[-1] in ('ret', 'retn', 'retf')


def get_condition_string(mnemonic: str) -> str | None:
    conditions = {
        'je': 'ZF == 1', 'jz': 'ZF == 1',
        'jne': 'ZF == 0', 'jnz': 'ZF == 0',
        'jl': 'SF != OF', 'jge': 'SF == OF',
        'jg': 'ZF == 0 && SF == OF', 'jle': 'ZF == 1 || SF != OF',
        'jb': 'CF == 1', 'jae': 'CF == 0',
        'ja': 'CF == 0 && ZF == 0', 'jbe': 'CF == 1 || ZF == 1',
        'js': 'SF == 1', 'jns': 'SF == 0',
        'jo': 'OF == 1', 'jno': 'OF == 0',
    }
    return conditions.get(mnemonic)
