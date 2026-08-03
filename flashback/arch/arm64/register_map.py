"""
Mapeo de registros ARM64 (AArch64) a expresiones C.
"""

from __future__ import annotations

from flashback.arch.base import RegisterMap

_REGS_64 = frozenset({
    'x0',  'x1',  'x2',  'x3',  'x4',  'x5',  'x6',  'x7',
    'x8',  'x9',  'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30',
    'sp', 'pc',
})

_REGS_32 = {
    'w0':  'x0',  'w1':  'x1',  'w2':  'x2',  'w3':  'x3',
    'w4':  'x4',  'w5':  'x5',  'w6':  'x6',  'w7':  'x7',
    'w8':  'x8',  'w9':  'x9',  'w10': 'x10', 'w11': 'x11',
    'w12': 'x12', 'w13': 'x13', 'w14': 'x14', 'w15': 'x15',
    'w16': 'x16', 'w17': 'x17', 'w18': 'x18', 'w19': 'x19',
    'w20': 'x20', 'w21': 'x21', 'w22': 'x22', 'w23': 'x23',
    'w24': 'x24', 'w25': 'x25', 'w26': 'x26', 'w27': 'x27',
    'w28': 'x28', 'w29': 'x29', 'w30': 'x30',
    'wsp': 'sp',
}


class Arm64RegisterMap(RegisterMap):
    def to_c(self, reg: str) -> str | None:
        o = reg.strip().lower()
        if o in ('xzr', 'wzr'):
            return '((uint64_t)0)'
        if o in _REGS_64:
            return o
        if o in _REGS_32:
            return f'(uint32_t){_REGS_32[o]}'
        if o.startswith('#'):
            imm = o[1:]
            try:
                v = int(imm, 0)
                return f'((uint64_t){v}ULL)' if v >= 0 else f'((int64_t){v}LL)'
            except ValueError:
                pass
        if o.startswith('0x') or o.startswith('-0x'):
            try:
                v = int(o, 16)
                return f'((uint64_t){v}ULL)' if v >= 0 else f'((int64_t){v}LL)'
            except ValueError:
                pass
        if o.lstrip('-').isdigit():
            v = int(o)
            return f'((int64_t){v}LL)' if v < 0 else f'((uint64_t){v}ULL)'
        return None

    @staticmethod
    def all_64bit() -> list[str]:
        return sorted(_REGS_64 - {'pc'})
