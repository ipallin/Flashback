"""
Mapeo de registros x86 (32-bit) a expresiones C.

Registros principales 32-bit: eax, ebx, ecx, edx, esi, edi, esp, ebp.
Sub-registros 16-bit: ax, bx, cx, dx, si, di, sp, bp.
Sub-registros 8-bit: al, ah, bl, bh, cl, ch, dl, dh.
No hay zero-extension a 64 bits (a diferencia de x86-64).
"""

from __future__ import annotations

from flashback.arch.base import RegisterMap

_REGS_32 = frozenset({
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eflags', 'eip',
})

_REGS_16 = {
    'ax': 'eax', 'bx': 'ebx', 'cx': 'ecx', 'dx': 'edx',
    'si': 'esi', 'di': 'edi', 'sp': 'esp', 'bp': 'ebp',
}

_REGS_8L = {
    'al': 'eax', 'bl': 'ebx', 'cl': 'ecx', 'dl': 'edx',
}

_REGS_8H = {
    'ah': 'eax', 'bh': 'ebx', 'ch': 'ecx', 'dh': 'edx',
}


class X86RegisterMap(RegisterMap):
    def to_c(self, reg: str) -> str | None:
        o = reg.strip()
        if o in _REGS_32:
            return o
        if o in _REGS_16:
            return f'(uint16_t){_REGS_16[o]}'
        if o in _REGS_8L:
            return f'(uint8_t){_REGS_8L[o]}'
        if o in _REGS_8H:
            return f'(uint8_t)({_REGS_8H[o]} >> 8)'
        if o.startswith('0x'):
            return f'((uint32_t){o}U)'
        if o.lstrip('-').isdigit():
            v = int(o)
            return f'((int32_t){v})' if v < 0 else f'((uint32_t){v}U)'
        return None

    @staticmethod
    def all_32bit() -> list[str]:
        return sorted(_REGS_32 - {'eflags', 'eip'})
