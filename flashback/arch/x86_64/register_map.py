"""
Mapeo de registros x86-64 a expresiones C (uint64_t con casts apropiados).
"""

from __future__ import annotations

from flashback.arch.base import RegisterMap

_REGS_64 = frozenset({
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rip', 'rflags',
})

_REGS_32 = {
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
    'r8d': 'r8',  'r9d': 'r9',  'r10d': 'r10', 'r11d': 'r11',
    'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
}

_REGS_16 = {
    'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
    'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp',
}

_REGS_8L = {
    'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
    'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp',
}

_REGS_8H = {'ah': 'rax', 'bh': 'rbx', 'ch': 'rcx', 'dh': 'rdx'}


class X86_64RegisterMap(RegisterMap):
    def to_c(self, reg: str) -> str | None:
        o = reg.strip()
        if o in _REGS_64:
            return o
        if o in _REGS_32:
            return f'(uint32_t){_REGS_32[o]}'
        if o in _REGS_16:
            return f'(uint16_t){_REGS_16[o]}'
        if o in _REGS_8L:
            return f'(uint8_t){_REGS_8L[o]}'
        if o in _REGS_8H:
            return f'(uint8_t)({_REGS_8H[o]} >> 8)'
        if o.startswith('0x'):
            return f'((uint64_t){o}ULL)'
        if o.lstrip('-').isdigit():
            v = int(o)
            return f'((int64_t){v}LL)' if v < 0 else f'((uint64_t){v}ULL)'
        return None

    @staticmethod
    def all_64bit() -> list[str]:
        return sorted(_REGS_64 - {'rip', 'rflags'})
