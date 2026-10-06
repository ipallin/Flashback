"""
Mapeo de registros ARM32 a expresiones C.

r0-r12: registros de propósito general (32-bit).
r13 = sp (stack pointer).
r14 = lr (link register).
r15 = pc (program counter).
ip  = r12 (intra-procedure-call scratch).
fp  = r11 (frame pointer, por convención).
"""

from __future__ import annotations

from flashback.arch.base import RegisterMap

_REGS_32 = frozenset({
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'sp', 'lr', 'pc', 'ip', 'fp', 'sl',
})

# Alias → nombre canónico
_ALIASES = {
    'sp': 'r13', 'lr': 'r14', 'pc': 'r15',
    'ip': 'r12', 'fp': 'r11', 'sl': 'r10', 'sb': 'r9',
}


class Arm32RegisterMap(RegisterMap):
    def to_c(self, reg: str) -> str | None:
        o = reg.strip()
        o = _ALIASES.get(o, o)
        if o in _REGS_32:
            return o
        if o.startswith('0x'):
            return f'((uint32_t){o}U)'
        if o.lstrip('-').isdigit():
            v = int(o)
            return f'((int32_t){v})' if v < 0 else f'((uint32_t){v}U)'
        return None

    @staticmethod
    def all_32bit() -> list[str]:
        return [f'r{i}' for i in range(16)]
