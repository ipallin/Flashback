"""
Módulo ARM64 (AArch64) para Flashback.

Expone el Disassembler, Enricher y Translator para binarios ELF AArch64.
Uso:
    from flashback.arch.arm64 import Arm64Disassembler, Arm64Enricher, Arm64Translator
"""

from flashback.arch.arm64.disassembler import Arm64Disassembler, DisassemblerError
from flashback.arch.arm64.enricher import Arm64Enricher
from flashback.arch.arm64.translator import Arm64Translator
from flashback.arch.arm64.register_map import Arm64RegisterMap
from flashback.arch.arm64 import syscall_table

__all__ = [
    'Arm64Disassembler',
    'Arm64Enricher',
    'Arm64Translator',
    'Arm64RegisterMap',
    'DisassemblerError',
    'syscall_table',
]
