"""
Módulo ARM32 (ARM 32-bit / ARMv7) para Flashback.
"""

from flashback.arch.arm32.disassembler import Arm32Disassembler, DisassemblerError
from flashback.arch.arm32.enricher import Arm32Enricher
from flashback.arch.arm32.translator import Arm32Translator
from flashback.arch.arm32.register_map import Arm32RegisterMap
from flashback.arch.arm32 import syscall_table

__all__ = [
    'Arm32Disassembler',
    'Arm32Enricher',
    'Arm32Translator',
    'Arm32RegisterMap',
    'DisassemblerError',
    'syscall_table',
]
