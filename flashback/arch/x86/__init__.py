"""
Módulo x86 (32-bit / i386) para Flashback.
"""

from flashback.arch.x86.disassembler import X86Disassembler, DisassemblerError
from flashback.arch.x86.enricher import X86Enricher
from flashback.arch.x86.translator import X86Translator
from flashback.arch.x86.register_map import X86RegisterMap
from flashback.arch.x86 import syscall_table

__all__ = [
    'X86Disassembler',
    'X86Enricher',
    'X86Translator',
    'X86RegisterMap',
    'DisassemblerError',
    'syscall_table',
]
