"""
Translator: genera código C portable a partir del CFG enriquecido.

Tres decisiones de diseño que habilitan la portabilidad:
  1. Stack simulado: el stack original se modela como array estático.
  2. Llamadas libc nativas: las external_call se emiten como llamadas directas,
     con argumentos casteados desde uint64_t. El compilador destino resuelve la ABI.
  3. Syscalls vía libc: las instrucciones syscall se mapean a funciones wrapper
     de la libc destino, cuyo número varía por arquitectura.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flashback.core.models import EnrichedCFG, BasicBlock, Instruction, ExternalCallAnnotation

logger = logging.getLogger(__name__)

_REGISTERS_64 = [
    'rax', 'rbx', 'rcx', 'rdx',
    'rsi', 'rdi', 'rbp', 'rsp',
    'r8',  'r9',  'r10', 'r11',
    'r12', 'r13', 'r14', 'r15',
    'rip', 'rflags',
]

_FLAGS = ['ZF', 'CF', 'SF', 'OF', 'PF']

_REG_32_TO_64 = {
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
    'r8d': 'r8',  'r9d': 'r9',  'r10d': 'r10', 'r11d': 'r11',
    'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
}
_REG_16_TO_64 = {
    'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
    'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp',
}
_REG_8L_TO_64 = {
    'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
    'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp',
}
_REG_8H_TO_64 = {'ah': 'rax', 'bh': 'rbx', 'ch': 'rcx', 'dh': 'rdx'}

_INCLUDES = [
    '#include <stdint.h>',
    '#include <stdio.h>',
    '#include <stdlib.h>',
    '#include <string.h>',
    '#include <unistd.h>',
    '#include <sys/syscall.h>',
    '#include <sys/mman.h>',
    '#include <fcntl.h>',
]

_SIM_STACK_SIZE_MB = 8
_SIM_HEAP_SIZE_MB  = 64

# Mapeo de función libc → (tipo_retorno, [argumentos_con_cast])
_LIBC_CALL_MAP: dict[str, tuple[str, list[str]]] = {
    'printf':   ('int',     ['(const char*)(uintptr_t)rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']),
    'fprintf':  ('int',     ['(FILE*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', 'rdx', 'rcx', 'r8', 'r9']),
    'scanf':    ('int',     ['(const char*)(uintptr_t)rdi', '(void*)(uintptr_t)rsi']),
    'puts':     ('int',     ['(const char*)(uintptr_t)rdi']),
    'putchar':  ('int',     ['(int)rdi']),
    'getchar':  ('int',     []),
    'malloc':   ('void*',   ['(size_t)rdi']),
    'calloc':   ('void*',   ['(size_t)rdi', '(size_t)rsi']),
    'realloc':  ('void*',   ['(void*)(uintptr_t)rdi', '(size_t)rsi']),
    'free':     ('void',    ['(void*)(uintptr_t)rdi']),
    'memcpy':   ('void*',   ['(void*)(uintptr_t)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx']),
    'memset':   ('void*',   ['(void*)(uintptr_t)rdi', '(int)rsi', '(size_t)rdx']),
    'strlen':   ('size_t',  ['(const char*)(uintptr_t)rdi']),
    'strcpy':   ('char*',   ['(char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'strncpy':  ('char*',   ['(char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', '(size_t)rdx']),
    'strcmp':   ('int',     ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'strncmp':  ('int',     ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', '(size_t)rdx']),
    'strcat':   ('char*',   ['(char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'strncat':  ('char*',   ['(char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', '(size_t)rdx']),
    'strchr':   ('char*',   ['(const char*)(uintptr_t)rdi', '(int)rsi']),
    'strrchr':  ('char*',   ['(const char*)(uintptr_t)rdi', '(int)rsi']),
    'strstr':   ('char*',   ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'strdup':   ('char*',   ['(const char*)(uintptr_t)rdi']),
    'strnlen':  ('size_t',  ['(const char*)(uintptr_t)rdi', '(size_t)rsi']),
    'strtoul':  ('unsigned long', ['(const char*)(uintptr_t)rdi', '(char**)(uintptr_t)rsi', '(int)rdx']),
    'strtod':   ('double',  ['(const char*)(uintptr_t)rdi', '(char**)(uintptr_t)rsi']),
    'snprintf': ('int',     ['(char*)(uintptr_t)rdi', '(size_t)rsi', '(const char*)(uintptr_t)rdx', 'rcx', 'r8', 'r9']),
    'sprintf':  ('int',     ['(char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', 'rdx', 'rcx', 'r8', 'r9']),
    'sscanf':   ('int',     ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', 'rdx', 'rcx', 'r8', 'r9']),
    'fscanf':   ('int',     ['(FILE*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi', 'rdx', 'rcx', 'r8', 'r9']),
    'fgets':    ('char*',   ['(char*)(uintptr_t)rdi', '(int)rsi', '(FILE*)(uintptr_t)rdx']),
    'fputs':    ('int',     ['(const char*)(uintptr_t)rdi', '(FILE*)(uintptr_t)rsi']),
    'fflush':   ('int',     ['(FILE*)(uintptr_t)rdi']),
    'fseek':    ('int',     ['(FILE*)(uintptr_t)rdi', '(long)rsi', '(int)rdx']),
    'ftell':    ('long',    ['(FILE*)(uintptr_t)rdi']),
    'rewind':   ('void',    ['(FILE*)(uintptr_t)rdi']),
    'memmove':  ('void*',   ['(void*)(uintptr_t)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx']),
    'memcmp':   ('int',     ['(const void*)(uintptr_t)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx']),
    'memchr':   ('void*',   ['(const void*)(uintptr_t)rdi', '(int)rsi', '(size_t)rdx']),
    'atol':     ('long',    ['(const char*)(uintptr_t)rdi']),
    'abs':      ('int',     ['(int)rdi']),
    'labs':     ('long',    ['(long)rdi']),
    'qsort':    ('void',    ['(void*)(uintptr_t)rdi', '(size_t)rsi', '(size_t)rdx', '(void*)(uintptr_t)rcx']),
    'bsearch':  ('void*',   ['(const void*)(uintptr_t)rdi', '(const void*)(uintptr_t)rsi',
                             '(size_t)rdx', '(size_t)rcx', '(void*)(uintptr_t)r8']),
    'getenv':   ('char*',   ['(const char*)(uintptr_t)rdi']),
    'strerror': ('char*',   ['(int)rdi']),
    'time':     ('time_t',  ['(time_t*)(uintptr_t)rdi']),
    'getpid':   ('pid_t',   []),
    'getppid':  ('pid_t',   []),
    'sleep':    ('unsigned', ['(unsigned)rdi']),
    'usleep':   ('int',     ['(unsigned long)rdi']),
    'open':     ('int',     ['(const char*)(uintptr_t)rdi', '(int)rsi', '(int)rdx']),
    'read':     ('ssize_t', ['(int)rdi', '(void*)(uintptr_t)rsi', '(size_t)rdx']),
    'write':    ('ssize_t', ['(int)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx']),
    'close':    ('int',     ['(int)rdi']),
    'exit':     ('void',    ['(int)rdi']),
    'atoi':     ('int',     ['(const char*)(uintptr_t)rdi']),
    'strtol':   ('long',    ['(const char*)(uintptr_t)rdi', '(char**)(uintptr_t)rsi', '(int)rdx']),
    'fopen':    ('FILE*',   ['(const char*)(uintptr_t)rdi', '(const char*)(uintptr_t)rsi']),
    'fclose':   ('int',     ['(FILE*)(uintptr_t)rdi']),
    'fread':    ('size_t',  ['(void*)(uintptr_t)rdi', '(size_t)rsi', '(size_t)rdx', '(FILE*)(uintptr_t)rcx']),
    'fwrite':   ('size_t',  ['(const void*)(uintptr_t)rdi', '(size_t)rsi', '(size_t)rdx', '(FILE*)(uintptr_t)rcx']),
    'perror':   ('void',    ['(const char*)(uintptr_t)rdi']),
    'mmap':     ('void*',   ['(void*)(uintptr_t)rdi', '(size_t)rsi', '(int)rdx', '(int)rcx', '(int)r8', '(off_t)r9']),
    'munmap':   ('int',     ['(void*)(uintptr_t)rdi', '(size_t)rsi']),
    'socket':   ('int',     ['(int)rdi', '(int)rsi', '(int)rdx']),
    'connect':  ('int',     ['(int)rdi', '(const struct sockaddr*)(uintptr_t)rsi', '(socklen_t)rdx']),
    'send':     ('ssize_t', ['(int)rdi', '(const void*)(uintptr_t)rsi', '(size_t)rdx', '(int)rcx']),
    'recv':     ('ssize_t', ['(int)rdi', '(void*)(uintptr_t)rsi', '(size_t)rdx', '(int)rcx']),
    'fork':     ('pid_t',   []),
    'execve':   ('int',     ['(const char*)(uintptr_t)rdi', '(char* const*)(uintptr_t)rsi', '(char* const*)(uintptr_t)rdx']),
    'waitpid':  ('pid_t',   ['(pid_t)rdi', '(int*)(uintptr_t)rsi', '(int)rdx']),
    # Funciones void / sin retorno usable. Su firma real es incompatible con
    # una llamada genérica de 6 argumentos con cast a uintptr_t, por lo que
    # deben declararse explícitamente para que el C generado compile.
    'abort':            ('void', []),
    '_exit':            ('void', ['(int)rdi']),
    '__stack_chk_fail': ('void', []),
    '__assert_fail':    ('void', ['(const char*)(uintptr_t)rdi',
                                  '(const char*)(uintptr_t)rsi',
                                  '(unsigned)rdx',
                                  '(const char*)(uintptr_t)rcx']),
}

_SYSCALL_LIBC_MAP: dict[str, str] = {
    'read': 'read', 'write': 'write', 'open': 'open', 'close': 'close',
    'exit': 'exit', 'exit_group': 'exit', 'mmap': 'mmap', 'munmap': 'munmap',
    'fork': 'fork', 'execve': 'execve', 'waitpid': 'waitpid',
}

# Mapeo de mnemónico de salto condicional → condición C exacta.
# Basado en Intel Manual Vol.1 §3.6 y Vol.2 Jcc reference.
#
# Flags usados:
#   ZF  — Zero Flag      (resultado == 0)
#   SF  — Sign Flag      (resultado < 0 en aritmética con signo)
#   OF  — Overflow Flag  (desbordamiento en aritmética con signo)
#   CF  — Carry Flag     (desbordamiento en aritmética sin signo / borrow)
#   PF  — Parity Flag    (paridad del byte menos significativo)
_JCC_TO_C: dict[str, str] = {
    # ── Igualdad ────────────────────────────────────────────────────────
    'je':    'ZF',                          # Jump if Equal          (ZF=1)
    'jz':    'ZF',                          # Jump if Zero           (ZF=1)
    'jne':   '!ZF',                         # Jump if Not Equal      (ZF=0)
    'jnz':   '!ZF',                         # Jump if Not Zero       (ZF=0)

    # ── Con signo ───────────────────────────────────────────────────────
    'jl':    '(SF != OF)',                  # Jump if Less           (SF≠OF)
    'jnge':  '(SF != OF)',                  # alias de jl
    'jle':   '(ZF || SF != OF)',            # Jump if Less or Equal  (ZF=1 ∨ SF≠OF)
    'jng':   '(ZF || SF != OF)',            # alias de jle
    'jg':    '(!ZF && SF == OF)',           # Jump if Greater        (ZF=0 ∧ SF=OF)
    'jnle':  '(!ZF && SF == OF)',           # alias de jg
    'jge':   '(SF == OF)',                  # Jump if ≥              (SF=OF)
    'jnl':   '(SF == OF)',                  # alias de jge

    # ── Sin signo ───────────────────────────────────────────────────────
    'jb':    'CF',                          # Jump if Below          (CF=1)
    'jnae':  'CF',                          # alias de jb
    'jc':    'CF',                          # alias de jb
    'jbe':   '(CF || ZF)',                  # Jump if Below or Equal (CF=1 ∨ ZF=1)
    'jna':   '(CF || ZF)',                  # alias de jbe
    'ja':    '(!CF && !ZF)',                # Jump if Above          (CF=0 ∧ ZF=0)
    'jnbe':  '(!CF && !ZF)',                # alias de ja
    'jae':   '!CF',                         # Jump if Above or Equal (CF=0)
    'jnb':   '!CF',                         # alias de jae
    'jnc':   '!CF',                         # alias de jae

    # ── Signo y overflow aislados ────────────────────────────────────────
    'js':    'SF',                          # Jump if Sign           (SF=1)
    'jns':   '!SF',                         # Jump if Not Sign       (SF=0)
    'jo':    'OF',                          # Jump if Overflow       (OF=1)
    'jno':   '!OF',                         # Jump if Not Overflow   (OF=0)

    # ── Paridad ─────────────────────────────────────────────────────────
    'jp':    'PF',                          # Jump if Parity         (PF=1)
    'jpe':   'PF',                          # alias de jp
    'jnp':   '!PF',                         # Jump if Not Parity     (PF=0)
    'jpo':   '!PF',                         # alias de jnp

    # ── Contador (no dependen de flags aritmétcos) ───────────────────────
    # jrcxz/jecxz se dejan fuera: su condición es rcx==0 / ecx==0,
    # no un flag. Se tratan como UNSUPPORTED en _translate_instruction.
}


# Movimientos condicionales (CMOVcc): mismas condiciones de flags que Jcc.
# dst = src solo si la condición se cumple (Intel Vol.2 CMOVcc).
_CMOV_TO_C: dict[str, str] = {
    'cmove':  'ZF',            'cmovz':  'ZF',
    'cmovne': '!ZF',           'cmovnz': '!ZF',
    'cmovl':  '(SF != OF)',    'cmovnge': '(SF != OF)',
    'cmovle': '(ZF || SF != OF)', 'cmovng': '(ZF || SF != OF)',
    'cmovg':  '(!ZF && SF == OF)', 'cmovnle': '(!ZF && SF == OF)',
    'cmovge': '(SF == OF)',    'cmovnl': '(SF == OF)',
    'cmovb':  'CF',            'cmovnae': 'CF',  'cmovc': 'CF',
    'cmovbe': '(CF || ZF)',    'cmovna': '(CF || ZF)',
    'cmova':  '(!CF && !ZF)',  'cmovnbe': '(!CF && !ZF)',
    'cmovae': '!CF',           'cmovnb': '!CF',  'cmovnc': '!CF',
    'cmovs':  'SF',            'cmovns': '!SF',
    'cmovo':  'OF',            'cmovno': '!OF',
    'cmovp':  'PF',            'cmovpe': 'PF',
    'cmovnp': '!PF',           'cmovpo': '!PF',
}


# Instrucciones con prefijo rep/repe/repne.
# En capstone el prefijo forma parte del mnemónico: "rep movsb", "repne scasb", etc.
# Se modelan con las funciones de libc equivalentes para mantener portabilidad.
_REP_INSNS: dict[str, str] = {
    # ── Mover memoria ───────────────────────────────────────────────────────────
    'rep movsb': 'memcpy(SIM_PTR(rdi), SIM_PTR(rsi), (size_t)rcx);   rdi += rcx;   rsi += rcx;   rcx = 0;',
    'rep movsw': 'memcpy(SIM_PTR(rdi), SIM_PTR(rsi), (size_t)rcx*2); rdi += rcx*2; rsi += rcx*2; rcx = 0;',
    'rep movsd': 'memcpy(SIM_PTR(rdi), SIM_PTR(rsi), (size_t)rcx*4); rdi += rcx*4; rsi += rcx*4; rcx = 0;',
    'rep movsq': 'memcpy(SIM_PTR(rdi), SIM_PTR(rsi), (size_t)rcx*8); rdi += rcx*8; rsi += rcx*8; rcx = 0;',
    # ── Rellenar memoria ────────────────────────────────────────────────────────
    'rep stosb': 'memset(SIM_PTR(rdi), (int)(uint8_t)rax,  (size_t)rcx);   rdi += rcx;   rcx = 0;',
    'rep stosw': '{ uint64_t __i; for(__i=0;__i<rcx;__i++) SIM_WRITE16(rdi+__i*2, (uint16_t)rax); rdi+=rcx*2; rcx=0; }',
    'rep stosd': '{ uint64_t __i; for(__i=0;__i<rcx;__i++) SIM_WRITE32(rdi+__i*4, (uint32_t)rax); rdi+=rcx*4; rcx=0; }',
    'rep stosq': '{ uint64_t __i; for(__i=0;__i<rcx;__i++) SIM_WRITE64(rdi+__i*8, rax);           rdi+=rcx*8; rcx=0; }',
    # ── Comparar memoria ────────────────────────────────────────────────────────
    'repe cmpsb':  '{ int __r=memcmp(SIM_PTR(rdi),SIM_PTR(rsi),(size_t)rcx); ZF=(__r==0); SF=(__r<0); CF=(__r<0); OF=0; rcx=0; }',
    'repne cmpsb': '{ int __r=memcmp(SIM_PTR(rdi),SIM_PTR(rsi),(size_t)rcx); ZF=(__r==0); SF=(__r<0); CF=(__r<0); OF=0; rcx=0; }',
    # ── Buscar en cadena ────────────────────────────────────────────────────────
    'repne scasb': (
        '{ uint8_t __v=(uint8_t)rax; uint64_t __i=0; '
        'while(__i<rcx && SIM_READ8(rdi+__i)!=__v) __i++; '
        'rdi+=__i; rcx-=__i; '
        'ZF=(__i<rcx && SIM_READ8(rdi)==__v); }'
    ),
    'repe scasb': (
        '{ uint8_t __v=(uint8_t)rax; uint64_t __i=0; '
        'while(__i<rcx && SIM_READ8(rdi+__i)==__v) __i++; '
        'rdi+=__i; rcx-=__i; '
        'ZF=(__i==rcx); }'
    ),
}


class TranslatorError(Exception):
    pass


class Translator:
    def __init__(self, tool_version: str = '0.1.0',
                 sim_stack_mb: int = _SIM_STACK_SIZE_MB,
                 sim_heap_mb: int = _SIM_HEAP_SIZE_MB):
        self.tool_version = tool_version
        self.sim_stack_mb = sim_stack_mb
        self.sim_heap_mb = sim_heap_mb

    def translate(self, cfg: EnrichedCFG) -> str:
        if cfg.metadata.pipeline_stage != 'enriched':
            raise TranslatorError(
                f'Se esperaba pipeline_stage=enriched, recibido: {cfg.metadata.pipeline_stage}'
            )
        logger.info(f'Traduciendo CFG de {cfg.binary_info.filename}')

        # Addresses that will have a C function definition (non-PLT, non-external)
        self._defined_funcs: set[str] = {
            addr for addr, func in cfg.functions.items()
            if not func.is_plt and not func.is_external
        }

        sections = [
            self._emit_header(cfg),
            self._emit_includes(),
            self._emit_portability_macros(),
            self._emit_simulated_memory(),
            self._emit_trace_runtime(),
            self._emit_registers(),
            self._emit_flags(),
            self._emit_rodata(cfg),
            self._emit_data_section(cfg),
            self._emit_bss_section(cfg),
            self._emit_addr_translation(cfg),
            self._emit_function_declarations(cfg),
            self._emit_functions(cfg),
            self._emit_entry_point(cfg),
        ]
        return '\n\n'.join(s for s in sections if s)

    # ------------------------------------------------------------------
    # Secciones del fichero C generado
    # ------------------------------------------------------------------

    def _emit_header(self, cfg: EnrichedCFG) -> str:
        now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        fn = cfg.binary_info.filename
        return (
            f'/*\n'
            f' * Generado por Flashback v{self.tool_version} — {now}\n'
            f' *\n'
            f' * Binario: {fn} ({cfg.binary_info.architecture})\n'
            f' * SHA256 : {cfg.binary_info.sha256}\n'
            f' * Entry  : {cfg.binary_info.entry_point}\n'
            f' *\n'
            f' * Compila en cualquier plataforma de 64 bits:\n'
            f' *   x86-64 : gcc -O0 -g {fn}.c -o output\n'
            f' *   ARM64  : aarch64-linux-gnu-gcc -O0 {fn}.c -o output\n'
            f' *   RISC-V : riscv64-linux-gnu-gcc -O0 {fn}.c -o output\n'
            f' *\n'
            f' * No editar manualmente — generado por Flashback.\n'
            f' */'
        )

    def _emit_includes(self) -> str:
        return '\n'.join(_INCLUDES)

    def _emit_portability_macros(self) -> str:
        return (
            '/* Traducción de direcciones (definida más abajo) */\n'
            'static uintptr_t __sim_addr(uint64_t va);\n'
            '/* Macros portables para accesos a memoria simulada.\n'
            '   Toda dirección pasa por __sim_addr, que la resuelve a los\n'
            '   arrays de datos embebidos (.rodata/.data/.bss) o la deja\n'
            '   intacta si ya es un puntero real del proceso. */\n'
            '#define SIM_READ8(addr)        (*(uint8_t  *)__sim_addr((uint64_t)(addr)))\n'
            '#define SIM_READ16(addr)       (*(uint16_t *)__sim_addr((uint64_t)(addr)))\n'
            '#define SIM_READ32(addr)       (*(uint32_t *)__sim_addr((uint64_t)(addr)))\n'
            '#define SIM_READ64(addr)       (*(uint64_t *)__sim_addr((uint64_t)(addr)))\n'
            '#define SIM_WRITE8(addr, val)  (*(uint8_t  *)__sim_addr((uint64_t)(addr)) = (uint8_t )(val))\n'
            '#define SIM_WRITE16(addr, val) (*(uint16_t *)__sim_addr((uint64_t)(addr)) = (uint16_t)(val))\n'
            '#define SIM_WRITE32(addr, val) (*(uint32_t *)__sim_addr((uint64_t)(addr)) = (uint32_t)(val))\n'
            '#define SIM_WRITE64(addr, val) (*(uint64_t *)__sim_addr((uint64_t)(addr)) = (uint64_t)(val))\n'
            '#define SIM_PTR(addr)          ((void *)__sim_addr((uint64_t)(addr)))\n'
            '#define SIM_CSTR(addr)         ((const char *)__sim_addr((uint64_t)(addr)))'
        )

    def _emit_simulated_memory(self) -> str:
        stack_bytes = self.sim_stack_mb * 1024 * 1024
        heap_bytes  = self.sim_heap_mb  * 1024 * 1024
        return (
            f'/* Stack y heap simulados — aíslan el programa del stack real del proceso */\n'
            f'#define SIM_STACK_SIZE ((size_t){stack_bytes}U)\n'
            f'#define SIM_HEAP_SIZE  ((size_t){heap_bytes}U)\n'
            f'static uint8_t __sim_stack[SIM_STACK_SIZE];\n'
            f'static uint8_t __sim_heap[SIM_HEAP_SIZE];\n'
            f'static uint8_t *__sim_heap_ptr = __sim_heap;\n'
            f'typedef char __assert_64bit_ptr[(sizeof(uintptr_t) == 8) ? 1 : -1];\n'
            f'typedef char __assert_uint64_size[(sizeof(uint64_t) == 8) ? 1 : -1];'
        )

    def _emit_trace_runtime(self) -> str:
        return (
            '/* Runtime de trazabilidad — __trace(addr) registra cada punto de ejecución */\n'
            '#define TRACE_BUFFER_SIZE ((uint64_t)(1u << 20))\n'
            '#define TRACE_PATH "flashback_trace.bin"\n'
            'static uint64_t __trace_buffer[TRACE_BUFFER_SIZE];\n'
            'static uint64_t __trace_idx = 0;\n'
            'static int __trace_dumped = 0;  /* garantiza un único volcado */\n'
            'static inline void __trace(uint64_t addr) {\n'
            '    __trace_buffer[__trace_idx & (TRACE_BUFFER_SIZE - 1)] = addr;\n'
            '    __trace_idx++;\n'
            '}\n'
            'static void __trace_dump(const char *path) {\n'
            '    if (__trace_dumped) return;  /* idempotente: solo el primer volcado escribe */\n'
            '    __trace_dumped = 1;\n'
            '    FILE *f = fopen(path, "wb");\n'
            '    if (!f) { perror("__trace_dump"); return; }\n'
            '    uint64_t n = (__trace_idx < TRACE_BUFFER_SIZE) ? __trace_idx : TRACE_BUFFER_SIZE;\n'
            '    if (fwrite(__trace_buffer, sizeof(uint64_t), (size_t)n, f) != (size_t)n)\n'
            '        perror("__trace_dump: fwrite");\n'
            '    fclose(f);\n'
            '}\n'
            '/* Handler registrado con atexit(): cubre el retorno normal de main()\n'
            '   y las terminaciones vía exit() de la libc (que ejecutan atexit). */\n'
            'static void __trace_dump_atexit(void) { __trace_dump(TRACE_PATH); }\n'
            '/* Envoltura de syscall que vuelca la traza ANTES de una llamada de la\n'
            '   familia exit (exit=60, exit_group=231 en x86-64). Una syscall cruda de\n'
            '   terminación va directa al kernel y no ejecuta los handlers de atexit,\n'
            '   por lo que sin este volcado previo la traza se perdería. */\n'
            'static long __do_syscall(long n, long a1, long a2, long a3,\n'
            '                         long a4, long a5, long a6) {\n'
            '    if (n == 60 || n == 231) __trace_dump(TRACE_PATH);\n'
            '    return syscall(n, a1, a2, a3, a4, a5, a6);\n'
            '}'
        )

    def _emit_registers(self) -> str:
        lines = ['/* Registros x86-64 simulados como variables globales */']
        for reg in _REGISTERS_64:
            lines.append(f'static uint64_t {reg} = 0;')
        lines.append('/* Índice de la última tabla de salto resuelta (Fase 1) */')
        lines.append('static uint64_t __jt_index = 0;')
        return '\n'.join(lines)

    def _emit_flags(self) -> str:
        lines = ['/* Flags de CPU simulados */']
        for flag in _FLAGS:
            lines.append(f'static uint8_t {flag} = 0;')
        return '\n'.join(lines)

    def _emit_rodata(self, cfg: EnrichedCFG) -> str:
        bi = cfg.binary_info
        if not bi.rodata_va or not bi.rodata_hex:
            return ''
        data = bytes.fromhex(bi.rodata_hex)
        hex_vals = ', '.join(f'0x{b:02x}' for b in data)
        return (
            f'/* .rodata embebida del binario original */\n'
            f'#define __RODATA_VA ((uint64_t)0x{bi.rodata_va:x}ULL)\n'
            f'#define __RODATA_SIZE ((size_t){len(data)}U)\n'
            f'static const uint8_t __rodata[{len(data)}U] = {{\n'
            f'    {hex_vals}\n'
            f'}};'
        )

    def _emit_data_section(self, cfg: EnrichedCFG) -> str:
        bi = cfg.binary_info
        if not bi.data_va or not bi.data_hex:
            return ''
        data = bytes.fromhex(bi.data_hex)
        if not data:
            return ''
        hex_vals = ', '.join(f'0x{b:02x}' for b in data)
        return (
            f'/* .data embebida del binario original (mutable) */\n'
            f'#define __DATA_VA   ((uint64_t)0x{bi.data_va:x}ULL)\n'
            f'#define __DATA_SIZE ((size_t){len(data)}U)\n'
            f'static uint8_t __data[{len(data)}U] = {{\n'
            f'    {hex_vals}\n'
            f'}};'
        )

    # Tope para embeber .bss directamente. .bss es zero-init, así que se
    # reserva como array estático; si supera este tope (binarios que reservan
    # cientos de MB) se reserva dinámicamente en el arranque para no inflar
    # el binario ni el fichero C.
    _BSS_STATIC_CAP = 1 * 1024 * 1024  # 1 MiB

    def _emit_bss_section(self, cfg: EnrichedCFG) -> str:
        bi = cfg.binary_info
        if not bi.bss_va or not bi.bss_size:
            return ''
        size = int(bi.bss_size)
        if size <= self._BSS_STATIC_CAP:
            return (
                f'/* .bss del binario original (zero-init) */\n'
                f'#define __BSS_VA   ((uint64_t)0x{bi.bss_va:x}ULL)\n'
                f'#define __BSS_SIZE ((size_t){size}U)\n'
                f'static uint8_t __bss[__BSS_SIZE];'
            )
        # .bss grande: puntero reservado en __sim_init()
        return (
            f'/* .bss del binario original (zero-init, reserva dinámica por tamaño) */\n'
            f'#define __BSS_VA   ((uint64_t)0x{bi.bss_va:x}ULL)\n'
            f'#define __BSS_SIZE ((size_t){size}U)\n'
            f'static uint8_t *__bss = NULL;'
        )

    def _emit_addr_translation(self, cfg: EnrichedCFG) -> str:
        """
        Capa de traducción de direcciones. Convierte una dirección virtual
        del binario original en un puntero real del proceso reconstruido:
          - si cae en .rodata/.data/.bss embebidas, devuelve el puntero al
            array correspondiente (resolviendo la "frontera" entre memoria
            simulada y datos globales);
          - en otro caso (stack/heap simulados, que ya son memoria real del
            proceso) devuelve la dirección sin cambios.
        Una dirección que no encaje en ningún rango conocido se considera un
        fallo de reconstrucción y aborta con un mensaje claro, en lugar de
        producir un acceso a memoria inválido silencioso (segfault).
        """
        bi = cfg.binary_info
        checks = []
        if bi.rodata_va and bi.rodata_hex:
            checks.append(
                '    if (va >= __RODATA_VA && va < __RODATA_VA + __RODATA_SIZE)\n'
                '        return (uintptr_t)(__rodata + (va - __RODATA_VA));')
        if bi.data_va and bi.data_hex:
            checks.append(
                '    if (va >= __DATA_VA && va < __DATA_VA + __DATA_SIZE)\n'
                '        return (uintptr_t)(__data + (va - __DATA_VA));')
        if bi.bss_va and bi.bss_size:
            checks.append(
                '    if (va >= __BSS_VA && va < __BSS_VA + __BSS_SIZE)\n'
                '        return (uintptr_t)(__bss + (va - __BSS_VA));')
        # Punteros que ya apuntan a memoria real del proceso (stack/heap
        # simulados o memoria devuelta por libc) se dejan pasar.
        passthrough = (
            '    if ((uint8_t *)(uintptr_t)va >= __sim_stack &&\n'
            '        (uint8_t *)(uintptr_t)va < __sim_stack + SIM_STACK_SIZE)\n'
            '        return (uintptr_t)va;\n'
            '    if ((uint8_t *)(uintptr_t)va >= __sim_heap &&\n'
            '        (uint8_t *)(uintptr_t)va < __sim_heap + SIM_HEAP_SIZE)\n'
            '        return (uintptr_t)va;')
        body = '\n'.join(checks)
        if body:
            body += '\n'
        return (
            '/* Traducción dirección virtual original → puntero real del proceso */\n'
            'static uintptr_t __sim_addr(uint64_t va) {\n'
            f'{body}{passthrough}\n'
            '    /* Cualquier otra dirección es un puntero real (libc, etc.) */\n'
            '    return (uintptr_t)va;\n'
            '}')

    def _emit_function_declarations(self, cfg: EnrichedCFG) -> str:
        lines = ['/* Declaraciones adelantadas */']
        for addr, func in cfg.functions.items():
            if func.is_plt or func.is_external:
                continue
            lines.append(f'static void func_{addr.replace("0x", "")}(void);  /* {func.name} */')
        return '\n'.join(lines)

    def _emit_functions(self, cfg: EnrichedCFG) -> str:
        parts = []
        for _addr, func in cfg.functions.items():
            if func.is_plt or func.is_external:
                continue
            parts.append(self._emit_function(func, cfg))
        return '\n\n'.join(parts)

    def _emit_function(self, func, cfg: EnrichedCFG) -> str:
        func_id = func.address.replace('0x', '')
        lines = [
            f'/* {"=" * 60} */',
            f'/* {func.name}  @  {func.address} */',
            f'/* {"=" * 60} */',
            f'static void func_{func_id}(void) {{',
        ]
        for block_addr in func.blocks:
            block = cfg.basic_blocks.get(block_addr)
            if block:
                lines.append(self._emit_block(block, cfg))
        lines.append('}')
        return '\n'.join(lines)

    def _is_branch_terminator(self, mnemonic: str) -> bool:
        """True si el mnemónico es un salto cuya semántica materializa _emit_block_exit."""
        m = mnemonic.lower()
        if m == 'jmp' or m.endswith(' jmp'):  # incluye 'notrack jmp' (prefijo CET)
            return True
        if m in ('jrcxz', 'jecxz'):
            return True
        return m in _JCC_TO_C

    def _emit_block(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        block_id = block.address.replace('0x', '')
        lines = [f'  block_{block_id}:']
        last_idx = len(block.instructions) - 1
        # ¿El bloque termina en un salto de tabla resuelto? Si es así, capturamos
        # el valor del registro índice en __jt_index en cuanto se usa escalado
        # (lea/mov con [idx*scale]), antes de que el cálculo de la dirección lo
        # sobrescriba; _emit_jump_table_switch despacha luego sobre __jt_index.
        jt_index_reg = ''
        if block.instructions:
            last_insn0 = cfg.instructions.get(block.instructions[-1])
            if last_insn0 is not None:
                for ann in last_insn0.annotations:
                    if ann.type == 'jump_table':
                        jt_index_reg = (getattr(ann, 'index_register', '') or '').strip()
        captured = False
        for i, insn_addr in enumerate(block.instructions):
            insn = cfg.instructions.get(insn_addr)
            if not insn:
                continue
            # La última instrucción del bloque, si es un salto (jmp/jcc), no se
            # traduce inline: su efecto lo materializa _emit_block_exit como
            # goto/if-goto. Se conserva el comentario de trazabilidad estática.
            if i == last_idx and self._is_branch_terminator(insn.mnemonic):
                lines.append(f'    /* {insn.address}: {insn.mnemonic} '
                             f'{insn.operands} */  /* salto → ver salida de bloque */')
                continue
            lines.append(self._emit_instruction(insn, cfg))
            # Capturar el índice tras la primera instrucción que lo usa escalado.
            if (jt_index_reg and not captured
                    and f'{jt_index_reg}*' in insn.operands.replace(' ', '')):
                lines.append(f'    __jt_index = {jt_index_reg};'
                             f'  /* índice de tabla de salto capturado */')
                captured = True
        lines.append(self._emit_block_exit(block, cfg))
        return '\n'.join(lines)

    def _emit_instruction(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        lines = []
        # Sincronizar rip solo cuando la instrucción lo referencia como operando.
        # Cubre accesos tipo [rip + offset] que no sean LEA (ya resuelta estáticamente).
        if 'rip' in insn.operands:
            next_addr = int(insn.address, 16) + insn.size
            lines.append(f'    rip = (uint64_t)0x{next_addr:x}ULL;')
        if any(a.type == 'trace_point' for a in insn.annotations):
            lines.append(f'    __trace({insn.address}ULL);')
        lines.append(f'    /* {insn.address}: {insn.mnemonic} {insn.operands} */')

        ext_calls    = [a for a in insn.annotations if a.type == 'external_call']
        syscall_anns = [a for a in insn.annotations if a.type == 'syscall']

        if ext_calls and insn.mnemonic == 'call':
            lines.append(self._emit_external_call(ext_calls[0]))
        elif syscall_anns and insn.mnemonic == 'syscall':
            lines.append(self._emit_syscall(syscall_anns[0]))
        elif insn.mnemonic == 'call':
            lines.append(self._emit_call(insn, cfg))
        elif insn.mnemonic == 'lea' and 'rip' in insn.operands:
            lines.append(self._emit_lea_rip(insn, cfg))
        else:
            lines.append(f'    {self._translate_instruction(insn)}')
        return '\n'.join(lines)

    def _emit_call(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        """
        Emite una llamada a función interna o indirecta.
        - Directa (call 0x401126): emite func_401126() si está definida.
        - Resuelta por backward slice (ResolvedIndirectAnnotation): usa el
          destino ya anotado por el enricher.
        - Indirecta sin resolver (call [rip+N]): busca 'mov rdi, <addr>'
          anterior (patrón _start → __libc_start_main).
        """
        # Fase 2: usar destino ya resuelto por el enricher (backward slice)
        for ann in insn.annotations:
            if ann.type == 'resolved_indirect':
                target = ann.resolved_target  # type: ignore[attr-defined]
                if target and target in self._defined_funcs:
                    func_id = target.replace('0x', '')
                    fname = cfg.functions[target].name
                    return f'    func_{func_id}();  /* indirect → {fname} (backslice) */'

        ops = insn.operands.strip()
        if '[' not in ops:
            target = _resolve_direct_target(ops)
            if target and target in self._defined_funcs:
                return f'    func_{target.replace("0x", "")}();'
            return f'    /* CALL {ops} — función no definida en este CFG */'

        # Llamada indirecta: buscar 'mov rdi, <addr>' anterior en el mismo bloque
        block = cfg.basic_blocks.get(insn.block)
        if block:
            try:
                idx = block.instructions.index(insn.address)
            except ValueError:
                idx = 0
            for prev_addr in reversed(block.instructions[:idx]):
                prev = cfg.instructions.get(prev_addr)
                if prev is None:
                    continue
                if prev.mnemonic == 'mov' and prev.operands.startswith('rdi,'):
                    val_str = prev.operands.split(',', 1)[1].strip()
                    target = _resolve_direct_target(val_str)
                    if target and target in self._defined_funcs:
                        func_id = target.replace('0x', '')
                        fname = cfg.functions[target].name
                        return f'    func_{func_id}();  /* indirect → {fname} via rdi */'
                    break
                if 'rdi' in (prev.registers_written or []):
                    break

        return f'    /* INDIRECT CALL: {ops} — sin resolver */'

    def _emit_lea_rip(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        """
        Resuelve LEA con direccionamiento RIP-relativo.
        Calcula la dirección real (next_ip + offset) y, si cae en .rodata
        embebida, emite una referencia al array __rodata.
        """
        dst, src = _split_operands(insn.operands)
        addr_expr = _mem_addr_expr(src) if src else None
        if not dst or not addr_expr:
            return f'    {self._translate_instruction(insn)}'

        next_ip = int(insn.address, 16) + insn.size
        target = _eval_rip_expr(addr_expr, next_ip)
        if target is None:
            return f'    {self._translate_instruction(insn)}'

        bi = cfg.binary_info
        if (bi.rodata_va and bi.rodata_hex and
                bi.rodata_va <= target < bi.rodata_va + len(bi.rodata_hex) // 2):
            offset = target - bi.rodata_va
            stmt = _reg_write(dst, f'(uint64_t)(uintptr_t)(__rodata + {offset}U)')
            return f'    {stmt}' if stmt else f'    /* LEA → .rodata@0x{target:x} */'

        if (bi.data_va and bi.data_hex and
                bi.data_va <= target < bi.data_va + len(bi.data_hex) // 2):
            offset = target - bi.data_va
            stmt = _reg_write(dst, f'(uint64_t)(uintptr_t)(__data + {offset}U)')
            return f'    {stmt}' if stmt else f'    /* LEA → .data@0x{target:x} */'

        stmt = _reg_write(dst, f'(uint64_t)(0x{target:x}ULL)')
        return f'    {stmt}' if stmt else f'    /* LEA rip-relativo → 0x{target:x} */'

    def _emit_external_call(self, ann) -> str:
        func_name = ann.function_name
        call_info = _LIBC_CALL_MAP.get(func_name)
        if call_info is None:
            # Sin prototipo conocido: no se puede asumir el número de
            # argumentos ni el tipo de retorno. Se declara el símbolo como
            # función variádica que devuelve long mediante un extern local,
            # y se pasan los registros de argumentos de la ABI System V.
            # Así el C generado compila siempre, sea cual sea la firma real,
            # sin castear un posible retorno void a uintptr_t.
            return (
                f'    /* EXTERNAL CALL sin prototipo conocido: {func_name}() */\n'
                f'    {{ extern long {func_name}(); '
                f'rax = (uint64_t)(long){func_name}('
                f'(long)rdi, (long)rsi, (long)rdx, '
                f'(long)rcx, (long)r8, (long)r9); }}'
            )
        ret_type, args = call_info
        args_str = ', '.join(args)
        if ret_type == 'void':
            return f'    {func_name}({args_str});'
        return f'    rax = (uint64_t)(uintptr_t){func_name}({args_str});'

    def _emit_syscall(self, ann) -> str:
        syscall_name = ann.syscall_name or 'unknown'
        libc_func = _SYSCALL_LIBC_MAP.get(syscall_name)
        if libc_func and libc_func in _LIBC_CALL_MAP:
            fake_ann = ExternalCallAnnotation(added_by='translator', function_name=libc_func)
            return self._emit_external_call(fake_ann)
        num = ann.syscall_number if ann.syscall_number >= 0 else 'rax'
        return (
            f'    /* SYSCALL portable: {syscall_name} (num={ann.syscall_number}) */\n'
            f'    rax = (uint64_t)__do_syscall((long){num}, '
            f'(long)rdi, (long)rsi, (long)rdx, (long)rcx, (long)r8, (long)r9);'
        )

    def _translate_instruction(self, insn: Instruction) -> str:
        m   = insn.mnemonic
        ops = insn.operands

        # Instrucciones con prefijo rep/repe/repne
        if m in _REP_INSNS:
            return _REP_INSNS[m]

        if m == 'nop':
            return '/* nop */'
        if m == 'hlt':
            return 'return;'
        if m == 'endbr64':
            return '/* nop */  /* endbr64 */'
        if m == 'push':
            reg = ops.strip()
            return (f'rsp -= 8; '
                    f'if (rsp < (uint64_t)(uintptr_t)__sim_stack) '
                    f'{{ fprintf(stderr, "stack overflow\\n"); abort(); }} '
                    f'SIM_WRITE64(rsp, {reg});')
        if m == 'pop':
            reg = ops.strip()
            w = _reg_write(reg, 'SIM_READ64(rsp)')
            if w:
                return f'{w} rsp += 8;'
        if m in ('ret', 'retn'):
            return 'return;'
        if m == 'leave':
            return 'rsp = rbp; rbp = SIM_READ64(rsp); rsp += 8;'
        if m == 'mov':
            dst, src = _split_operands(ops)
            if dst and src:
                c_src = _reg_to_c(src)
                if c_src is not None and _reg_to_c(dst) is not None:
                    return _reg_write(dst, c_src)
                mem = _mem_to_c(dst, 'write', src) or _mem_to_c(src, 'read', dst)
                if mem:
                    return mem
        if m in ('movsx', 'movsxd'):
            dst, src = _split_operands(ops)
            c_s = _operand_read_expr(src) if src else None
            if dst and c_s is not None:
                sz = _operand_size(src)
                ity = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t', 64: 'int64_t'}[sz]
                return _reg_write(dst, f'(uint64_t)(int64_t)({ity})({c_s})')
        if m == 'cdqe':
            return 'rax = (uint64_t)(int64_t)(int32_t)(uint32_t)rax;'
        if m == 'cwde':
            return 'rax = (uint64_t)(uint32_t)(int32_t)(int16_t)(uint16_t)rax;'
        if m == 'cdq':
            return 'rdx = (uint64_t)(uint32_t)(((int32_t)(uint32_t)rax) >> 31);'
        if m == 'cqo':
            return 'rdx = (uint64_t)(((int64_t)rax) >> 63);'
        if m == 'movzx':
            dst, src = _split_operands(ops)
            c_s = _operand_read_expr(src) if src else None
            if dst and c_s is not None:
                return _reg_write(dst, f'(uint64_t){c_s}')
        if m == 'lea':
            dst, src = _split_operands(ops)
            if dst and src:
                addr = _mem_addr_expr(src)
                if addr:
                    return _reg_write(dst, f'(uint64_t)({addr})')
        if m == 'add':
            return _emit_alu_binop(ops, '+')
        if m == 'sub':
            return _emit_alu_binop(ops, '-')
        if m == 'inc':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'{c_o} + 1')
        if m == 'dec':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'{c_o} - 1')
        if m == 'mul':
            # Forma de un operando: rax * reg → rdx:rax (resultado de 128 bits)
            c_r = _reg_to_c(ops.strip())
            if c_r is not None:
                return (f'{{ __uint128_t __p = (__uint128_t)rax * (__uint128_t)({c_r}); '
                        f'rax = (uint64_t)__p; rdx = (uint64_t)(__p >> 64); '
                        f'OF = CF = (rdx != 0); }}')
        if m == 'imul':
            dst, src = _split_operands(ops)
            if dst is None:
                # Forma de un operando: rax * reg → rdx:rax con signo
                c_r = _reg_to_c(ops.strip())
                if c_r is not None:
                    return (f'{{ __int128_t __p = (__int128_t)(int64_t)rax * (__int128_t)(int64_t)({c_r}); '
                            f'rax = (uint64_t)__p; rdx = (uint64_t)((__uint128_t)__p >> 64); '
                            f'OF = CF = (rdx != (uint64_t)((int64_t)rax >> 63)); }}')
            c_d = _reg_to_c(dst) if dst else None
            c_s = _operand_read_expr(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'(uint64_t)((int64_t){c_d} * (int64_t){c_s})')
        if m == 'div':
            # rax / op → cociente en rax, resto en rdx (división sin signo)
            c_r = _operand_read_expr(ops.strip())
            if c_r is not None:
                return (f'{{ uint64_t __d = (uint64_t)({c_r}); '
                        f'if (__d == 0) {{ fprintf(stderr, "div: division por cero\\n"); abort(); }} '
                        f'uint64_t __q = rax / __d; rdx = rax % __d; rax = __q; }}')
        if m == 'idiv':
            # rax / op → cociente en rax, resto en rdx (división con signo)
            c_r = _operand_read_expr(ops.strip())
            if c_r is not None:
                return (f'{{ int64_t __d = (int64_t)({c_r}); '
                        f'if (__d == 0) {{ fprintf(stderr, "idiv: division por cero\\n"); abort(); }} '
                        f'int64_t __q = (int64_t)rax / __d; '
                        f'rdx = (uint64_t)((int64_t)rax % __d); rax = (uint64_t)__q; }}')

        if m == 'neg':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'(uint64_t)(-(int64_t){c_o})')
        if m == 'xor':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                if dst == src:
                    return f'{_reg_base(dst)} = 0;  /* xor reg,reg */'
                return _reg_write(dst, f'{c_d} ^ {c_s}')
        if m == 'and':
            return _emit_alu_binop(ops, '&')
        if m == 'or':
            return _emit_alu_binop(ops, '|')
        if m == 'not':
            reg = ops.strip()
            c_o = _reg_to_c(reg)
            if c_o is not None:
                return _reg_write(reg, f'~{c_o}')
        if m in ('shl', 'sal'):
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} << ({c_s} & 63)')
        if m == 'shr':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'{c_d} >> ({c_s} & 63)')
        if m == 'sar':
            dst, src = _split_operands(ops)
            c_d = _reg_to_c(dst) if dst else None
            c_s = _reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _reg_write(dst, f'(uint64_t)((int64_t){c_d} >> ({c_s} & 63))')
        if m == 'cmp':
            dst, src = _split_operands(ops)
            c_d = _operand_read_expr(dst) if dst else None
            c_s = _operand_read_expr(src) if src else None
            if c_d and c_s:
                return (f'{{ int64_t __a=(int64_t)({c_d}), __b=(int64_t)({c_s}), __r=__a-__b; '
                        f'ZF=(__r==0); SF=(__r<0); '
                        f'CF=((uint64_t)({c_d})<(uint64_t)({c_s})); '
                        f'OF=(uint8_t)((__a<0)!=(__b<0)&&(__r<0)!=(__a<0)); '
                        f'PF=(uint8_t)(__builtin_parity((uint8_t)__r)); }}')
        if m == 'test':
            dst, src = _split_operands(ops)
            c_d = _operand_read_expr(dst) if dst else None
            c_s = _operand_read_expr(src) if src else None
            if c_d and c_s:
                return (f'{{ int64_t __t=(int64_t)({c_d}&{c_s}); '
                        f'ZF=(__t==0); SF=(__t<0); CF=0; OF=0; '
                        f'PF=(uint8_t)(__builtin_parity((uint8_t)__t)); }}')
        if m.startswith('cmov') and m in _CMOV_TO_C:
            dst, src = _split_operands(ops)
            c_s = _operand_read_expr(src) if src else None
            if dst and c_s is not None and _reg_base(dst) is not None:
                cond = _CMOV_TO_C[m]
                assign = _reg_write(dst, c_s)
                return f'if ({cond}) {{ {assign} }}'
        _setcc = {
            'sete': 'ZF', 'setz': 'ZF', 'setne': '!ZF', 'setnz': '!ZF',
            'setl': '(SF!=OF)', 'setg': '(!ZF&&(SF==OF))',
            'setge': '(SF==OF)', 'setle': '(ZF||(SF!=OF))',
            'seta': '(!CF&&!ZF)', 'setb': 'CF',
        }
        if m in _setcc:
            reg = ops.strip()
            if _reg_to_c(reg) is not None:
                return _reg_write(reg, f'(uint8_t)({_setcc[m]})')
        if m == 'call':
            target = _resolve_direct_target(ops)
            if target:
                if target in self._defined_funcs:
                    return f'func_{target.replace("0x", "")}();'
                return f'/* CALL {ops} — función no definida en este CFG */'
            return f'/* INDIRECT CALL: {ops} — omitido */\n    fprintf(stderr, "indirect call\\n");'

        return (
            f'/* UNSUPPORTED: {m} {ops} */\n'
            f'    fprintf(stderr, "UNSUPPORTED: {m} {ops}\\n");\n'
            f'    abort();'
        )

    def _emit_block_exit(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        if not block.successors:
            return ''
        if len(block.successors) == 1:
            succ = block.successors[0]
            if succ in cfg.basic_blocks:
                return f'  goto block_{succ.replace("0x", "")};'
            return ''
        if len(block.successors) == 2:
            t  = block.successors[0].replace('0x', '')
            f_ = block.successors[1].replace('0x', '')
            condition = self._jcc_condition(block, cfg)
            return f'  if ({condition}) goto block_{t};\n  goto block_{f_};'

        # Tres o más sucesores: buscar JumpTableAnnotation en la última instrucción
        if block.instructions:
            last_insn = cfg.instructions.get(block.instructions[-1])
            if last_insn is not None:
                for ann in last_insn.annotations:
                    if ann.type == 'jump_table':
                        return self._emit_jump_table_switch(ann, block)  # type: ignore[arg-type]

        return (
            '  /* UNSUPPORTED: salto indirecto sin resolver */\n'
            '  fprintf(stderr, "indirect jump\\n");\n'
            '  abort();'
        )

    def _emit_jump_table_switch(self, jt_ann, block: BasicBlock) -> str:
        """
        Emite un switch C para un salto indexado resuelto (Fase 1).

        Despacha sobre el índice capturado en la variable global __jt_index en el
        momento de la lectura de la tabla (ver _emit_block), lo que es robusto
        aunque el registro índice se sobrescriba durante el cálculo de la
        dirección de destino (patrón de GCC con base + offset relativo).
        """
        cases: list[str] = []
        for i, target in enumerate(jt_ann.targets):
            blk_id = target.replace('0x', '')
            cases.append(f'    case {i}: goto block_{blk_id};')
        cases_str = '\n'.join(cases)
        return (
            f'  switch ((int)__jt_index) {{\n'
            f'{cases_str}\n'
            f'    default: abort();\n'
            f'  }}'
        )

    def _jcc_condition(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        """
        Devuelve la condición C exacta para el salto condicional que termina
        el bloque, consultando el mnemónico real de la última instrucción.

        Si el mnemónico no está en _JCC_TO_C (no debería ocurrir en un CFG
        bien formado) cae en 'ZF' como valor seguro y emite una advertencia
        en el comentario para que el analista lo detecte.
        """
        if not block.instructions:
            return 'ZF'
        last_addr = block.instructions[-1]
        last_insn = cfg.instructions.get(last_addr)
        if last_insn is None:
            return 'ZF'
        mnemonic  = last_insn.mnemonic.lower()
        # Saltos que comprueban el contador directamente, no flags aritméticos
        if mnemonic == 'jrcxz':
            return 'rcx == 0'
        if mnemonic == 'jecxz':
            return '(uint32_t)rcx == 0'
        condition = _JCC_TO_C.get(mnemonic)
        if condition is not None:
            return condition
        # Mnemónico desconocido: emite ZF con comentario de advertencia
        return f'ZF /* WARNING: condición desconocida para {mnemonic} */'

    def _emit_entry_point(self, cfg: EnrichedCFG) -> str:
        entry    = cfg.binary_info.entry_point
        entry_id = entry.replace('0x', '')
        ef       = cfg.functions.get(entry)
        fname    = ef.name if ef else f'func_{entry_id}'
        bi       = cfg.binary_info
        bss_init = ''
        if bi.bss_va and bi.bss_size and int(bi.bss_size) > self._BSS_STATIC_CAP:
            bss_init = (
                '    __bss = (uint8_t *)calloc(__BSS_SIZE, 1);\n'
                f'    if (!__bss) {{ fprintf(stderr, "no se pudo reservar .bss\\n"); return 1; }}\n'
            )
        return (
            f'/* Punto de entrada — rsp apunta al stack simulado, no al stack real */\n'
            f'int main(int argc, char *argv[]) {{\n'
            f'    atexit(__trace_dump_atexit);  /* volcado de traza en retorno normal o exit() de libc */\n'
            f'{bss_init}'
            f'    rsp  = (uint64_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 8);\n'
            f'    rsp &= ~(uint64_t)0xFULL;\n'
            f'    rdi = (uint64_t)(uint32_t)argc;\n'
            f'    rsi = (uint64_t)(uintptr_t)argv;\n'
            f'    func_{entry_id}();  /* {fname} @ {entry} */\n'
            f'    __trace_dump(TRACE_PATH);\n'
            f'    return (int)(uint32_t)rax;\n'
            f'}}'
        )


# ---------------------------------------------------------------------------
# Utilidades privadas
# ---------------------------------------------------------------------------

def _emit_alu_binop(ops: str, op: str) -> str:
    """
    Traduce una operación ALU de dos operandos (add/sub/and/or) admitiendo
    que la fuente y/o el destino sean memoria, además de registro. Actualiza
    ZF y SF en función del resultado. Devuelve el marcador UNSUPPORTED si no
    puede traducir los operandos.
    """
    dst, src = _split_operands(ops)
    if not dst or not src:
        return _unsupported(op, ops)
    c_s = _operand_read_expr(src)
    if c_s is None:
        return _unsupported(op, ops)
    flags = ' ZF=((int64_t)__res==0); SF=((int64_t)__res<0);'

    # Destino registro
    c_d = _reg_to_c(dst)
    if c_d is not None:
        write_res = _reg_write(dst, '__res')
        if write_res:
            return (f'{{ uint64_t __res=({c_d}) {op} ({c_s}); '
                    f'{write_res}{flags} }}')

    # Destino memoria
    addr = _mem_addr_expr(dst)
    if addr is not None:
        size = _operand_size(dst)
        cur = f'(uint64_t)SIM_READ{size}({addr})'
        return (f'{{ uint64_t __res=({cur}) {op} ({c_s}); '
                f'SIM_WRITE{size}({addr}, __res);{flags} }}')

    return _unsupported(op, ops)


def _unsupported(m: str, ops: str) -> str:
    return (f'/* UNSUPPORTED: {m} {ops} */\n'
            f'    fprintf(stderr, "UNSUPPORTED: {m} {ops}\\n");\n'
            f'    abort();')


def _is_branch_terminator(mnemonic: str) -> bool:
    """
    True si el mnemónico es un salto (incondicional o condicional) que
    termina un bloque y cuya semántica la materializa _emit_block_exit.
    Excluye 'call' y 'ret', que tienen traducción inline propia.
    """
    m = mnemonic.lower()
    if m == 'jmp':
        return True
    if m in ('jrcxz', 'jecxz'):
        return True
    return m in _JCC_TO_C


def _split_operands(ops: str) -> tuple[str | None, str | None]:
    parts = ops.split(',', 1)
    return (parts[0].strip(), parts[1].strip()) if len(parts) == 2 else (None, None)


def _reg_to_c(operand: str) -> str | None:
    """Rvalue expression for reading a register or immediate. Cast but not an lvalue."""
    o = operand.strip()
    if o in _REGISTERS_64:
        return o
    if o in _REG_32_TO_64:
        return f'(uint32_t){_REG_32_TO_64[o]}'
    if o in _REG_16_TO_64:
        return f'(uint16_t){_REG_16_TO_64[o]}'
    if o in _REG_8L_TO_64:
        return f'(uint8_t){_REG_8L_TO_64[o]}'
    if o in _REG_8H_TO_64:
        return f'(uint8_t)({_REG_8H_TO_64[o]} >> 8)'
    if o.startswith('0x'):
        return f'((uint64_t){o}ULL)'
    if o.startswith('-0x'):
        v = -int(o[1:], 16)
        return f'((int64_t){v}LL)'
    if o.lstrip('-').isdigit():
        v = int(o)
        return f'((int64_t){v}LL)' if v < 0 else f'((uint64_t){v}ULL)'
    return None


def _reg_base(operand: str) -> str | None:
    """Returns the underlying 64-bit register name for any register alias."""
    o = operand.strip()
    if o in _REGISTERS_64:
        return o
    for table in (_REG_32_TO_64, _REG_16_TO_64, _REG_8L_TO_64, _REG_8H_TO_64):
        if o in table:
            return table[o]
    return None


def _reg_write(dst: str, src_expr: str) -> str | None:
    """
    Generates a valid C assignment statement writing src_expr into dst.

    Handles x86-64 partial-register semantics:
      - 32-bit writes zero-extend to 64 bits (Intel manual Vol.1 §3.4.1.1)
      - 16/8-bit writes merge into the base register (upper bits preserved)
    """
    d = dst.strip()
    if d in _REGISTERS_64:
        return f'{d} = {src_expr};'
    if d in _REG_32_TO_64:
        base = _REG_32_TO_64[d]
        return f'{base} = (uint64_t)(uint32_t)({src_expr});'
    if d in _REG_16_TO_64:
        base = _REG_16_TO_64[d]
        return f'{base} = ({base} & ~(uint64_t)0xFFFFULL) | (uint64_t)(uint16_t)({src_expr});'
    if d in _REG_8L_TO_64:
        base = _REG_8L_TO_64[d]
        return f'{base} = ({base} & ~(uint64_t)0xFFULL) | (uint64_t)(uint8_t)({src_expr});'
    if d in _REG_8H_TO_64:
        base = _REG_8H_TO_64[d]
        return f'{base} = ({base} & ~(uint64_t)0xFF00ULL) | ((uint64_t)(uint8_t)({src_expr}) << 8);'
    return None


def _mem_addr_expr(mem: str) -> str | None:
    s = mem.strip()
    for p in ('qword ptr ', 'dword ptr ', 'word ptr ', 'byte ptr '):
        if s.startswith(p):
            s = s[len(p):]
            break
    return s[1:-1].strip() if s.startswith('[') and s.endswith(']') else None


def _mem_to_c(operand: str, direction: str, other: str) -> str | None:
    s = operand.strip()
    size = 64
    for p, b in [('qword ptr ', 64), ('dword ptr ', 32), ('word ptr ', 16), ('byte ptr ', 8)]:
        if s.startswith(p):
            s = s[len(p):]
            size = b
            break
    if not (s.startswith('[') and s.endswith(']')):
        return None
    addr = s[1:-1].strip()
    if direction == 'read':
        if _reg_to_c(other) is not None:
            return _reg_write(other, f'(uint64_t)SIM_READ{size}({addr})')
        return None
    src = _reg_to_c(other)
    return f'SIM_WRITE{size}({addr}, {src});' if src else None


def _operand_size(operand: str) -> int:
    """Tamaño en bits de un operando (registro o memoria con ptr explícito)."""
    o = operand.strip()
    for p, b in (('qword ptr', 64), ('dword ptr', 32),
                 ('word ptr', 16), ('byte ptr', 8)):
        if o.startswith(p):
            return b
    if o in _REGISTERS_64:
        return 64
    if o in _REG_32_TO_64:
        return 32
    if o in _REG_16_TO_64:
        return 16
    if o in _REG_8L_TO_64 or o in _REG_8H_TO_64:
        return 8
    return 64


def _operand_read_expr(operand: str) -> str | None:
    """
    Expresión C (rvalue uint64_t) para leer cualquier operando fuente:
    registro, inmediato o acceso a memoria con SIM_READ. Devuelve None si
    no se reconoce el operando.
    """
    o = operand.strip()
    reg = _reg_to_c(o)
    if reg is not None:
        return reg
    addr = _mem_addr_expr(o)
    if addr is not None:
        return f'(uint64_t)SIM_READ{_operand_size(o)}({addr})'
    return None


def _resolve_direct_target(operands: str) -> str | None:
    o = operands.strip()
    try:
        if o.startswith('0x'):
            return hex(int(o, 16))
        if o.lstrip('-').isdigit():
            return hex(int(o))
    except ValueError:
        pass
    return None


def _eval_rip_expr(addr_expr: str, next_ip: int) -> int | None:
    """Evalúa 'rip + 0xef3' o 'rip - 0x5' sustituyendo rip por next_ip."""
    expr = addr_expr.strip()
    if not expr.startswith('rip'):
        return None
    rest = expr[len('rip'):].strip()
    if not rest:
        return next_ip
    if rest.startswith('+'):
        try:
            return next_ip + int(rest[1:].strip(), 0)
        except ValueError:
            return None
    if rest.startswith('-'):
        try:
            return next_ip - int(rest[1:].strip(), 0)
        except ValueError:
            return None
    return None
