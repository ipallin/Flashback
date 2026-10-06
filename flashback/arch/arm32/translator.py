"""
Translator ARM32: genera código C portable desde CFG ARM (32-bit) enriquecido.

Diferencias clave respecto al Translator base:
  - Registros r0-r15 como uint32_t; sp=r13, lr=r14, pc=r15.
  - Flags NZCV (N, Z, C, V).
  - Llamadas vía bl/blx; syscalls vía svc (número en r7).
  - Instrucciones con sufijo de condición (beq, bne, addlt, etc.).
  - ldm/stm (push/pop múltiple) tratados como secuencias de SIM_READ/WRITE.
  - ABI AAPCS: args r0-r3, args extra en pila.
"""

from __future__ import annotations

import logging

from flashback.core.translator import Translator, _INCLUDES, _resolve_direct_target
from flashback.core.models import EnrichedCFG, BasicBlock, Instruction
from flashback.arch.arm32.instruction_sem import ARM32_COND_TO_C, split_arm_mnemonic
from flashback.arch.arm32 import semantics

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes ARM32
# ---------------------------------------------------------------------------

_ARM32_REGS = [f'r{i}' for i in range(16)]   # r0..r15

_ARM32_FLAGS = ['N', 'Z', 'C', 'V']

_ARM32_ALIASES = {
    'sp': 'r13', 'lr': 'r14', 'pc': 'r15',
    'ip': 'r12', 'fp': 'r11', 'sl': 'r10', 'sb': 'r9',
}

# Condiciones de rama ARM32 → expresión C
_A32_BCC_TO_C: dict[str, str] = ARM32_COND_TO_C

# Saltos cuya semántica materializa _emit_block_exit (goto / if-goto / switch),
# con o sin sufijo de condición o de anchura (beq.w, cbz, tbb...). Las llamadas
# (bl/blx) y los retornos (bx lr, pop {pc}) se traducen en línea.
_A32_BRANCH_BASES = frozenset({'b', 'cbz', 'cbnz', 'tbb', 'tbh'})

# Libc call map ARM32: args en r0, r1, r2, r3 (AAPCS; extras en pila)
_A32_LIBC_CALL_MAP: dict[str, tuple[str, list[str]]] = {
    'printf':   ('int',     ['(const char*)(uintptr_t)r0', 'r1', 'r2', 'r3']),
    'fprintf':  ('int',     ['(FILE*)(uintptr_t)r0', '(const char*)(uintptr_t)r1', 'r2']),
    'scanf':    ('int',     ['(const char*)(uintptr_t)r0', '(void*)(uintptr_t)r1']),
    'puts':     ('int',     ['(const char*)(uintptr_t)r0']),
    'putchar':  ('int',     ['(int)r0']),
    'getchar':  ('int',     []),
    'malloc':   ('void*',   ['(size_t)r0']),
    'calloc':   ('void*',   ['(size_t)r0', '(size_t)r1']),
    'realloc':  ('void*',   ['(void*)(uintptr_t)r0', '(size_t)r1']),
    'free':     ('void',    ['(void*)(uintptr_t)r0']),
    'memcpy':   ('void*',   ['(void*)(uintptr_t)r0', '(const void*)(uintptr_t)r1', '(size_t)r2']),
    'memset':   ('void*',   ['(void*)(uintptr_t)r0', '(int)r1', '(size_t)r2']),
    'strlen':   ('size_t',  ['(const char*)(uintptr_t)r0']),
    'strcpy':   ('char*',   ['(char*)(uintptr_t)r0', '(const char*)(uintptr_t)r1']),
    'strncpy':  ('char*',   ['(char*)(uintptr_t)r0', '(const char*)(uintptr_t)r1', '(size_t)r2']),
    'strcmp':   ('int',     ['(const char*)(uintptr_t)r0', '(const char*)(uintptr_t)r1']),
    'strncmp':  ('int',     ['(const char*)(uintptr_t)r0', '(const char*)(uintptr_t)r1', '(size_t)r2']),
    'open':     ('int',     ['(const char*)(uintptr_t)r0', '(int)r1', '(int)r2']),
    'read':     ('ssize_t', ['(int)r0', '(void*)(uintptr_t)r1', '(size_t)r2']),
    'write':    ('ssize_t', ['(int)r0', '(const void*)(uintptr_t)r1', '(size_t)r2']),
    'close':    ('int',     ['(int)r0']),
    'exit':     ('void',    ['(int)r0']),
    'atoi':     ('int',     ['(const char*)(uintptr_t)r0']),
    'strtol':   ('long',    ['(const char*)(uintptr_t)r0', '(char**)(uintptr_t)r1', '(int)r2']),
    'fopen':    ('FILE*',   ['(const char*)(uintptr_t)r0', '(const char*)(uintptr_t)r1']),
    'fclose':   ('int',     ['(FILE*)(uintptr_t)r0']),
    'fread':    ('size_t',  ['(void*)(uintptr_t)r0', '(size_t)r1', '(size_t)r2', '(FILE*)(uintptr_t)r3']),
    'fwrite':   ('size_t',  ['(const void*)(uintptr_t)r0', '(size_t)r1', '(size_t)r2', '(FILE*)(uintptr_t)r3']),
    'perror':   ('void',    ['(const char*)(uintptr_t)r0']),
    'mmap':     ('void*',   ['(void*)(uintptr_t)r0', '(size_t)r1', '(int)r2', '(int)r3',
                             '(int)SIM_READ32(r13)', '(off_t)SIM_READ32(r13+4)']),
    'munmap':   ('int',     ['(void*)(uintptr_t)r0', '(size_t)r1']),
    'socket':   ('int',     ['(int)r0', '(int)r1', '(int)r2']),
    'connect':  ('int',     ['(int)r0', '(const struct sockaddr*)(uintptr_t)r1', '(socklen_t)r2']),
    'fork':     ('pid_t',   []),
    'execve':   ('int',     ['(const char*)(uintptr_t)r0', '(char* const*)(uintptr_t)r1',
                             '(char* const*)(uintptr_t)r2']),
    'waitpid':  ('pid_t',   ['(pid_t)r0', '(int*)(uintptr_t)r1', '(int)r2']),
    'abort':            ('void', []),
    '_exit':            ('void', ['(int)r0']),
    '__stack_chk_fail': ('void', []),
}


class Arm32Translator(Translator):
    """Traductor de CFG ARM32 → C portátil."""

    def _emit_registers(self) -> str:
        lines = ['/* Registros ARM32 simulados como variables globales */']
        for reg in _ARM32_REGS:
            lines.append(f'static uint32_t {reg} = 0;')
        lines.append('/* Aliases convenientes */')
        for alias, target in _ARM32_ALIASES.items():
            lines.append(f'#define {alias} {target}')
        lines.append('static uint64_t __jt_index = 0;  /* índice de tabla de salto */')
        return '\n'.join(lines)

    def translate(self, cfg: EnrichedCFG) -> str:
        # Funciones Thumb: las que contienen alguna instrucción de 2 bytes.
        # Determina el valor que lee pc (dirección + 4 en Thumb, + 8 en ARM).
        thumb_funcs = {
            block.function for block in cfg.basic_blocks.values()
            if any(cfg.instructions[a].size == 2 for a in block.instructions
                   if a in cfg.instructions)
        }
        self._thumb_blocks = {
            addr for addr, block in cfg.basic_blocks.items() if block.function in thumb_funcs
        }
        return super().translate(cfg)

    def _is_thumb(self, insn: Instruction) -> bool:
        return insn.size == 2 or insn.block in getattr(self, '_thumb_blocks', ())

    def _emit_includes(self) -> str:
        return '\n'.join(_INCLUDES + ['#include <math.h>'])

    def _emit_flags(self) -> str:
        lines = ['/* Flags NZCV ARM32 */']
        for flag in _ARM32_FLAGS:
            lines.append(f'static uint8_t {flag} = 0;')
        lines.append(semantics.C_RUNTIME)
        return '\n'.join(lines)

    def _emit_function_declarations(self, cfg: EnrichedCFG) -> str:
        """Declaraciones + despachador de llamadas/saltos a registro (blx rN, bx rN)."""
        cases = '\n'.join(
            f'    case 0x{int(addr, 16) & ~1:x}U: func_{addr.replace("0x", "")}(); return;'
            for addr in sorted(self._defined_funcs, key=lambda a: int(a, 16))
        )
        return (
            f'{super()._emit_function_declarations(cfg)}\n\n'
            '/* Despachador de llamadas y saltos a registro: resuelve en tiempo de\n'
            '   ejecución la dirección (puntero a función, bit Thumb incluido). */\n'
            'static void __call_indirect(uint32_t target, uint32_t site) {\n'
            '    switch (target & ~1U) {\n'
            f'{cases}\n'
            '    }\n'
            '    fprintf(stderr, "salto/llamada indirecta a 0x%08x no resoluble (desde 0x%08x)\\n",\n'
            '            (unsigned)target, (unsigned)site);\n'
            '    abort();\n'
            '}'
        )

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
            f'/* Punto de entrada ARM32 */\n'
            f'int main(int argc, char *argv[]) {{\n'
            f'{bss_init}'
            f'    r13 = (uint32_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 4);\n'
            f'    r13 &= ~(uint32_t)0x7U;\n'
            f'    r0 = (uint32_t)argc;\n'
            f'    r1 = (uint32_t)(uintptr_t)argv;\n'
            f'    func_{entry_id}();  /* {fname} @ {entry} */\n'
            f'    __trace_dump("flashback_trace.bin");\n'
            f'    return (int)(uint32_t)r0;\n'
            f'}}'
        )

    _jt_capture_at_dispatch = True

    def _jt_index_expr(self, reg: str) -> str:
        return _ARM32_ALIASES.get(reg, reg)

    def _is_branch_terminator(self, mnemonic: str) -> bool:
        base, _cond = split_arm_mnemonic(mnemonic)
        return base in _A32_BRANCH_BASES

    def _jcc_condition(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        if not block.instructions:
            return 'Z'
        last_insn = cfg.instructions.get(block.instructions[-1])
        if last_insn is None:
            return 'Z'
        # Sufijo de condición del mnemónico ('beq' → 'eq', 'bne.w' → 'ne')
        m, cond = split_arm_mnemonic(last_insn.mnemonic)
        if cond:
            return ARM32_COND_TO_C[cond]
        if m == 'cbz':
            ops = last_insn.operands.split(',')[0].strip()
            reg = _a32_resolve_reg(ops)
            return f'{reg} == 0'
        if m == 'cbnz':
            ops = last_insn.operands.split(',')[0].strip()
            reg = _a32_resolve_reg(ops)
            return f'{reg} != 0'
        return f'Z /* WARNING: condición desconocida para {m} */'

    def _emit_instruction(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        lines = []
        if any(a.type == 'trace_point' for a in insn.annotations):
            lines.append(f'    __trace({insn.address}ULL);')
        lines.append(f'    /* {insn.address}: {insn.mnemonic} {insn.operands} */')

        ext_calls    = [a for a in insn.annotations if a.type == 'external_call']
        syscall_anns = [a for a in insn.annotations if a.type == 'syscall']

        m = insn.mnemonic
        base, cond = split_arm_mnemonic(m)
        if base in ('bl', 'blx'):
            call = (self._emit_external_call(ext_calls[0]) if ext_calls
                    else self._emit_call(insn, cfg))
            if cond:
                call = f'    if ({ARM32_COND_TO_C[cond]}) {{\n{call}\n    }}'
            lines.append(call)
        elif syscall_anns and m in ('svc', 'swi'):
            lines.append(self._emit_syscall(syscall_anns[0]))
        else:
            lines.append(f'    {self._translate_instruction(insn)}')
        return '\n'.join(lines)

    def _emit_external_call(self, ann) -> str:
        func_name = ann.function_name
        call_info = _A32_LIBC_CALL_MAP.get(func_name)
        if call_info is None:
            return (
                f'    /* EXTERNAL CALL sin prototipo: {func_name}() */\n'
                f'    {{ extern long {func_name}(); '
                f'r0 = (uint32_t)(long){func_name}('
                f'(long)r0, (long)r1, (long)r2, (long)r3); }}'
            )
        ret_type, args = call_info
        args_str = ', '.join(args)
        if ret_type == 'void':
            return f'    {func_name}({args_str});'
        return f'    r0 = (uint32_t)(uintptr_t){func_name}({args_str});'

    def _emit_syscall(self, ann) -> str:
        num = ann.syscall_number if ann.syscall_number >= 0 else 'r7'
        name = ann.syscall_name or 'unknown'
        return (
            f'    /* SYSCALL svc #0: {name} (num={ann.syscall_number}) */\n'
            f'    r0 = (uint32_t)syscall((long){num}, '
            f'(long)r0, (long)r1, (long)r2, (long)r3, (long)r4, (long)r5);'
        )

    def _emit_call(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        ops = insn.operands.strip()
        site = f'0x{int(insn.address, 16):x}U'
        target = _resolve_direct_target(ops.lstrip('#'))
        if target and target in self._defined_funcs:
            return f'    func_{target.replace("0x", "")}();'
        if target:
            # Llamada directa a una dirección sin función en el CFG
            return f'    __call_indirect({target}U, {site});'
        reg = _a32_resolve_reg(ops)
        return f'    __call_indirect({reg}, {site});  /* llamada indirecta */'

    def _svc(self, insn: Instruction) -> str:
        """svc sin anotación de syscall: llamada al sistema Linux EABI (número en r7)."""
        return ('r0 = (uint32_t)syscall((long)r7, (long)r0, (long)r1, (long)r2, '
                '(long)r3, (long)r4, (long)r5);')

    def _translate_instruction(self, insn: Instruction) -> str:
        m = insn.mnemonic.lower()
        if split_arm_mnemonic(m)[0] == 'svc':
            return self._svc(insn)
        literal = None
        jump_table = False
        for ann in insn.annotations:
            if ann.type == 'literal_load':
                literal = bytes.fromhex(ann.data)  # type: ignore[attr-defined]
            elif ann.type == 'jump_table':
                jump_table = True
        ctx = semantics.InsnContext(
            address=int(insn.address, 16), size=insn.size, thumb=self._is_thumb(insn),
            literal=literal, jump_table=jump_table,
        )
        stmt = semantics.translate(insn.mnemonic, insn.operands, ctx)
        if stmt is not None:
            return stmt
        return (
            f'/* UNSUPPORTED: {insn.mnemonic} {insn.operands} */\n'
            f'    fprintf(stderr, "UNSUPPORTED: {insn.mnemonic} {insn.operands}\\n");\n'
            f'    abort();'
        )


# ---------------------------------------------------------------------------
# Helpers privados ARM32
# ---------------------------------------------------------------------------

def _a32_resolve_reg(name: str) -> str:
    n = name.strip()
    return _ARM32_ALIASES.get(n, n)
