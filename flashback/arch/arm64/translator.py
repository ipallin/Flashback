"""
Translator ARM64: genera código C portable a partir del CFG AArch64 enriquecido.

Subclase de Translator que adapta la generación de código para la ABI AAPCS64:
  - Registros x0-x30, sp como variables globales.
  - Flags NZCV en lugar de ZF/SF/CF/OF.
  - Instrucciones ARM64: mov/orr, add, sub, ldr, str, ldp, stp, etc.
  - Llamadas vía bl/blr; syscalls vía svc.
"""

from __future__ import annotations

import logging

from flashback.core.translator import Translator, _resolve_direct_target
from flashback.core.models import EnrichedCFG, BasicBlock, Instruction, ExternalCallAnnotation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes ARM64
# ---------------------------------------------------------------------------

_ARM64_REGS_64 = [
    'x0',  'x1',  'x2',  'x3',  'x4',  'x5',  'x6',  'x7',
    'x8',  'x9',  'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp',
]

_ARM64_REGS_32_TO_64 = {
    'w0':  'x0',  'w1':  'x1',  'w2':  'x2',  'w3':  'x3',
    'w4':  'x4',  'w5':  'x5',  'w6':  'x6',  'w7':  'x7',
    'w8':  'x8',  'w9':  'x9',  'w10': 'x10', 'w11': 'x11',
    'w12': 'x12', 'w13': 'x13', 'w14': 'x14', 'w15': 'x15',
    'w16': 'x16', 'w17': 'x17', 'w18': 'x18', 'w19': 'x19',
    'w20': 'x20', 'w21': 'x21', 'w22': 'x22', 'w23': 'x23',
    'w24': 'x24', 'w25': 'x25', 'w26': 'x26', 'w27': 'x27',
    'w28': 'x28', 'w29': 'x29', 'w30': 'x30', 'wsp': 'sp',
}

_ARM64_FLAGS = ['N', 'Z', 'C', 'V']

# Condiciones de rama ARM64 → expresión C usando flags NZCV
_A64_BCC_TO_C: dict[str, str] = {
    'b.eq': 'Z',         'b.ne': '!Z',
    'b.cs': 'C',         'b.cc': '!C',
    'b.hs': 'C',         'b.lo': '!C',
    'b.mi': 'N',         'b.pl': '!N',
    'b.vs': 'V',         'b.vc': '!V',
    'b.hi': '(C && !Z)', 'b.ls': '(!C || Z)',
    'b.ge': '(N == V)',  'b.lt': '(N != V)',
    'b.gt': '(!Z && N == V)', 'b.le': '(Z || N != V)',
    'b.al': '1',
}

# Ramas que terminan bloque (no se traducen inline)
_A64_BRANCH_TERMINATORS = frozenset(
    _A64_BCC_TO_C.keys() | {'b', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz'}
)

# Map de función libc → (tipo_retorno, [args con cast usando registros ARM64])
_A64_LIBC_CALL_MAP: dict[str, tuple[str, list[str]]] = {
    'printf':   ('int',     ['(const char*)(uintptr_t)x0', 'x1', 'x2', 'x3', 'x4', 'x5']),
    'fprintf':  ('int',     ['(FILE*)(uintptr_t)x0', '(const char*)(uintptr_t)x1', 'x2']),
    'scanf':    ('int',     ['(const char*)(uintptr_t)x0', '(void*)(uintptr_t)x1']),
    'puts':     ('int',     ['(const char*)(uintptr_t)x0']),
    'putchar':  ('int',     ['(int)x0']),
    'getchar':  ('int',     []),
    'malloc':   ('void*',   ['(size_t)x0']),
    'calloc':   ('void*',   ['(size_t)x0', '(size_t)x1']),
    'realloc':  ('void*',   ['(void*)(uintptr_t)x0', '(size_t)x1']),
    'free':     ('void',    ['(void*)(uintptr_t)x0']),
    'memcpy':   ('void*',   ['(void*)(uintptr_t)x0', '(const void*)(uintptr_t)x1', '(size_t)x2']),
    'memset':   ('void*',   ['(void*)(uintptr_t)x0', '(int)x1', '(size_t)x2']),
    'memmove':  ('void*',   ['(void*)(uintptr_t)x0', '(const void*)(uintptr_t)x1', '(size_t)x2']),
    'strlen':   ('size_t',  ['(const char*)(uintptr_t)x0']),
    'strcpy':   ('char*',   ['(char*)(uintptr_t)x0', '(const char*)(uintptr_t)x1']),
    'strncpy':  ('char*',   ['(char*)(uintptr_t)x0', '(const char*)(uintptr_t)x1', '(size_t)x2']),
    'strcmp':   ('int',     ['(const char*)(uintptr_t)x0', '(const char*)(uintptr_t)x1']),
    'strncmp':  ('int',     ['(const char*)(uintptr_t)x0', '(const char*)(uintptr_t)x1', '(size_t)x2']),
    'strcat':   ('char*',   ['(char*)(uintptr_t)x0', '(const char*)(uintptr_t)x1']),
    'open':     ('int',     ['(const char*)(uintptr_t)x0', '(int)x1', '(int)x2']),
    'openat':   ('int',     ['(int)x0', '(const char*)(uintptr_t)x1', '(int)x2', '(int)x3']),
    'read':     ('ssize_t', ['(int)x0', '(void*)(uintptr_t)x1', '(size_t)x2']),
    'write':    ('ssize_t', ['(int)x0', '(const void*)(uintptr_t)x1', '(size_t)x2']),
    'close':    ('int',     ['(int)x0']),
    'lseek':    ('off_t',   ['(int)x0', '(off_t)x1', '(int)x2']),
    'exit':     ('void',    ['(int)x0']),
    'atoi':     ('int',     ['(const char*)(uintptr_t)x0']),
    'strtol':   ('long',    ['(const char*)(uintptr_t)x0', '(char**)(uintptr_t)x1', '(int)x2']),
    'fopen':    ('FILE*',   ['(const char*)(uintptr_t)x0', '(const char*)(uintptr_t)x1']),
    'fclose':   ('int',     ['(FILE*)(uintptr_t)x0']),
    'fread':    ('size_t',  ['(void*)(uintptr_t)x0', '(size_t)x1', '(size_t)x2', '(FILE*)(uintptr_t)x3']),
    'fwrite':   ('size_t',  ['(const void*)(uintptr_t)x0', '(size_t)x1', '(size_t)x2', '(FILE*)(uintptr_t)x3']),
    'perror':   ('void',    ['(const char*)(uintptr_t)x0']),
    'mmap':     ('void*',   ['(void*)(uintptr_t)x0', '(size_t)x1', '(int)x2', '(int)x3', '(int)x4', '(off_t)x5']),
    'munmap':   ('int',     ['(void*)(uintptr_t)x0', '(size_t)x1']),
    'socket':   ('int',     ['(int)x0', '(int)x1', '(int)x2']),
    'connect':  ('int',     ['(int)x0', '(const struct sockaddr*)(uintptr_t)x1', '(socklen_t)x2']),
    'send':     ('ssize_t', ['(int)x0', '(const void*)(uintptr_t)x1', '(size_t)x2', '(int)x3']),
    'recv':     ('ssize_t', ['(int)x0', '(void*)(uintptr_t)x1', '(size_t)x2', '(int)x3']),
    'fork':     ('pid_t',   []),
    'execve':   ('int',     ['(const char*)(uintptr_t)x0', '(char* const*)(uintptr_t)x1', '(char* const*)(uintptr_t)x2']),
    'waitpid':  ('pid_t',   ['(pid_t)x0', '(int*)(uintptr_t)x1', '(int)x2']),
    'abort':            ('void', []),
    '_exit':            ('void', ['(int)x0']),
    '__stack_chk_fail': ('void', []),
}

_A64_SYSCALL_LIBC_MAP: dict[str, str] = {
    'read': 'read', 'write': 'write', 'close': 'close',
    'exit': 'exit', 'exit_group': 'exit', 'mmap': 'mmap', 'munmap': 'munmap',
    'fork': 'fork', 'execve': 'execve',
}


# ---------------------------------------------------------------------------
# Translator ARM64
# ---------------------------------------------------------------------------

class Arm64Translator(Translator):
    """
    Genera código C desde un CFG AArch64 enriquecido.
    Hereda la infraestructura compartida (trace, memoria simulada, etc.)
    y sobrescribe las partes específicas de arquitectura.
    """

    # ------------------------------------------------------------------
    # Declaraciones de registros y flags
    # ------------------------------------------------------------------

    def _emit_registers(self) -> str:
        lines = ['/* Registros AArch64 simulados como variables globales */']
        for reg in _ARM64_REGS_64:
            lines.append(f'static uint64_t {reg} = 0;')
        return '\n'.join(lines)

    def _emit_flags(self) -> str:
        lines = ['/* Flags NZCV de CPU simulados */']
        for flag in _ARM64_FLAGS:
            lines.append(f'static uint8_t {flag} = 0;')
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Punto de entrada (usa registros ARM64)
    # ------------------------------------------------------------------

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
            f'/* Punto de entrada — sp apunta al stack simulado */\n'
            f'int main(int argc, char *argv[]) {{\n'
            f'{bss_init}'
            f'    sp  = (uint64_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 16);\n'
            f'    sp &= ~(uint64_t)0xFULL;\n'
            f'    x0  = (uint64_t)(uint32_t)argc;\n'
            f'    x1  = (uint64_t)(uintptr_t)argv;\n'
            f'    func_{entry_id}();  /* {fname} @ {entry} */\n'
            f'    __trace_dump("flashback_trace.bin");\n'
            f'    return (int)(uint32_t)x0;\n'
            f'}}'
        )

    # ------------------------------------------------------------------
    # Terminadores de rama ARM64
    # ------------------------------------------------------------------

    def _is_branch_terminator(self, mnemonic: str) -> bool:
        return mnemonic.lower() in _A64_BRANCH_TERMINATORS

    def _jcc_condition(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        if not block.instructions:
            return 'Z'
        last_addr = block.instructions[-1]
        last_insn = cfg.instructions.get(last_addr)
        if last_insn is None:
            return 'Z'
        m   = last_insn.mnemonic.lower()
        ops = last_insn.operands.strip()

        if m == 'cbz':
            reg = ops.split(',')[0].strip()
            return f'{reg} == 0'
        if m == 'cbnz':
            reg = ops.split(',')[0].strip()
            return f'{reg} != 0'
        if m == 'tbz':
            parts = [p.strip() for p in ops.split(',')]
            reg = parts[0] if parts else 'x0'
            bit = parts[1].lstrip('#') if len(parts) > 1 else '0'
            return f'({reg} & (1ULL << {bit})) == 0'
        if m == 'tbnz':
            parts = [p.strip() for p in ops.split(',')]
            reg = parts[0] if parts else 'x0'
            bit = parts[1].lstrip('#') if len(parts) > 1 else '0'
            return f'({reg} & (1ULL << {bit})) != 0'

        condition = _A64_BCC_TO_C.get(m)
        if condition is not None:
            return condition
        return f'Z /* WARNING: condición desconocida para {m} */'

    # ------------------------------------------------------------------
    # Emisión de instrucciones ARM64
    # ------------------------------------------------------------------

    def _emit_instruction(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        lines = []
        if any(a.type == 'trace_point' for a in insn.annotations):
            lines.append(f'    __trace({insn.address}ULL);')
        lines.append(f'    /* {insn.address}: {insn.mnemonic} {insn.operands} */')

        ext_calls    = [a for a in insn.annotations if a.type == 'external_call']
        syscall_anns = [a for a in insn.annotations if a.type == 'syscall']

        if ext_calls and insn.mnemonic in ('bl', 'blr'):
            lines.append(self._emit_external_call(ext_calls[0]))
        elif syscall_anns and insn.mnemonic == 'svc':
            lines.append(self._emit_syscall(syscall_anns[0]))
        elif insn.mnemonic == 'bl':
            lines.append(self._emit_bl(insn, cfg))
        elif insn.mnemonic == 'blr':
            lines.append(f'    /* BLR {insn.operands} — llamada indirecta sin resolver */')
        else:
            lines.append(f'    {self._translate_instruction(insn)}')
        return '\n'.join(lines)

    def _emit_bl(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        """Traduce una llamada directa bl a función interna."""
        ops = insn.operands.strip()
        if ops.startswith('#'):
            ops = ops[1:]
        target = _resolve_direct_target(ops)
        if target and target in self._defined_funcs:
            return f'    func_{target.replace("0x", "")}();'
        return f'    /* BL {insn.operands} — función no definida en este CFG */'

    def _emit_external_call(self, ann) -> str:
        func_name = ann.function_name
        call_info = _A64_LIBC_CALL_MAP.get(func_name)
        if call_info is None:
            return (
                f'    /* EXTERNAL CALL sin prototipo conocido: {func_name}() */\n'
                f'    {{ extern long {func_name}(); '
                f'x0 = (uint64_t)(long){func_name}('
                f'(long)x0, (long)x1, (long)x2, '
                f'(long)x3, (long)x4, (long)x5); }}'
            )
        ret_type, args = call_info
        args_str = ', '.join(args)
        if ret_type == 'void':
            return f'    {func_name}({args_str});'
        return f'    x0 = (uint64_t)(uintptr_t){func_name}({args_str});'

    def _emit_syscall(self, ann) -> str:
        syscall_name = ann.syscall_name or 'unknown'
        libc_func = _A64_SYSCALL_LIBC_MAP.get(syscall_name)
        if libc_func and libc_func in _A64_LIBC_CALL_MAP:
            fake_ann = ExternalCallAnnotation(added_by='translator', function_name=libc_func)
            return self._emit_external_call(fake_ann)
        num = ann.syscall_number if ann.syscall_number >= 0 else 'x8'
        return (
            f'    /* SYSCALL portable: {syscall_name} (num={ann.syscall_number}) */\n'
            f'    x0 = (uint64_t)syscall((long){num}, '
            f'(long)x0, (long)x1, (long)x2, (long)x3, (long)x4, (long)x5);'
        )

    def _translate_instruction(self, insn: Instruction) -> str:
        m   = insn.mnemonic
        ops = insn.operands

        if m == 'nop':
            return '/* nop */'
        if m in ('ret', 'retaa', 'retab'):
            return 'return;'
        if m in ('hlt', 'brk', 'udf'):
            return 'abort();  /* hlt/brk/udf */'

        # Movimientos
        if m in ('mov', 'orr') and ',' in ops:
            dst, src = _a64_split2(ops)
            if dst and src:
                c_s = _a64_reg_to_c(src)
                if c_s is not None:
                    w = _a64_reg_write(dst, c_s)
                    if w is not None:
                        return w
        if m == 'movz':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_s = _a64_imm(src)
                if c_s is not None:
                    w = _a64_reg_write(dst, c_s)
                    if w is not None:
                        return w
        if m == 'movk':
            # movk inserta 16 bits en una posición; modelamos como UNSUPPORTED
            # (requiere conocer el shift amount: "movk x0, #val, lsl #shift")
            dst, rest = _a64_split2(ops)
            return f'/* movk {ops} — inmediato parcial, no traducido */'
        if m == 'movn':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_s = _a64_imm(src)
                if c_s is not None:
                    w = _a64_reg_write(dst, f'~(uint64_t)({c_s})')
                    if w is not None:
                        return w
        if m == 'mvn':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_s = _a64_reg_to_c(src)
                if c_s is not None:
                    w = _a64_reg_write(dst, f'~(uint64_t)({c_s})')
                    if w is not None:
                        return w

        # Aritmética
        if m in ('add', 'adds'):
            return _a64_alu3(ops, '+')
        if m in ('sub', 'subs'):
            return _a64_alu3(ops, '-')
        if m in ('and', 'ands'):
            return _a64_alu3(ops, '&')
        if m == 'orr':
            return _a64_alu3(ops, '|')
        if m == 'eor':
            return _a64_alu3(ops, '^')
        if m == 'bic':
            parts = [p.strip() for p in ops.split(',', 2)]
            if len(parts) == 3:
                c_a = _a64_reg_to_c(parts[1])
                c_b = _a64_reg_to_c(parts[2])
                if c_a and c_b:
                    w = _a64_reg_write(parts[0], f'({c_a}) & ~({c_b})')
                    if w:
                        return w
        if m == 'neg':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_s = _a64_reg_to_c(src)
                if c_s:
                    w = _a64_reg_write(dst, f'(uint64_t)(-(int64_t)({c_s}))')
                    if w:
                        return w
        if m == 'mul':
            return _a64_alu3(ops, '*')
        if m == 'madd':
            parts = [p.strip() for p in ops.split(',', 3)]
            if len(parts) == 4:
                c_n = _a64_reg_to_c(parts[1])
                c_m = _a64_reg_to_c(parts[2])
                c_a = _a64_reg_to_c(parts[3])
                if c_n and c_m and c_a:
                    w = _a64_reg_write(parts[0], f'({c_n}) * ({c_m}) + ({c_a})')
                    if w:
                        return w
        if m == 'msub':
            parts = [p.strip() for p in ops.split(',', 3)]
            if len(parts) == 4:
                c_n = _a64_reg_to_c(parts[1])
                c_m = _a64_reg_to_c(parts[2])
                c_a = _a64_reg_to_c(parts[3])
                if c_n and c_m and c_a:
                    w = _a64_reg_write(parts[0], f'({c_a}) - ({c_n}) * ({c_m})')
                    if w:
                        return w
        if m == 'udiv':
            dst, src1, src2 = _a64_split3(ops)
            if dst and src1 and src2:
                c_n = _a64_reg_to_c(src1)
                c_d = _a64_reg_to_c(src2)
                if c_n and c_d:
                    w = _a64_reg_write(dst, f'({c_d}) ? ({c_n}) / ({c_d}) : 0')
                    if w:
                        return w
        if m == 'sdiv':
            dst, src1, src2 = _a64_split3(ops)
            if dst and src1 and src2:
                c_n = _a64_reg_to_c(src1)
                c_d = _a64_reg_to_c(src2)
                if c_n and c_d:
                    w = _a64_reg_write(
                        dst,
                        f'({c_d}) ? (uint64_t)((int64_t)({c_n}) / (int64_t)({c_d})) : 0')
                    if w:
                        return w

        # Shifts
        if m == 'lsl':
            return _a64_alu3(ops, '<<')
        if m == 'lsr':
            return _a64_alu3(ops, '>>')
        if m == 'asr':
            dst, src1, src2 = _a64_split3(ops)
            if dst and src1 and src2:
                c_v = _a64_reg_to_c(src1)
                c_s = _a64_reg_to_c(src2)
                if c_v and c_s:
                    w = _a64_reg_write(dst, f'(uint64_t)((int64_t)({c_v}) >> ({c_s} & 63))')
                    if w:
                        return w
        if m == 'ror':
            dst, src1, src2 = _a64_split3(ops)
            if dst and src1 and src2:
                c_v = _a64_reg_to_c(src1)
                c_s = _a64_reg_to_c(src2)
                if c_v and c_s:
                    w = _a64_reg_write(
                        dst,
                        f'(({c_v}) >> ({c_s} & 63)) | (({c_v}) << (64 - ({c_s} & 63)))')
                    if w:
                        return w

        # Comparación
        if m == 'cmp':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_a = _a64_reg_to_c(dst)
                c_b = _a64_reg_to_c(src)
                if c_a and c_b:
                    return (f'{{ int64_t __a=(int64_t)({c_a}), __b=(int64_t)({c_b}), __r=__a-__b; '
                            f'Z=(__r==0); N=(__r<0); '
                            f'C=((uint64_t)({c_a})>=(uint64_t)({c_b})); '
                            f'V=(uint8_t)((__a<0)!=(__b<0)&&(__r<0)!=(__a<0)); }}')
        if m == 'cmn':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_a = _a64_reg_to_c(dst)
                c_b = _a64_reg_to_c(src)
                if c_a and c_b:
                    return (f'{{ int64_t __a=(int64_t)({c_a}), __b=(int64_t)({c_b}), __r=__a+__b; '
                            f'Z=(__r==0); N=(__r<0); '
                            f'C=((uint64_t)__r<(uint64_t)({c_a})); '
                            f'V=(uint8_t)((__a>0&&__b>0&&__r<0)||(__a<0&&__b<0&&__r>=0)); }}')
        if m == 'tst':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_a = _a64_reg_to_c(dst)
                c_b = _a64_reg_to_c(src)
                if c_a and c_b:
                    return f'{{ int64_t __t=(int64_t)(({c_a})&({c_b})); Z=(__t==0); N=(__t<0); C=0; V=0; }}'

        # Carga de dirección
        if m in ('adr', 'adrp'):
            dst, src = _a64_split2(ops)
            if dst and src:
                imm = _a64_imm(src)
                if imm:
                    w = _a64_reg_write(dst, imm)
                    if w:
                        return w

        # Extensión de signo
        if m == 'sxtw':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_s = _a64_reg_to_c(src)
                if c_s:
                    w = _a64_reg_write(dst, f'(uint64_t)(int64_t)(int32_t)({c_s})')
                    if w:
                        return w
        if m == 'uxtw':
            dst, src = _a64_split2(ops)
            if dst and src:
                c_s = _a64_reg_to_c(src)
                if c_s:
                    w = _a64_reg_write(dst, f'(uint64_t)(uint32_t)({c_s})')
                    if w:
                        return w

        # Loads
        if m in ('ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw'):
            return _a64_emit_load(m, ops)
        # Stores
        if m in ('str', 'strb', 'strh'):
            return _a64_emit_store(m, ops)
        # Load/Store pair
        if m in ('ldp', 'ldpsw'):
            return _a64_emit_ldp(ops, signed=(m == 'ldpsw'))
        if m == 'stp':
            return _a64_emit_stp(ops)

        # Condicionales set
        if m == 'cset':
            parts = [p.strip() for p in ops.split(',', 1)]
            if len(parts) == 2:
                reg, cond_str = parts
                cond = _A64_BCC_TO_C.get(f'b.{cond_str.lower()}', '0')
                w = _a64_reg_write(reg, f'(uint64_t)({cond})')
                if w:
                    return w

        return (
            f'/* UNSUPPORTED: {m} {ops} */\n'
            f'    fprintf(stderr, "UNSUPPORTED: {m} {ops}\\n");\n'
            f'    abort();'
        )


# ---------------------------------------------------------------------------
# Helpers de operandos ARM64
# ---------------------------------------------------------------------------

def _a64_split2(ops: str) -> tuple[str | None, str | None]:
    """Divide 'dst, src' en (dst, src). Respeta comas dentro de corchetes."""
    # Busca la primera coma fuera de corchetes
    depth = 0
    for i, c in enumerate(ops):
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
        elif c == ',' and depth == 0:
            return ops[:i].strip(), ops[i+1:].strip()
    return None, None


def _a64_split3(ops: str) -> tuple[str | None, str | None, str | None]:
    """Divide 'dst, src1, src2'."""
    dst, rest = _a64_split2(ops)
    if dst is None or rest is None:
        return None, None, None
    src1, src2 = _a64_split2(rest)
    return dst, src1, src2


def _a64_imm(operand: str) -> str | None:
    """Convierte un inmediato ARM64 ('#N' o '0xN') a expresión C uint64_t."""
    o = operand.strip()
    if o.startswith('#'):
        o = o[1:]
    try:
        if o.startswith('0x') or o.startswith('-0x'):
            v = int(o, 16)
        elif o.lstrip('-').isdigit():
            v = int(o)
        else:
            return None
        return f'((uint64_t){v}ULL)' if v >= 0 else f'((int64_t){v}LL)'
    except ValueError:
        return None


def _a64_reg_to_c(operand: str) -> str | None:
    """Expresión C de lectura de un operando ARM64 (registro o inmediato)."""
    o = operand.strip()
    # Quitar suffixes de shift: "x0, lsl #2" → tomar solo "x0"
    if ',' in o:
        o = o.split(',')[0].strip()
    if o.lower() in ('xzr', 'wzr'):
        return '((uint64_t)0)'
    if o in _ARM64_REGS_64 or o.lower() in _ARM64_REGS_64:
        return o.lower()
    lo = o.lower()
    if lo in _ARM64_REGS_32_TO_64:
        return f'(uint32_t){_ARM64_REGS_32_TO_64[lo]}'
    return _a64_imm(o)


def _a64_reg_write(dst: str, src_expr: str) -> str | None:
    """Genera sentencia C que escribe src_expr en el registro dst."""
    d = dst.strip().lower()
    if d in ('xzr', 'wzr'):
        return ''  # escritura al registro cero se descarta
    if d in _ARM64_REGS_64:
        return f'{d} = {src_expr};'
    if d in _ARM64_REGS_32_TO_64:
        base = _ARM64_REGS_32_TO_64[d]
        return f'{base} = (uint64_t)(uint32_t)({src_expr});'
    return None


def _a64_alu3(ops: str, op: str) -> str:
    """Traduce operación ALU de 3 operandos: dst = src1 op src2."""
    dst, src1, src2 = _a64_split3(ops)
    if not dst or not src1 or not src2:
        return f'/* UNSUPPORTED alu3 {ops} */ abort();'
    c_a = _a64_reg_to_c(src1)
    c_b = _a64_reg_to_c(src2)
    if not c_a or not c_b:
        return f'/* UNSUPPORTED alu3 {ops} */ abort();'
    # Para shifts, usar & 63 para limitar el desplazamiento
    if op in ('<<', '>>'):
        expr = f'({c_a}) {op} (({c_b}) & 63)'
    else:
        expr = f'({c_a}) {op} ({c_b})'
    w = _a64_reg_write(dst, expr)
    return w if w else f'/* UNSUPPORTED alu3 dst={dst} */'


def _a64_parse_mem_operand(mem: str) -> tuple[str | None, str | None, bool, bool]:
    """
    Parsea el operando de memoria ARM64.
    Formatos:
      [xN]                  → base=xN, offset=0, pre=False, post=False
      [xN, #off]            → base=xN, offset=#off
      [xN, #off]!           → base=xN, offset=#off, pre=True  (pre-index)
      [xN], #off            → base=xN, offset=#off, post=True (post-index)
      [xN, xM]              → base=xN, offset=xM (reg offset)
    Devuelve (base_reg, offset_expr, is_pre_index, is_post_index)
    """
    s = mem.strip()
    post_offset = None
    pre_index = False
    post_index = False

    # Post-index: "[xN], #off"
    if '],' in s:
        bracket_part, post_part = s.split('],', 1)
        s = bracket_part.strip() + ']'
        post_offset = post_part.strip()
        post_index = True

    # Pre-index: "[xN, #off]!"
    if s.endswith('!'):
        s = s[:-1].strip()
        pre_index = True

    # Extraer contenido del bracket
    if not (s.startswith('[') and s.endswith(']')):
        return None, None, False, False
    inner = s[1:-1].strip()

    parts = [p.strip() for p in inner.split(',', 1)]
    base = parts[0] if parts else None
    offset_raw = parts[1] if len(parts) > 1 else None

    if offset_raw is None:
        offset_expr = '0'
    else:
        imm = _a64_imm(offset_raw)
        if imm:
            offset_expr = imm
        else:
            reg_c = _a64_reg_to_c(offset_raw)
            offset_expr = reg_c if reg_c else '0'

    if post_index and post_offset:
        pass  # post_offset se aplica en el caller vía el último elemento de la tupla

    return base, offset_expr, pre_index, post_index, post_offset  # type: ignore


def _a64_emit_load(mnemonic: str, ops: str) -> str:
    """Genera código C para instrucciones de carga ARM64."""
    dst, mem_str = _a64_split2(ops)
    if not dst or not mem_str:
        return f'/* UNSUPPORTED load: {mnemonic} {ops} */ abort();'

    # Parsear operando de memoria
    result = _a64_parse_mem_operand(mem_str)
    if len(result) == 5:
        base, offset_expr, pre_index, post_index, post_offset = result
    else:
        base, offset_expr, pre_index, post_index = result
        post_offset = None

    if not base:
        return f'/* UNSUPPORTED load mem: {mem_str} */ abort();'

    base_c = _a64_reg_to_c(base)
    if not base_c:
        return f'/* UNSUPPORTED load base: {base} */ abort();'

    size_map = {
        'ldr': 64, 'ldrb': 8, 'ldrh': 16, 'ldrsb': 8, 'ldrsh': 16, 'ldrsw': 32,
    }
    size = size_map.get(mnemonic, 64)
    signed = mnemonic in ('ldrsb', 'ldrsh', 'ldrsw')

    lines = []
    addr_expr = f'({base_c}) + ({offset_expr})' if offset_expr != '0' else f'({base_c})'

    if pre_index:
        # Actualizar base antes de la carga
        base_write = _a64_reg_write(base, addr_expr)
        if base_write:
            lines.append(f'    {base_write}')
        addr_expr = f'({base_c})'

    if signed:
        ity = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t'}[size]
        load_expr = f'(uint64_t)(int64_t)({ity})SIM_READ{size}({addr_expr})'
    else:
        load_expr = f'(uint64_t)SIM_READ{size}({addr_expr})'

    w = _a64_reg_write(dst, load_expr)
    if w:
        lines.append(f'    {w}')

    if post_index and post_offset:
        post_imm = _a64_imm(post_offset)
        if post_imm:
            base_update = _a64_reg_write(base, f'({base_c}) + {post_imm}')
            if base_update:
                lines.append(f'    {base_update}')

    return '\n'.join(lines) if lines else f'/* UNSUPPORTED load: {mnemonic} {ops} */'


def _a64_emit_store(mnemonic: str, ops: str) -> str:
    """Genera código C para instrucciones de escritura ARM64."""
    src, mem_str = _a64_split2(ops)
    if not src or not mem_str:
        return f'/* UNSUPPORTED store: {mnemonic} {ops} */ abort();'

    result = _a64_parse_mem_operand(mem_str)
    if len(result) == 5:
        base, offset_expr, pre_index, post_index, post_offset = result
    else:
        base, offset_expr, pre_index, post_index = result
        post_offset = None

    if not base:
        return f'/* UNSUPPORTED store mem: {mem_str} */ abort();'

    base_c = _a64_reg_to_c(base)
    src_c  = _a64_reg_to_c(src)
    if not base_c or not src_c:
        return f'/* UNSUPPORTED store reg: {base}/{src} */ abort();'

    size_map = {'str': 64, 'strb': 8, 'strh': 16}
    size = size_map.get(mnemonic, 64)

    lines = []
    addr_expr = f'({base_c}) + ({offset_expr})' if offset_expr != '0' else f'({base_c})'

    if pre_index:
        base_write = _a64_reg_write(base, addr_expr)
        if base_write:
            lines.append(f'    {base_write}')
        addr_expr = f'({base_c})'

    lines.append(f'    SIM_WRITE{size}({addr_expr}, {src_c});')

    if post_index and post_offset:
        post_imm = _a64_imm(post_offset)
        if post_imm:
            base_update = _a64_reg_write(base, f'({base_c}) + {post_imm}')
            if base_update:
                lines.append(f'    {base_update}')

    return '\n'.join(lines) if lines else f'/* UNSUPPORTED store: {mnemonic} {ops} */'


def _a64_emit_ldp(ops: str, signed: bool = False) -> str:
    """Genera código C para ldp (load pair)."""
    # Formato: "x29, x30, [sp, #N]" o "x29, x30, [sp], #N" o "x29, x30, [sp, #-N]!"
    parts = [p.strip() for p in ops.split(',', 2)]
    if len(parts) < 3:
        return f'/* UNSUPPORTED ldp: {ops} */ abort();'

    r1, r2 = parts[0], parts[1]
    mem_raw = parts[2]

    result = _a64_parse_mem_operand(mem_raw)
    if len(result) == 5:
        base, offset_expr, pre_index, post_index, post_offset = result
    else:
        base, offset_expr, pre_index, post_index = result
        post_offset = None

    if not base:
        return f'/* UNSUPPORTED ldp mem: {mem_raw} */ abort();'

    base_c = _a64_reg_to_c(base)
    if not base_c:
        return f'/* UNSUPPORTED ldp base: {base} */ abort();'

    lines = []
    addr_expr = f'({base_c}) + ({offset_expr})' if offset_expr != '0' else f'({base_c})'

    if pre_index:
        bw = _a64_reg_write(base, addr_expr)
        if bw:
            lines.append(f'    {bw}')
        addr_expr = f'({base_c})'

    size = 64
    load1 = f'(uint64_t)SIM_READ{size}({addr_expr})'
    load2 = f'(uint64_t)SIM_READ{size}(({addr_expr}) + {size // 8})'
    if signed:
        load1 = f'(uint64_t)(int64_t)(int32_t)SIM_READ32({addr_expr})'
        load2 = f'(uint64_t)(int64_t)(int32_t)SIM_READ32(({addr_expr}) + 4)'

    w1 = _a64_reg_write(r1, load1)
    w2 = _a64_reg_write(r2, load2)
    if w1:
        lines.append(f'    {w1}')
    if w2:
        lines.append(f'    {w2}')

    if post_index and post_offset:
        post_imm = _a64_imm(post_offset)
        if post_imm:
            bw = _a64_reg_write(base, f'({base_c}) + {post_imm}')
            if bw:
                lines.append(f'    {bw}')

    return '\n'.join(lines) if lines else f'/* UNSUPPORTED ldp: {ops} */'


def _a64_emit_stp(ops: str) -> str:
    """Genera código C para stp (store pair)."""
    parts = [p.strip() for p in ops.split(',', 2)]
    if len(parts) < 3:
        return f'/* UNSUPPORTED stp: {ops} */ abort();'

    r1, r2 = parts[0], parts[1]
    mem_raw = parts[2]

    result = _a64_parse_mem_operand(mem_raw)
    if len(result) == 5:
        base, offset_expr, pre_index, post_index, post_offset = result
    else:
        base, offset_expr, pre_index, post_index = result
        post_offset = None

    if not base:
        return f'/* UNSUPPORTED stp mem: {mem_raw} */ abort();'

    base_c = _a64_reg_to_c(base)
    r1_c   = _a64_reg_to_c(r1)
    r2_c   = _a64_reg_to_c(r2)
    if not base_c or not r1_c or not r2_c:
        return f'/* UNSUPPORTED stp regs */'

    lines = []
    addr_expr = f'({base_c}) + ({offset_expr})' if offset_expr != '0' else f'({base_c})'

    if pre_index:
        bw = _a64_reg_write(base, addr_expr)
        if bw:
            lines.append(f'    {bw}')
        addr_expr = f'({base_c})'

    lines.append(f'    SIM_WRITE64({addr_expr}, {r1_c});')
    lines.append(f'    SIM_WRITE64(({addr_expr}) + 8, {r2_c});')

    if post_index and post_offset:
        post_imm = _a64_imm(post_offset)
        if post_imm:
            bw = _a64_reg_write(base, f'({base_c}) + {post_imm}')
            if bw:
                lines.append(f'    {bw}')

    return '\n'.join(lines) if lines else f'/* UNSUPPORTED stp: {ops} */'
