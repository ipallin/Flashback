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
import re

from flashback.core.translator import (
    Translator, _resolve_direct_target, _split_operands,
)
from flashback.core.models import EnrichedCFG, BasicBlock, Instruction
from flashback.arch.arm32.instruction_sem import ARM32_COND_TO_C

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes ARM32
# ---------------------------------------------------------------------------

_ARM32_REGS = [f'r{i}' for i in range(16)]   # r0..r15

_ARM32_FLAGS = ['N', 'Z', 'C', 'V']

_ARM32_ALIASES = {
    'sp': 'r13', 'lr': 'r14', 'pc': 'r15',
    'ip': 'r12', 'fp': 'r11', 'sl': 'r10',
}

# Condiciones de rama ARM32 → expresión C
_A32_BCC_TO_C: dict[str, str] = ARM32_COND_TO_C

# Terminadores de bloque (ramas condicionales e incondicionales)
_A32_BRANCH_TERMINATORS = frozenset(
    {'b', 'bx', 'bl', 'blx'} | {f'b{c}' for c in ARM32_COND_TO_C}
)

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
        return '\n'.join(lines)

    def _emit_flags(self) -> str:
        lines = ['/* Flags NZCV ARM32 */']
        for flag in _ARM32_FLAGS:
            lines.append(f'static uint8_t {flag} = 0;')
        return '\n'.join(lines)

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

    def _is_branch_terminator(self, mnemonic: str) -> bool:
        return mnemonic.lower() in _A32_BRANCH_TERMINATORS

    def _jcc_condition(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        if not block.instructions:
            return 'Z'
        last_insn = cfg.instructions.get(block.instructions[-1])
        if last_insn is None:
            return 'Z'
        m = last_insn.mnemonic.lower()
        # Extraer sufijo de condición del mnemónico (p.ej. 'beq' → 'eq')
        for suffix in sorted(ARM32_COND_TO_C.keys(), key=len, reverse=True):
            if m.endswith(suffix) and len(m) > len(suffix):
                cond = ARM32_COND_TO_C[suffix]
                return cond
        # cbz/cbnz estilo: en Thumb2, no en ARM clásico; tratar por si acaso
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
        if ext_calls and m in ('bl', 'blx'):
            lines.append(self._emit_external_call(ext_calls[0]))
        elif syscall_anns and m in ('svc', 'swi'):
            lines.append(self._emit_syscall(syscall_anns[0]))
        elif m in ('bl', 'blx'):
            lines.append(self._emit_call(insn, cfg))
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
        # Llamada directa
        o = ops.lstrip('#')
        target = _resolve_direct_target(o)
        if target and target in self._defined_funcs:
            return f'    func_{target.replace("0x", "")}();'
        # Llamada indirecta a registro
        if ops and not ops.startswith('0x'):
            reg = _a32_resolve_reg(ops)
            return f'    /* INDIRECT CALL: bl {ops} (r={reg}) — sin resolver */'
        return f'    /* CALL {ops} — función no definida en este CFG */'

    def _translate_instruction(self, insn: Instruction) -> str:
        m   = insn.mnemonic
        ops = insn.operands

        if m == 'nop':
            return '/* nop */'
        if m in ('bkpt', 'udf'):
            return 'abort();'

        # Instrucción con sufijo de condición: envolverla en if (cond)
        base_m, cond_c = _strip_condition(m)
        if cond_c and base_m != m:
            inner = self._translate_arm32_base(base_m, ops)
            if inner and not inner.startswith('/* UNSUPPORTED'):
                return f'if ({cond_c}) {{ {inner} }}'
            return inner or f'/* UNSUPPORTED: {m} {ops} */'

        return self._translate_arm32_base(m, ops)

    def _translate_arm32_base(self, m: str, ops: str) -> str:
        """Traduce un mnemónico ARM32 sin sufijo de condición."""
        if m == 'nop':
            return '/* nop */'
        if m == 'bx' and 'lr' in ops:
            return 'return;'
        if m in ('pop', 'ldmia', 'ldmfd') and 'pc' in ops:
            # pop {r4, r5, pc} → restaurar registros y return
            regs = _parse_reglist(ops)
            stmts = []
            for reg in regs:
                canon = _ARM32_ALIASES.get(reg, reg)
                if canon == 'r15':  # pc
                    stmts.append('return;')
                else:
                    stmts.append(f'{canon} = SIM_READ32(r13); r13 += 4;')
            return ' '.join(stmts)
        if m in ('push', 'stmfd', 'stmdb'):
            regs = _parse_reglist(ops)
            stmts = []
            for reg in reversed(regs):
                canon = _ARM32_ALIASES.get(reg, reg)
                stmts.append(f'r13 -= 4; SIM_WRITE32(r13, {canon});')
            return ' '.join(stmts) if stmts else '/* push {} */'
        if m in ('pop', 'ldmia', 'ldmfd'):
            regs = _parse_reglist(ops)
            stmts = []
            for reg in regs:
                canon = _ARM32_ALIASES.get(reg, reg)
                stmts.append(f'{canon} = SIM_READ32(r13); r13 += 4;')
            return ' '.join(stmts) if stmts else '/* pop {} */'
        if m in ('stmia', 'stmea'):
            # stmia rN!, {r0, r1, ...} or stmia rN, {r0, r1, ...}
            base_reg, regs = _parse_stm_base_regs(ops)
            if base_reg and regs:
                stmts = []
                for reg in regs:
                    canon = _ARM32_ALIASES.get(reg, reg)
                    stmts.append(f'SIM_WRITE32({base_reg}, {canon}); {base_reg} += 4;')
                return ' '.join(stmts)
        if m in ('ldmda', 'ldmdb'):
            base_reg, regs = _parse_stm_base_regs(ops)
            if base_reg and regs:
                stmts = []
                for reg in reversed(regs):
                    canon = _ARM32_ALIASES.get(reg, reg)
                    stmts.append(f'{base_reg} -= 4; {canon} = SIM_READ32({base_reg});')
                return ' '.join(stmts)
        if m in ('mov', 'movs'):
            dst, src = _split_operands(ops)
            if dst and src:
                canon_d = _ARM32_ALIASES.get(dst.strip(), dst.strip())
                c_s = _a32_reg_to_c(src)
                if c_s and canon_d in _ARM32_REGS:
                    return f'{canon_d} = (uint32_t){c_s};'
        if m in ('movw',):
            dst, src = _split_operands(ops)
            if dst and src:
                canon_d = _ARM32_ALIASES.get(dst.strip(), dst.strip())
                c_s = _a32_reg_to_c(src)
                if c_s and canon_d in _ARM32_REGS:
                    return f'{canon_d} = ({canon_d} & 0xFFFF0000U) | ((uint32_t){c_s} & 0xFFFFU);'
        if m in ('movt',):
            dst, src = _split_operands(ops)
            if dst and src:
                canon_d = _ARM32_ALIASES.get(dst.strip(), dst.strip())
                c_s = _a32_reg_to_c(src)
                if c_s and canon_d in _ARM32_REGS:
                    return f'{canon_d} = ({canon_d} & 0x0000FFFFU) | (((uint32_t){c_s} & 0xFFFFU) << 16);'
        if m in ('mvn', 'mvns'):
            dst, src = _split_operands(ops)
            if dst and src:
                canon_d = _ARM32_ALIASES.get(dst.strip(), dst.strip())
                c_s = _a32_reg_to_c(src)
                if c_s and canon_d in _ARM32_REGS:
                    return f'{canon_d} = ~(uint32_t)({c_s});'
        if m in ('add', 'adds', 'adc', 'adcs'):
            return _a32_alu3(ops, '+')
        if m in ('sub', 'subs', 'sbc', 'sbcs', 'rsb', 'rsbs'):
            return _a32_alu3(ops, '-')
        if m in ('and', 'ands'):
            return _a32_alu3(ops, '&')
        if m in ('orr', 'orrs'):
            return _a32_alu3(ops, '|')
        if m in ('eor', 'eors'):
            return _a32_alu3(ops, '^')
        if m in ('bic', 'bics'):
            dst, src1, src2 = _a32_split3(ops)
            c_d = _ARM32_ALIASES.get(dst, dst) if dst else None
            c_1 = _a32_reg_to_c(src1) if src1 else None
            c_2 = _a32_reg_to_c(src2) if src2 else None
            if c_d and c_1 and c_2 and c_d in _ARM32_REGS:
                return f'{c_d} = (uint32_t)({c_1}) & ~(uint32_t)({c_2});'
        if m in ('lsl', 'lsls', 'asl'):
            dst, src1, src2 = _a32_split3(ops)
            c_d = _ARM32_ALIASES.get(dst, dst) if dst else None
            c_1 = _a32_reg_to_c(src1) if src1 else None
            c_2 = _a32_reg_to_c(src2) if src2 else None
            if c_d and c_1 and c_2 and c_d in _ARM32_REGS:
                return f'{c_d} = (uint32_t)({c_1}) << ((uint32_t)({c_2}) & 31);'
        if m in ('lsr', 'lsrs'):
            dst, src1, src2 = _a32_split3(ops)
            c_d = _ARM32_ALIASES.get(dst, dst) if dst else None
            c_1 = _a32_reg_to_c(src1) if src1 else None
            c_2 = _a32_reg_to_c(src2) if src2 else None
            if c_d and c_1 and c_2 and c_d in _ARM32_REGS:
                return f'{c_d} = (uint32_t)({c_1}) >> ((uint32_t)({c_2}) & 31);'
        if m in ('asr', 'asrs'):
            dst, src1, src2 = _a32_split3(ops)
            c_d = _ARM32_ALIASES.get(dst, dst) if dst else None
            c_1 = _a32_reg_to_c(src1) if src1 else None
            c_2 = _a32_reg_to_c(src2) if src2 else None
            if c_d and c_1 and c_2 and c_d in _ARM32_REGS:
                return f'{c_d} = (uint32_t)((int32_t)({c_1}) >> ((uint32_t)({c_2}) & 31));'
        if m in ('mul', 'muls'):
            dst, src1, src2 = _a32_split3(ops)
            c_d = _ARM32_ALIASES.get(dst, dst) if dst else None
            c_1 = _a32_reg_to_c(src1) if src1 else None
            c_2 = _a32_reg_to_c(src2) if src2 else None
            if c_d and c_1 and c_2 and c_d in _ARM32_REGS:
                return f'{c_d} = (uint32_t)((uint32_t)({c_1}) * (uint32_t)({c_2}));'
        if m in ('cmp', 'cmps'):
            dst, src = _split_operands(ops)
            c_d = _a32_reg_to_c(dst) if dst else None
            c_s = _a32_reg_to_c(src) if src else None
            if c_d and c_s:
                return (f'{{ int32_t __a=(int32_t)({c_d}),__b=(int32_t)({c_s}),__r=__a-__b; '
                        f'Z=(__r==0); N=(__r<0); '
                        f'C=((uint32_t)({c_d})>=(uint32_t)({c_s})); '
                        f'V=(uint8_t)((__a<0)!=(__b<0)&&(__r<0)!=(__a<0)); }}')
        if m in ('cmn',):
            dst, src = _split_operands(ops)
            c_d = _a32_reg_to_c(dst) if dst else None
            c_s = _a32_reg_to_c(src) if src else None
            if c_d and c_s:
                return (f'{{ int32_t __r=(int32_t)({c_d})+(int32_t)({c_s}); '
                        f'Z=(__r==0); N=(__r<0); }}')
        if m in ('tst',):
            dst, src = _split_operands(ops)
            c_d = _a32_reg_to_c(dst) if dst else None
            c_s = _a32_reg_to_c(src) if src else None
            if c_d and c_s:
                return (f'{{ int32_t __t=(int32_t)(({c_d})&({c_s})); '
                        f'Z=(__t==0); N=(__t<0); }}')
        if m in ('ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrt', 'ldrbt'):
            return _a32_emit_load(m, ops)
        if m in ('str', 'strb', 'strh', 'strt', 'strbt'):
            return _a32_emit_store(m, ops)

        return (
            f'/* UNSUPPORTED: {m} {ops} */\n'
            f'    fprintf(stderr, "UNSUPPORTED: {m} {ops}\\n");\n'
            f'    abort();'
        )


# ---------------------------------------------------------------------------
# Helpers privados ARM32
# ---------------------------------------------------------------------------

_ARM32_REGS_SET = frozenset(_ARM32_REGS)


def _a32_resolve_reg(name: str) -> str:
    n = name.strip()
    return _ARM32_ALIASES.get(n, n)


def _a32_reg_to_c(operand: str) -> str | None:
    o = operand.strip()
    o = _ARM32_ALIASES.get(o, o)
    if o in _ARM32_REGS_SET:
        return o
    # Inmediato con # o sin él
    if o.startswith('#'):
        o = o[1:]
    try:
        if o.startswith('0x') or o.startswith('-0x'):
            return f'((uint32_t){o}U)'
        if o.lstrip('-').isdigit():
            v = int(o)
            return f'((int32_t){v})' if v < 0 else f'((uint32_t){v}U)'
    except ValueError:
        pass
    return None


def _a32_split3(ops: str) -> tuple[str | None, str | None, str | None]:
    """Divide 'dst, src1, src2' en tres partes (para instrucciones ALU de 3 operandos)."""
    parts = [p.strip() for p in ops.split(',', 2)]
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[0], parts[1]  # forma de 2 operandos: dst = dst OP src
    return None, None, None


def _a32_alu3(ops: str, op: str) -> str:
    dst, src1, src2 = _a32_split3(ops)
    c_d = _ARM32_ALIASES.get(dst, dst) if dst else None
    c_1 = _a32_reg_to_c(src1) if src1 else None
    c_2 = _a32_reg_to_c(src2) if src2 else None
    if c_d and c_1 and c_2 and c_d in _ARM32_REGS_SET:
        return f'{c_d} = (uint32_t)((uint32_t)({c_1}) {op} (uint32_t)({c_2}));'
    return f'/* UNSUPPORTED alu3 {op} {ops} */'


def _parse_reglist(ops: str) -> list[str]:
    """Extrae la lista de registros de '{r0, r1, lr}' o '{r0-r3, lr}'."""
    m = re.search(r'\{([^}]+)\}', ops)
    if not m:
        return []
    inner = m.group(1)
    regs = []
    for part in inner.split(','):
        part = part.strip()
        if '-' in part and not part.startswith('-'):
            # rango: r4-r7
            a, b = part.split('-', 1)
            a, b = a.strip(), b.strip()
            a_n = _ARM32_ALIASES.get(a, a)
            b_n = _ARM32_ALIASES.get(b, b)
            try:
                ai = int(a_n[1:]) if a_n.startswith('r') else int(a_n)
                bi = int(b_n[1:]) if b_n.startswith('r') else int(b_n)
                regs.extend([f'r{i}' for i in range(ai, bi + 1)])
            except ValueError:
                regs.append(a)
        else:
            regs.append(part)
    return regs


def _parse_stm_base_regs(ops: str) -> tuple[str | None, list[str]]:
    """Extrae el registro base y la lista de registros para stm/ldm."""
    m = re.match(r'(\w+)!?,\s*\{([^}]+)\}', ops)
    if not m:
        return None, []
    base_raw = m.group(1).strip().rstrip('!')
    base = _ARM32_ALIASES.get(base_raw, base_raw)
    regs = _parse_reglist(m.group(0))
    return base, regs


def _a32_parse_mem_operand(ops: str, skip_first: bool = True) -> tuple[str | None, str | None]:
    """
    Extrae el operando de memoria ARM32.
    Formato: 'rDst, [rBase, #offset]' o 'rSrc, [rBase, #offset]'.
    Retorna (reg_data, addr_expr).
    """
    parts = ops.split(',', 1)
    if len(parts) != 2:
        return None, None
    reg_data = _ARM32_ALIASES.get(parts[0].strip(), parts[0].strip())
    mem_part = parts[1].strip()
    # Quitar corchetes externos
    if mem_part.startswith('[') and ']' in mem_part:
        end = mem_part.index(']')
        inner = mem_part[1:end].strip()
        # inner puede ser 'r0' o 'r0, #4' o 'r0, r1'
        inner_parts = [p.strip() for p in inner.split(',', 1)]
        base_r = _ARM32_ALIASES.get(inner_parts[0], inner_parts[0])
        if len(inner_parts) == 1:
            return reg_data, base_r
        offset = inner_parts[1]
        if offset.startswith('#'):
            offset = offset[1:]
        try:
            off_val = int(offset, 0)
            if off_val == 0:
                return reg_data, base_r
            sign = '+' if off_val > 0 else '-'
            return reg_data, f'{base_r} {sign} {abs(off_val)}'
        except ValueError:
            off_reg = _ARM32_ALIASES.get(offset, offset)
            return reg_data, f'{base_r} + {off_reg}'
    return None, None


def _a32_emit_load(mnemonic: str, ops: str) -> str:
    reg, addr = _a32_parse_mem_operand(ops)
    if reg is None or addr is None:
        return f'/* UNSUPPORTED: {mnemonic} {ops} */'
    if reg not in _ARM32_REGS_SET:
        return f'/* UNSUPPORTED load dst {reg} */'
    if mnemonic in ('ldrb', 'ldrbt', 'ldrsb'):
        signed = 'b' in mnemonic and 's' in mnemonic
        cast = '(int8_t)' if signed else ''
        return f'{reg} = (uint32_t){cast}SIM_READ8({addr});'
    if mnemonic in ('ldrh', 'ldrsh'):
        signed = 's' in mnemonic
        cast = '(int16_t)' if signed else ''
        return f'{reg} = (uint32_t){cast}SIM_READ16({addr});'
    return f'{reg} = SIM_READ32({addr});'


def _a32_emit_store(mnemonic: str, ops: str) -> str:
    reg, addr = _a32_parse_mem_operand(ops)
    if reg is None or addr is None:
        return f'/* UNSUPPORTED: {mnemonic} {ops} */'
    c_r = _a32_reg_to_c(reg)
    if c_r is None:
        return f'/* UNSUPPORTED store src {reg} */'
    if mnemonic in ('strb', 'strbt'):
        return f'SIM_WRITE8({addr}, (uint8_t){c_r});'
    if mnemonic in ('strh',):
        return f'SIM_WRITE16({addr}, (uint16_t){c_r});'
    return f'SIM_WRITE32({addr}, {c_r});'


def _strip_condition(mnemonic: str) -> tuple[str, str | None]:
    """
    Separa el mnemónico base del sufijo de condición ARM32.
    Ejemplo: 'beq' → ('b', 'Z'), 'addlt' → ('add', '(N != V)').
    Retorna (base_mnemonic, c_condition) o (mnemonic, None) si no hay sufijo.
    """
    m = mnemonic.lower()
    # Sufijos ordenados por longitud descendente para evitar solapamientos
    for suffix in sorted(ARM32_COND_TO_C.keys(), key=len, reverse=True):
        if m.endswith(suffix) and len(m) > len(suffix):
            base = m[:-len(suffix)]
            # Evitar falsos positivos: 'movs' no es 'mov' + 's' de condición
            # Los sufijos de condición son ≥ 2 caracteres; los sufijos 's' son 1
            if len(suffix) >= 2:
                return base, ARM32_COND_TO_C[suffix]
    return m, None
