"""
Translator x86 (32-bit): genera código C portable desde CFG i386.

Diferencias clave respecto al Translator base (x86-64):
  - Registros uint32_t (eax, ebx, ecx, edx, esi, edi, esp, ebp).
  - Stack con esp/ebp; sin registros r8-r15.
  - Llamadas externas cdecl: args en la pila (leídas via SIM_READ32).
  - Syscalls via int 0x80: num en eax, args en ebx, ecx, edx, esi, edi, ebp.
  - Direcciones 32-bit: SIM macros con cast a uint32_t.
"""

from __future__ import annotations

import logging

from flashback.core.translator import (
    Translator, _resolve_direct_target,
    _split_operands, _mem_addr_expr,
)
from flashback.core.models import EnrichedCFG, BasicBlock, Instruction

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes x86 (32-bit)
# ---------------------------------------------------------------------------

_X86_REGS_32 = [
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eip', 'eflags',
]

_X86_REG_16 = {
    'ax': 'eax', 'bx': 'ebx', 'cx': 'ecx', 'dx': 'edx',
    'si': 'esi', 'di': 'edi', 'sp': 'esp', 'bp': 'ebp',
}
_X86_REG_8L = {'al': 'eax', 'bl': 'ebx', 'cl': 'ecx', 'dl': 'edx'}
_X86_REG_8H = {'ah': 'eax', 'bh': 'ebx', 'ch': 'ecx', 'dh': 'edx'}

_X86_FLAGS = ['ZF', 'CF', 'SF', 'OF', 'PF']

# Saltos condicionales x86 → condición C
_X86_JCC_TO_C: dict[str, str] = {
    'je': 'ZF', 'jz': 'ZF',
    'jne': '!ZF', 'jnz': '!ZF',
    'jl': '(SF != OF)', 'jnge': '(SF != OF)',
    'jle': '(ZF || SF != OF)', 'jng': '(ZF || SF != OF)',
    'jg': '(!ZF && SF == OF)', 'jnle': '(!ZF && SF == OF)',
    'jge': '(SF == OF)', 'jnl': '(SF == OF)',
    'jb': 'CF', 'jnae': 'CF', 'jc': 'CF',
    'jbe': '(CF || ZF)', 'jna': '(CF || ZF)',
    'ja': '(!CF && !ZF)', 'jnbe': '(!CF && !ZF)',
    'jae': '!CF', 'jnb': '!CF', 'jnc': '!CF',
    'js': 'SF', 'jns': '!SF',
    'jo': 'OF', 'jno': '!OF',
    'jp': 'PF', 'jpe': 'PF',
    'jnp': '!PF', 'jpo': '!PF',
}

# Ramas terminadoras de bloque para x86 32-bit
_X86_BRANCH_TERMINATORS = frozenset(_X86_JCC_TO_C.keys() | {'jmp', 'jcxz', 'jecxz'})

# Mapeo función libc → (retorno, args usando SIM_READ32 para stack cdecl).
# esp+4 = primer arg, esp+8 = segundo, etc. al momento del call.
_X86_LIBC_CALL_MAP: dict[str, tuple[str, list[str]]] = {
    'printf':   ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             'SIM_READ32(esp+8)', 'SIM_READ32(esp+12)']),
    'fprintf':  ('int',     ['(FILE*)(uintptr_t)SIM_READ32(esp+4)',
                             '(const char*)(uintptr_t)SIM_READ32(esp+8)',
                             'SIM_READ32(esp+12)']),
    'scanf':    ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(void*)(uintptr_t)SIM_READ32(esp+8)']),
    'puts':     ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)']),
    'putchar':  ('int',     ['(int)SIM_READ32(esp+4)']),
    'getchar':  ('int',     []),
    'malloc':   ('void*',   ['(size_t)SIM_READ32(esp+4)']),
    'calloc':   ('void*',   ['(size_t)SIM_READ32(esp+4)', '(size_t)SIM_READ32(esp+8)']),
    'realloc':  ('void*',   ['(void*)(uintptr_t)SIM_READ32(esp+4)', '(size_t)SIM_READ32(esp+8)']),
    'free':     ('void',    ['(void*)(uintptr_t)SIM_READ32(esp+4)']),
    'memcpy':   ('void*',   ['(void*)(uintptr_t)SIM_READ32(esp+4)',
                             '(const void*)(uintptr_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)']),
    'memset':   ('void*',   ['(void*)(uintptr_t)SIM_READ32(esp+4)',
                             '(int)SIM_READ32(esp+8)', '(size_t)SIM_READ32(esp+12)']),
    'strlen':   ('size_t',  ['(const char*)(uintptr_t)SIM_READ32(esp+4)']),
    'strcpy':   ('char*',   ['(char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(const char*)(uintptr_t)SIM_READ32(esp+8)']),
    'strncpy':  ('char*',   ['(char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(const char*)(uintptr_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)']),
    'strcmp':   ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(const char*)(uintptr_t)SIM_READ32(esp+8)']),
    'strncmp':  ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(const char*)(uintptr_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)']),
    'open':     ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(int)SIM_READ32(esp+8)', '(int)SIM_READ32(esp+12)']),
    'read':     ('ssize_t', ['(int)SIM_READ32(esp+4)',
                             '(void*)(uintptr_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)']),
    'write':    ('ssize_t', ['(int)SIM_READ32(esp+4)',
                             '(const void*)(uintptr_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)']),
    'close':    ('int',     ['(int)SIM_READ32(esp+4)']),
    'exit':     ('void',    ['(int)SIM_READ32(esp+4)']),
    'atoi':     ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)']),
    'strtol':   ('long',    ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(char**)(uintptr_t)SIM_READ32(esp+8)',
                             '(int)SIM_READ32(esp+12)']),
    'fopen':    ('FILE*',   ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(const char*)(uintptr_t)SIM_READ32(esp+8)']),
    'fclose':   ('int',     ['(FILE*)(uintptr_t)SIM_READ32(esp+4)']),
    'fread':    ('size_t',  ['(void*)(uintptr_t)SIM_READ32(esp+4)',
                             '(size_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)',
                             '(FILE*)(uintptr_t)SIM_READ32(esp+16)']),
    'fwrite':   ('size_t',  ['(const void*)(uintptr_t)SIM_READ32(esp+4)',
                             '(size_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)',
                             '(FILE*)(uintptr_t)SIM_READ32(esp+16)']),
    'perror':   ('void',    ['(const char*)(uintptr_t)SIM_READ32(esp+4)']),
    'mmap':     ('void*',   ['(void*)(uintptr_t)SIM_READ32(esp+4)',
                             '(size_t)SIM_READ32(esp+8)',
                             '(int)SIM_READ32(esp+12)',
                             '(int)SIM_READ32(esp+16)',
                             '(int)SIM_READ32(esp+20)',
                             '(off_t)SIM_READ32(esp+24)']),
    'munmap':   ('int',     ['(void*)(uintptr_t)SIM_READ32(esp+4)',
                             '(size_t)SIM_READ32(esp+8)']),
    'socket':   ('int',     ['(int)SIM_READ32(esp+4)', '(int)SIM_READ32(esp+8)',
                             '(int)SIM_READ32(esp+12)']),
    'connect':  ('int',     ['(int)SIM_READ32(esp+4)',
                             '(const struct sockaddr*)(uintptr_t)SIM_READ32(esp+8)',
                             '(socklen_t)SIM_READ32(esp+12)']),
    'send':     ('ssize_t', ['(int)SIM_READ32(esp+4)',
                             '(const void*)(uintptr_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)', '(int)SIM_READ32(esp+16)']),
    'recv':     ('ssize_t', ['(int)SIM_READ32(esp+4)',
                             '(void*)(uintptr_t)SIM_READ32(esp+8)',
                             '(size_t)SIM_READ32(esp+12)', '(int)SIM_READ32(esp+16)']),
    'fork':     ('pid_t',   []),
    'execve':   ('int',     ['(const char*)(uintptr_t)SIM_READ32(esp+4)',
                             '(char* const*)(uintptr_t)SIM_READ32(esp+8)',
                             '(char* const*)(uintptr_t)SIM_READ32(esp+12)']),
    'waitpid':  ('pid_t',   ['(pid_t)SIM_READ32(esp+4)',
                             '(int*)(uintptr_t)SIM_READ32(esp+8)',
                             '(int)SIM_READ32(esp+12)']),
    'abort':            ('void', []),
    '_exit':            ('void', ['(int)SIM_READ32(esp+4)']),
    '__stack_chk_fail': ('void', []),
}


class X86Translator(Translator):
    """Traductor de CFG i386 → C portátil."""

    def _emit_registers(self) -> str:
        lines = ['/* Registros x86 (32-bit) simulados como variables globales */']
        for reg in _X86_REGS_32:
            lines.append(f'static uint32_t {reg} = 0;')
        return '\n'.join(lines)

    def _emit_flags(self) -> str:
        lines = ['/* Flags de CPU (x86 32-bit) */']
        for flag in _X86_FLAGS:
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
            f'/* Punto de entrada x86 (32-bit) */\n'
            f'int main(int argc, char *argv[]) {{\n'
            f'{bss_init}'
            f'    esp  = (uint32_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 4);\n'
            f'    esp &= ~(uint32_t)0xFU;\n'
            f'    /* cdecl: argc y argv en pila */\n'
            f'    esp -= 4; SIM_WRITE32(esp, (uint32_t)(uintptr_t)argv);\n'
            f'    esp -= 4; SIM_WRITE32(esp, (uint32_t)(uint32_t)argc);\n'
            f'    func_{entry_id}();  /* {fname} @ {entry} */\n'
            f'    __trace_dump("flashback_trace.bin");\n'
            f'    return (int)(uint32_t)eax;\n'
            f'}}'
        )

    def _is_branch_terminator(self, mnemonic: str) -> bool:
        return mnemonic.lower() in _X86_BRANCH_TERMINATORS

    def _jcc_condition(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        if not block.instructions:
            return 'ZF'
        last_insn = cfg.instructions.get(block.instructions[-1])
        if last_insn is None:
            return 'ZF'
        m = last_insn.mnemonic.lower()
        if m == 'jcxz':
            return '(uint16_t)ecx == 0'
        if m == 'jecxz':
            return 'ecx == 0'
        cond = _X86_JCC_TO_C.get(m)
        return cond if cond is not None else f'ZF /* WARNING: {m} */'

    def _emit_instruction(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        lines = []
        if any(a.type == 'trace_point' for a in insn.annotations):
            lines.append(f'    __trace({insn.address}ULL);')
        lines.append(f'    /* {insn.address}: {insn.mnemonic} {insn.operands} */')

        ext_calls    = [a for a in insn.annotations if a.type == 'external_call']
        syscall_anns = [a for a in insn.annotations if a.type == 'syscall']

        if ext_calls and insn.mnemonic == 'call':
            lines.append(self._emit_external_call(ext_calls[0]))
        elif syscall_anns and insn.mnemonic == 'int':
            lines.append(self._emit_syscall(syscall_anns[0]))
        elif insn.mnemonic == 'call':
            lines.append(self._emit_call(insn, cfg))
        else:
            lines.append(f'    {self._translate_instruction(insn)}')
        return '\n'.join(lines)

    def _emit_external_call(self, ann) -> str:
        func_name = ann.function_name
        call_info = _X86_LIBC_CALL_MAP.get(func_name)
        if call_info is None:
            return (
                f'    /* EXTERNAL CALL sin prototipo: {func_name}() */\n'
                f'    {{ extern long {func_name}(); '
                f'eax = (uint32_t)(long){func_name}('
                f'(long)SIM_READ32(esp+4), (long)SIM_READ32(esp+8), '
                f'(long)SIM_READ32(esp+12), (long)SIM_READ32(esp+16)); }}'
            )
        ret_type, args = call_info
        args_str = ', '.join(args)
        if ret_type == 'void':
            return f'    {func_name}({args_str});'
        return f'    eax = (uint32_t)(uintptr_t){func_name}({args_str});'

    def _emit_syscall(self, ann) -> str:
        num = ann.syscall_number if ann.syscall_number >= 0 else 'eax'
        name = ann.syscall_name or 'unknown'
        return (
            f'    /* SYSCALL int 0x80: {name} (num={ann.syscall_number}) */\n'
            f'    eax = (uint32_t)syscall((long){num}, '
            f'(long)ebx, (long)ecx, (long)edx, (long)esi, (long)edi, (long)ebp);'
        )

    def _emit_call(self, insn: Instruction, cfg: EnrichedCFG) -> str:
        ops = insn.operands.strip()
        if '[' not in ops:
            target = _resolve_direct_target(ops)
            if target and target in self._defined_funcs:
                return f'    func_{target.replace("0x", "")}();'
            return f'    /* CALL {ops} — función no definida en este CFG */'
        return f'    /* INDIRECT CALL: {ops} — sin resolver */'

    def _translate_instruction(self, insn: Instruction) -> str:
        m   = insn.mnemonic
        ops = insn.operands

        if m == 'nop':
            return '/* nop */'
        if m == 'hlt':
            return 'return;'
        if m == 'push':
            reg = ops.strip()
            c_r = _x86_reg_to_c(reg)
            if c_r is None:
                # memory push
                addr = _mem_addr_expr(ops)
                c_r = f'(uint32_t)SIM_READ32({addr})' if addr else f'(uint32_t)0'
            return (f'esp -= 4; '
                    f'if (esp < (uint32_t)(uintptr_t)__sim_stack) '
                    f'{{ fprintf(stderr, "stack overflow\\n"); abort(); }} '
                    f'SIM_WRITE32(esp, {c_r});')
        if m == 'pop':
            reg = ops.strip()
            w = _x86_reg_write(reg, 'SIM_READ32(esp)')
            if w:
                return f'{w} esp += 4;'
        if m in ('ret', 'retn'):
            return 'return;'
        if m == 'leave':
            return 'esp = ebp; ebp = SIM_READ32(esp); esp += 4;'
        if m == 'mov':
            dst, src = _split_operands(ops)
            if dst and src:
                c_src = _x86_reg_to_c(src)
                if c_src is not None and _x86_reg_to_c(dst) is not None:
                    return _x86_reg_write(dst, c_src)
                mem = _x86_mem_to_c(dst, 'write', src) or _x86_mem_to_c(src, 'read', dst)
                if mem:
                    return mem
        if m in ('movsx', 'movzx'):
            dst, src = _split_operands(ops)
            c_s = _x86_operand_read(src) if src else None
            if dst and c_s is not None:
                if m == 'movsx':
                    sz = _x86_operand_size(src)
                    ity = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t'}[sz]
                    return _x86_reg_write(dst, f'(uint32_t)(int32_t)({ity})({c_s})')
                else:
                    return _x86_reg_write(dst, f'(uint32_t){c_s}')
        if m == 'lea':
            dst, src = _split_operands(ops)
            if dst and src:
                addr = _mem_addr_expr(src)
                if addr:
                    return _x86_reg_write(dst, f'(uint32_t)({addr})')
        if m == 'add':
            return _x86_alu_binop(ops, '+')
        if m == 'sub':
            return _x86_alu_binop(ops, '-')
        if m == 'and':
            return _x86_alu_binop(ops, '&')
        if m == 'or':
            return _x86_alu_binop(ops, '|')
        if m == 'xor':
            dst, src = _split_operands(ops)
            c_d = _x86_reg_to_c(dst) if dst else None
            c_s = _x86_reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                if dst == src:
                    base = _x86_reg_base(dst)
                    return f'{base} = 0;  /* xor reg,reg */' if base else '/* xor */'
                return _x86_reg_write(dst, f'{c_d} ^ {c_s}')
        if m == 'not':
            reg = ops.strip()
            c_o = _x86_reg_to_c(reg)
            if c_o is not None:
                return _x86_reg_write(reg, f'~{c_o}')
        if m == 'neg':
            reg = ops.strip()
            c_o = _x86_reg_to_c(reg)
            if c_o is not None:
                return _x86_reg_write(reg, f'(uint32_t)(-(int32_t){c_o})')
        if m == 'inc':
            reg = ops.strip()
            c_o = _x86_reg_to_c(reg)
            if c_o is not None:
                return _x86_reg_write(reg, f'{c_o} + 1')
        if m == 'dec':
            reg = ops.strip()
            c_o = _x86_reg_to_c(reg)
            if c_o is not None:
                return _x86_reg_write(reg, f'{c_o} - 1')
        if m in ('shl', 'sal'):
            dst, src = _split_operands(ops)
            c_d = _x86_reg_to_c(dst) if dst else None
            c_s = _x86_reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _x86_reg_write(dst, f'{c_d} << ({c_s} & 31)')
        if m == 'shr':
            dst, src = _split_operands(ops)
            c_d = _x86_reg_to_c(dst) if dst else None
            c_s = _x86_reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _x86_reg_write(dst, f'{c_d} >> ({c_s} & 31)')
        if m == 'sar':
            dst, src = _split_operands(ops)
            c_d = _x86_reg_to_c(dst) if dst else None
            c_s = _x86_reg_to_c(src) if src else None
            if c_d is not None and c_s is not None:
                return _x86_reg_write(dst, f'(uint32_t)((int32_t){c_d} >> ({c_s} & 31))')
        if m == 'mul':
            c_r = _x86_reg_to_c(ops.strip())
            if c_r is not None:
                return (f'{{ uint64_t __p = (uint64_t)eax * (uint64_t)({c_r}); '
                        f'eax = (uint32_t)__p; edx = (uint32_t)(__p >> 32); '
                        f'OF = CF = (edx != 0); }}')
        if m == 'imul':
            dst, src = _split_operands(ops)
            if dst is None:
                c_r = _x86_reg_to_c(ops.strip())
                if c_r is not None:
                    return (f'{{ int64_t __p = (int64_t)(int32_t)eax * (int64_t)(int32_t)({c_r}); '
                            f'eax = (uint32_t)__p; edx = (uint32_t)(uint64_t)(__p >> 32); '
                            f'OF = CF = (edx != (uint32_t)((int32_t)eax >> 31)); }}')
            c_d = _x86_reg_to_c(dst) if dst else None
            c_s = _x86_operand_read(src) if src else None
            if c_d is not None and c_s is not None:
                return _x86_reg_write(dst, f'(uint32_t)((int32_t){c_d} * (int32_t){c_s})')
        if m == 'div':
            c_r = _x86_operand_read(ops.strip())
            if c_r is not None:
                return (f'{{ uint32_t __d=(uint32_t)({c_r}); '
                        f'if (!__d) {{ fprintf(stderr,"div: div by zero\\n"); abort(); }} '
                        f'uint64_t __n=((uint64_t)edx<<32)|eax; '
                        f'eax=(uint32_t)(__n/__d); edx=(uint32_t)(__n%__d); }}')
        if m == 'idiv':
            c_r = _x86_operand_read(ops.strip())
            if c_r is not None:
                return (f'{{ int32_t __d=(int32_t)({c_r}); '
                        f'if (!__d) {{ fprintf(stderr,"idiv: div by zero\\n"); abort(); }} '
                        f'int64_t __n=(int64_t)(((uint64_t)edx<<32)|eax); '
                        f'eax=(uint32_t)(int32_t)(__n/__d); edx=(uint32_t)(int32_t)(__n%__d); }}')
        if m == 'cmp':
            dst, src = _split_operands(ops)
            c_d = _x86_operand_read(dst) if dst else None
            c_s = _x86_operand_read(src) if src else None
            if c_d and c_s:
                return (f'{{ int32_t __a=(int32_t)({c_d}),__b=(int32_t)({c_s}),__r=__a-__b; '
                        f'ZF=(__r==0); SF=(__r<0); '
                        f'CF=((uint32_t)({c_d})<(uint32_t)({c_s})); '
                        f'OF=(uint8_t)((__a<0)!=(__b<0)&&(__r<0)!=(__a<0)); '
                        f'PF=(uint8_t)(__builtin_parity((uint8_t)__r)); }}')
        if m == 'test':
            dst, src = _split_operands(ops)
            c_d = _x86_operand_read(dst) if dst else None
            c_s = _x86_operand_read(src) if src else None
            if c_d and c_s:
                return (f'{{ int32_t __t=(int32_t)({c_d}&{c_s}); '
                        f'ZF=(__t==0); SF=(__t<0); CF=0; OF=0; '
                        f'PF=(uint8_t)(__builtin_parity((uint8_t)__t)); }}')
        if m == 'cdq':
            return 'edx = (uint32_t)(((int32_t)eax) >> 31);'
        if m == 'cwde':
            return 'eax = (uint32_t)(int32_t)(int16_t)(uint16_t)eax;'
        _setcc = {
            'sete': 'ZF', 'setz': 'ZF', 'setne': '!ZF', 'setnz': '!ZF',
            'setl': '(SF!=OF)', 'setg': '(!ZF&&(SF==OF))',
            'setge': '(SF==OF)', 'setle': '(ZF||(SF!=OF))',
            'seta': '(!CF&&!ZF)', 'setb': 'CF',
        }
        if m in _setcc:
            reg = ops.strip()
            if _x86_reg_to_c(reg) is not None:
                return _x86_reg_write(reg, f'(uint8_t)({_setcc[m]})')
        if m == 'call':
            target = _resolve_direct_target(ops)
            if target and target in self._defined_funcs:
                return f'func_{target.replace("0x", "")}();'
            return f'/* CALL {ops} — función no definida */'

        return (
            f'/* UNSUPPORTED: {m} {ops} */\n'
            f'    fprintf(stderr, "UNSUPPORTED: {m} {ops}\\n");\n'
            f'    abort();'
        )


# ---------------------------------------------------------------------------
# Helpers privados x86 (32-bit)
# ---------------------------------------------------------------------------

def _x86_reg_to_c(operand: str) -> str | None:
    o = operand.strip()
    if o in _X86_REGS_32:
        return o
    if o in _X86_REG_16:
        return f'(uint16_t){_X86_REG_16[o]}'
    if o in _X86_REG_8L:
        return f'(uint8_t){_X86_REG_8L[o]}'
    if o in _X86_REG_8H:
        return f'(uint8_t)({_X86_REG_8H[o]} >> 8)'
    if o.startswith('0x'):
        return f'((uint32_t){o}U)'
    if o.lstrip('-').isdigit():
        v = int(o)
        return f'((int32_t){v})' if v < 0 else f'((uint32_t){v}U)'
    return None


def _x86_reg_base(operand: str) -> str | None:
    o = operand.strip()
    if o in _X86_REGS_32:
        return o
    for table in (_X86_REG_16, _X86_REG_8L, _X86_REG_8H):
        if o in table:
            return table[o]
    return None


def _x86_reg_write(dst: str, src_expr: str) -> str | None:
    d = dst.strip()
    if d in _X86_REGS_32:
        return f'{d} = {src_expr};'
    if d in _X86_REG_16:
        base = _X86_REG_16[d]
        return f'{base} = ({base} & ~(uint32_t)0xFFFFU) | (uint32_t)(uint16_t)({src_expr});'
    if d in _X86_REG_8L:
        base = _X86_REG_8L[d]
        return f'{base} = ({base} & ~(uint32_t)0xFFU) | (uint32_t)(uint8_t)({src_expr});'
    if d in _X86_REG_8H:
        base = _X86_REG_8H[d]
        return f'{base} = ({base} & ~(uint32_t)0xFF00U) | ((uint32_t)(uint8_t)({src_expr}) << 8);'
    return None


def _x86_operand_size(operand: str) -> int:
    o = operand.strip()
    for p, b in (('dword ptr', 32), ('word ptr', 16), ('byte ptr', 8)):
        if o.startswith(p):
            return b
    if o in _X86_REGS_32:
        return 32
    if o in _X86_REG_16:
        return 16
    if o in _X86_REG_8L or o in _X86_REG_8H:
        return 8
    return 32


def _x86_operand_read(operand: str) -> str | None:
    o = operand.strip()
    reg = _x86_reg_to_c(o)
    if reg is not None:
        return reg
    addr = _mem_addr_expr(o)
    if addr is not None:
        sz = _x86_operand_size(o)
        return f'(uint32_t)SIM_READ{sz}({addr})'
    return None


def _x86_mem_to_c(operand: str, direction: str, other: str) -> str | None:
    s = operand.strip()
    size = 32
    for p, b in [('dword ptr ', 32), ('word ptr ', 16), ('byte ptr ', 8)]:
        if s.startswith(p):
            s = s[len(p):]
            size = b
            break
    if not (s.startswith('[') and s.endswith(']')):
        return None
    addr = s[1:-1].strip()
    if direction == 'read':
        if _x86_reg_to_c(other) is not None:
            return _x86_reg_write(other, f'(uint32_t)SIM_READ{size}({addr})')
        return None
    src = _x86_reg_to_c(other)
    return f'SIM_WRITE{size}({addr}, {src});' if src else None


def _x86_alu_binop(ops: str, op: str) -> str:
    dst, src = _split_operands(ops)
    if not dst or not src:
        return f'/* UNSUPPORTED alu {op} {ops} */'
    c_s = _x86_operand_read(src)
    if c_s is None:
        return f'/* UNSUPPORTED alu {op} {ops} */'
    flags = ' ZF=((int32_t)__res==0); SF=((int32_t)__res<0);'
    c_d = _x86_reg_to_c(dst)
    if c_d is not None:
        write_res = _x86_reg_write(dst, '__res')
        if write_res:
            return (f'{{ uint32_t __res=({c_d}) {op} ({c_s}); '
                    f'{write_res}{flags} }}')
    addr = _mem_addr_expr(dst)
    if addr is not None:
        sz = _x86_operand_size(dst)
        cur = f'(uint32_t)SIM_READ{sz}({addr})'
        return (f'{{ uint32_t __res=({cur}) {op} ({c_s}); '
                f'SIM_WRITE{sz}({addr}, __res);{flags} }}')
    return f'/* UNSUPPORTED alu {op} {ops} */'
