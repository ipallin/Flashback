"""
Translator Cortex-M: genera código C portátil desde CFG ARM bare-metal.

Diferencias respecto a Arm32Translator:
  - Punto de entrada: Reset_Handler, no main(argc, argv).
  - Registros especiales Cortex-M: MSP, PSP, xPSR, CONTROL, PRIMASK, BASEPRI, FAULTMASK.
  - MRS/MSR mapeados a accesos a variables de registros especiales.
  - cpsid/cpsie mapeados a PRIMASK.
  - dmb/dsb/isb/wfi/wfe/sev son no-ops en la simulación.
  - cbz/cbnz terminan bloque: la salida de bloque emite if (r0 == 0) goto.
  - Sin emit_syscall ni emit_external_call (bare-metal sin OS).
  - Modelo de memoria: Flash en 0x08xxxxxx, SRAM en 0x20xxxxxx/0x30xxxxxx.
"""

from __future__ import annotations

import logging

from flashback.arch.arm32 import semantics
from flashback.arch.arm32.instruction_sem import ARM32_COND_TO_C, split_arm_mnemonic
from flashback.arch.arm32.translator import Arm32Translator, _ARM32_REGS, _ARM32_ALIASES
from flashback.core.models import EnrichedCFG

logger = logging.getLogger(__name__)

# Registros especiales Cortex-M accedidos vía MRS/MSR
_CORTEXM_SPECIAL_REGS = [
    'msp', 'psp', 'xpsr', 'control', 'primask', 'basepri', 'faultmask',
    'apsr', 'ipsr', 'epsr',
]

# Capstone nombra los registros especiales en lowercase; algunos tienen aliases
_SPECIAL_REG_ALIASES = {
    'xpsr': 'xpsr', 'apsr': 'apsr', 'ipsr': 'ipsr', 'epsr': 'epsr',
    'msp': 'msp', 'psp': 'psp',
    'control': 'control', 'primask': 'primask', 'basepri': 'basepri',
    'faultmask': 'faultmask', 'basepri_max': 'basepri',
}

# Vistas de xPSR que contienen los flags NZCV (bits 31..28)
_APSR_NAMES = frozenset({'apsr', 'xpsr', 'iapsr', 'eapsr', 'apsr_nzcvq', 'apsr_nzcv', 'apsr_g',
                         'apsr_nzcvqg'})
_IPSR_NAMES = frozenset({'xpsr', 'iapsr'})


class CortexMTranslator(Arm32Translator):
    """Traductor de CFG Cortex-M → C portátil (firmware bare-metal)."""

    def __init__(self, initial_sp: int = 0, **kwargs):
        super().__init__(**kwargs)
        self._initial_sp = initial_sp

    def _emit_registers(self) -> str:
        lines = ['/* Registros ARM Cortex-M simulados como variables globales */']
        for reg in _ARM32_REGS:
            lines.append(f'static uint32_t {reg} = 0;')
        lines.append('/* Aliases convenientes */')
        for alias, target in _ARM32_ALIASES.items():
            lines.append(f'#define {alias} {target}')
        lines.append('static uint64_t __jt_index = 0;  /* índice de tabla de salto */')
        lines.append('/* Registros especiales Cortex-M */')
        for sreg in _CORTEXM_SPECIAL_REGS:
            lines.append(f'static uint32_t {sreg} = 0;')
        return '\n'.join(lines)

    def _emit_entry_point(self, cfg: EnrichedCFG) -> str:
        entry    = cfg.binary_info.entry_point
        entry_id = entry.replace('0x', '')

        # Buscar Reset_Handler o usar el entry point directamente
        reset_addr = None
        reset_name = None
        for addr, func in cfg.functions.items():
            if func.name in ('Reset_Handler', 'reset_handler', 'Reset'):
                reset_addr = addr
                reset_name = func.name
                break

        if reset_addr:
            call_id   = reset_addr.replace('0x', '')
            call_name = reset_name
        else:
            call_id   = entry_id
            ef        = cfg.functions.get(entry)
            call_name = ef.name if ef else f'func_{entry_id}'

        sp_init = self._initial_sp or 0
        sp_comment = f'/* MSP inicial del vector table: 0x{sp_init:08x} */' if sp_init else \
                     '/* MSP: tope del stack de simulación */'

        bi = cfg.binary_info
        bss_init = ''
        if bi.bss_va and bi.bss_size and int(bi.bss_size) > self._BSS_STATIC_CAP:
            bss_init = (
                '    __bss = (uint8_t *)calloc(__BSS_SIZE, 1);\n'
                f'    if (!__bss) {{ fprintf(stderr, "no se pudo reservar .bss\\n"); return 1; }}\n'
            )

        return (
            f'/* Punto de entrada Cortex-M — firmware bare-metal */\n'
            f'/* El hardware inicializa MSP y llama a Reset_Handler */\n'
            f'int main(void) {{\n'
            f'{bss_init}'
            f'    {sp_comment}\n'
            f'    r13 = (uint32_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 4);\n'
            f'    r13 &= ~(uint32_t)0x7U;\n'
            f'    msp = r13;\n'
            f'    func_{call_id}();  /* {call_name} @ {reset_addr or entry} */\n'
            f'    for (;;);  /* el firmware no retorna */\n'
            f'    return 0;\n'
            f'}}'
        )

    def _emit_syscall(self, ann) -> str:
        return '/* syscall — bare-metal, sin SO */'

    def _emit_external_call(self, ann) -> str:
        return '/* external call — sin dynamic linker */'

    # ------------------------------------------------------------------
    # Traducción de instrucciones Cortex-M específicas
    # ------------------------------------------------------------------

    def translate(self, cfg: EnrichedCFG) -> str:
        # Handler de la excepción SVCall (svc #n), si el firmware lo define
        self._svc_handler = next(
            (addr for addr, f in cfg.functions.items()
             if f.name in ('SVC_Handler', 'SVCall_Handler', 'vPortSVCHandler')
             and not f.is_external), None)
        return super().translate(cfg)

    def _is_thumb(self, insn) -> bool:
        return True                     # Cortex-M solo ejecuta Thumb-2

    def _svc(self, insn) -> str:
        handler = getattr(self, '_svc_handler', None)
        if handler:
            return f'func_{handler.replace("0x", "")}();  /* svc {insn.operands}: excepción SVCall */'
        return f'/* svc {insn.operands}: el firmware no define SVC_Handler */'

    def _translate_instruction(self, insn) -> str | None:
        m = insn.mnemonic.lower()
        ops = insn.operands.strip()
        base, cond = split_arm_mnemonic(m)
        stmt = None

        # MRS / MSR: registros especiales; APSR/xPSR se corresponden con los flags NZCV
        if base == 'mrs':
            parts = [p.strip() for p in ops.split(',', 1)]
            if len(parts) == 2:
                dst = _a32_reg_to_c(parts[0])
                src = parts[1].lower()
                if src in _APSR_NAMES:
                    stmt = f'{dst} = {semantics.APSR_PACK}{" | ipsr" if src in _IPSR_NAMES else ""};'
                elif src == 'msp':      # SP activo = MSP si CONTROL.SPSEL == 0
                    stmt = f'{dst} = (control & 2U) ? msp : r13;'
                elif src == 'psp':
                    stmt = f'{dst} = (control & 2U) ? r13 : psp;'
                else:
                    sreg = _SPECIAL_REG_ALIASES.get(src, src)
                    stmt = f'{dst} = {sreg};'
        elif base == 'msr':
            parts = [p.strip() for p in ops.split(',', 1)]
            if len(parts) == 2:
                dst = parts[0].lower()
                src = _a32_reg_to_c(parts[1])
                if dst.startswith(('apsr', 'xpsr')):
                    stmt = semantics.apsr_unpack(src)
                elif dst == 'msp':
                    stmt = f'msp = {src}; if (!(control & 2U)) r13 = msp;'
                elif dst == 'psp':
                    stmt = f'psp = {src}; if (control & 2U) r13 = psp;'
                else:
                    sreg = _SPECIAL_REG_ALIASES.get(dst, dst)
                    stmt = f'{sreg} = {src};'

        # CPSID / CPSIE — enable/disable interrupts
        elif base in ('cpsid', 'cpsie'):
            value = 1 if base == 'cpsid' else 0
            reg = 'faultmask' if ops.lower() == 'f' else 'primask'
            stmt = f'{reg} = {value};  /* {m} {ops} */'

        if stmt is not None:
            return f'if ({ARM32_COND_TO_C[cond]}) {{ {stmt} }}' if cond else stmt
        # Resto de instrucciones (enteras, VFP, memoria...): semántica ARM común
        return super()._translate_instruction(insn)


# ---------------------------------------------------------------------------
# Helper local (duplicado de arm32/translator.py para evitar importación circular)
# ---------------------------------------------------------------------------

def _a32_reg_to_c(reg: str) -> str:
    reg = reg.lower().strip()
    aliases = {'sp': 'r13', 'lr': 'r14', 'pc': 'r15',
               'ip': 'r12', 'fp': 'r11', 'sl': 'r10', 'sb': 'r9'}
    return aliases.get(reg, reg)
