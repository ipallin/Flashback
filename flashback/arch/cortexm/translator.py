"""
Translator Cortex-M: genera código C portátil desde CFG ARM bare-metal.

Diferencias respecto a Arm32Translator:
  - Punto de entrada: Reset_Handler, no main(argc, argv).
  - Registros especiales Cortex-M: MSP, PSP, xPSR, CONTROL, PRIMASK, BASEPRI, FAULTMASK.
  - MRS/MSR mapeados a accesos a variables de registros especiales.
  - cpsid/cpsie mapeados a PRIMASK.
  - dmb/dsb/isb/wfi/wfe/sev son no-ops en la simulación.
  - cbz/cbnz tratados como if (!r0) goto / if (r0) goto.
  - Sin emit_syscall ni emit_external_call (bare-metal sin OS).
  - Modelo de memoria: Flash en 0x08xxxxxx, SRAM en 0x20xxxxxx/0x30xxxxxx.
"""

from __future__ import annotations

import logging

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
    'faultmask': 'faultmask',
}


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

    def _translate_instruction(self, insn) -> str | None:
        m = insn.mnemonic.lower()
        ops = insn.operands.strip()

        # MRS: mover de registro especial a registro general
        if m == 'mrs':
            parts = [p.strip() for p in ops.split(',', 1)]
            if len(parts) == 2:
                dst  = _a32_reg_to_c(parts[0])
                sreg = _SPECIAL_REG_ALIASES.get(parts[1].lower(), parts[1].lower())
                return f'{dst} = {sreg};'

        # MSR: mover de registro general a registro especial
        if m == 'msr':
            parts = [p.strip() for p in ops.split(',', 1)]
            if len(parts) == 2:
                sreg = _SPECIAL_REG_ALIASES.get(parts[0].lower(), parts[0].lower())
                src  = _a32_reg_to_c(parts[1])
                return f'{sreg} = {src};'

        # CPSID / CPSIE — enable/disable interrupts
        if m == 'cpsid':
            flag = ops.lower()
            if flag == 'i':
                return 'primask = 1;  /* CPSID i — disable IRQ */'
            if flag == 'f':
                return 'faultmask = 1;  /* CPSID f — disable faults */'
            return f'primask = 1;  /* CPSID {ops} */'
        if m == 'cpsie':
            flag = ops.lower()
            if flag == 'i':
                return 'primask = 0;  /* CPSIE i — enable IRQ */'
            if flag == 'f':
                return 'faultmask = 0;  /* CPSIE f — enable faults */'
            return f'primask = 0;  /* CPSIE {ops} */'

        # Barreras de memoria y espera — no-ops en simulación
        if m in ('dmb', 'dsb', 'isb'):
            return f'/* {m} — memory barrier (nop en simulación) */'
        if m in ('wfi', 'wfe'):
            return f'/* {m} — wait for interrupt/event (nop en simulación) */'
        if m == 'sev':
            return '/* sev — send event (nop en simulación) */'
        if m == 'nop':
            return '/* nop */'

        # cbz / cbnz — Compare and Branch if Zero / Non-Zero
        if m in ('cbz', 'cbnz'):
            parts = [p.strip() for p in ops.split(',', 1)]
            if len(parts) == 2:
                reg  = _a32_reg_to_c(parts[0])
                dest = parts[1].strip()
                cond = f'!{reg}' if m == 'cbz' else reg
                return f'if ({cond}) goto label_{dest.replace("0x", "").replace("#", "")};'

        # BKPT — breakpoint
        if m == 'bkpt':
            return f'/* bkpt {ops} — breakpoint */'

        # IT block — la instrucción IT en sí no genera código (capstone ya
        # pone la condición en las instrucciones siguientes)
        if m.startswith('it'):
            return f'/* {m} {ops} — IT block (condición en instrucciones siguientes) */'

        # VFP / FPU — operaciones de punto flotante (vldr/vstr/vadd/vmul/etc.)
        if (m.startswith('v') and m not in ('vpush', 'vpop')
                and m not in ('vldm', 'vstm')):
            return f'/* {m} {ops}  [VFP/FPU — no simulado] */'
        if m in ('vpush', 'vpop', 'vldm', 'vstm'):
            return f'/* {m} {ops}  [VFP stack op — no simulada] */'

        # Delegar el resto al traductor ARM32 base
        return super()._translate_instruction(insn)


# ---------------------------------------------------------------------------
# Helper local (duplicado de arm32/translator.py para evitar importación circular)
# ---------------------------------------------------------------------------

def _a32_reg_to_c(reg: str) -> str:
    reg = reg.lower().strip()
    aliases = {'sp': 'r13', 'lr': 'r14', 'pc': 'r15',
               'ip': 'r12', 'fp': 'r11', 'sl': 'r10'}
    return aliases.get(reg, reg)
