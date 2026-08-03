"""
Disassembler Cortex-M: ELF ARM bare-metal (Thumb-2 exclusivo).

Diferencias clave respecto a Arm32Disassembler:
  - CS_MODE_THUMB | CS_MODE_MCLASS: necesario para instrucciones MSR/MRS (xPSR, MSP, PSP...).
  - Sin PLT ni sección .dynamic (no hay enlazador dinámico en bare-metal).
  - La sección de vector table (startup/.isr_vector/...) se parsea como datos,
    no como código; sus entradas se incorporan al mapa de símbolos de función.
  - cbz/cbnz se añaden como ramas condicionales (solo existen en Thumb).
"""

from __future__ import annotations

import logging
from pathlib import Path

import capstone
import lief

from flashback.arch.arm32.disassembler import (
    Arm32Disassembler, DisassemblerError,
    _sha256, _is_stripped, _get_reg_access,
    _ARM32_MNEMONICS,
)
from flashback.arch.arm32.instruction_sem import (
    COND_BRANCH_MNEMONICS, UNCOND_JUMP_MNEMONICS, CALL_MNEMONICS,
)
from flashback.arch.cortexm.vector_table import parse_vector_table, is_vector_table_section
from flashback.core.cfg_builder import BinaryMeta, RawInstruction, ArchMnemonics, CFGBuilder

logger = logging.getLogger(__name__)

_CORTEXM_MNEMONICS = ArchMnemonics(
    cond_branches=COND_BRANCH_MNEMONICS | frozenset({'cbz', 'cbnz'}),
    uncond_jumps=UNCOND_JUMP_MNEMONICS | frozenset({'bx', 'tbb', 'tbh'}),
    calls=CALL_MNEMONICS,
    returns=frozenset({'bx'}),
    syscalls=frozenset(),       # sin syscalls de SO en bare-metal
    halts=frozenset({'udf', 'bkpt', 'wfi', 'wfe'}),
    target_resolver=_ARM32_MNEMONICS.target_resolver,
)

_CORTEXM_RUNTIME = frozenset({
    'Reset_Handler', 'SystemInit', '__libc_init_array',
    'main', '_exit', '__assert_func',
})


class CortexMDisassembler(Arm32Disassembler):
    """Disassembler para firmware ARM Cortex-M (Thumb-2 bare-metal)."""

    def __init__(self):
        super().__init__()
        self._initial_sp: int = 0
        self._vector_table_sections: set[int] = set()  # virtual_address de secciones de VT

    def disassemble(self, binary_path: str):
        raw_insns, meta = self.load(binary_path)
        return CFGBuilder(
            tool_version=self.version,
            capstone_version=self.capstone_version,
            lief_version=self.lief_version,
            arch_mnemonics=_CORTEXM_MNEMONICS,
        ).build(raw_insns, meta)

    def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
        path = Path(binary_path)
        self._validate(path)

        logger.info(f'Cargando {path.name} con lief (Cortex-M)')
        elf = lief.parse(str(path))
        if elf is None:
            raise DisassemblerError(f'lief no pudo parsear: {path}')

        self._validate_arch(elf)

        # Parsear vector table primero (necesario para _find_func_symbols)
        self._locate_vector_tables(elf)

        func_symbols = self._find_func_symbols(elf)
        # Guardar para que _disassemble pueda reiniciar en cada función
        self._func_addrs = set(func_symbols.keys())
        all_insns    = self._disassemble(elf)
        rodata_va, rodata_hex = self._extract_section_bytes(elf, '.rodata')
        data_va, data_hex     = self._extract_section_bytes(elf, '.data')
        bss_va, bss_size      = self._extract_bss(elf)

        meta = BinaryMeta(
            path=str(path.resolve()),
            sha256=_sha256(path),
            entry_point=elf.entrypoint & ~1,
            architecture='cortexm',
            is_pie=False,       # el firmware tiene direcciones absolutas
            is_stripped=_is_stripped(elf),
            func_symbols=func_symbols,
            plt_symbols={},     # sin PLT en bare-metal
            rodata_va=rodata_va,
            rodata_hex=rodata_hex,
            data_va=data_va,
            data_hex=data_hex,
            bss_va=bss_va,
            bss_size=bss_size,
        )
        logger.info(
            f'Cortex-M: {len(func_symbols)} funciones, '
            f'{len(all_insns)} instrucciones, SP inicial=0x{self._initial_sp:08x}'
        )
        return all_insns, meta

    # ------------------------------------------------------------------
    # Validación
    # ------------------------------------------------------------------

    def _validate_arch(self, elf) -> None:
        arch = elf.header.machine_type
        if arch != lief.ELF.ARCH.ARM:
            raise DisassemblerError(
                f'Arquitectura no soportada: {arch}. CortexMDisassembler solo admite ARM (32-bit).'
            )
        ep = elf.entrypoint
        if not (ep & 1):
            raise DisassemblerError(
                f'El binario no tiene Thumb bit en el entry point (0x{ep:08x}). '
                f'¿Es realmente firmware Cortex-M?'
            )

    # ------------------------------------------------------------------
    # Vector table
    # ------------------------------------------------------------------

    def _locate_vector_tables(self, elf) -> None:
        """Identifica secciones de vector table y extrae SP inicial + handler addresses."""
        for section in elf.sections:
            if not is_vector_table_section(section, elf):
                continue
            data = bytes(section.content)
            sp_val, handlers = parse_vector_table(data)
            if sp_val is not None and not self._initial_sp:
                self._initial_sp = sp_val
                logger.debug(f'SP inicial Cortex-M: 0x{sp_val:08x}')
            self._vector_table_sections.add(section.virtual_address)
            logger.debug(
                f'Vector table en sección "{section.name}" '
                f'@ 0x{section.virtual_address:08x}: {len(handlers)} handlers'
            )
            # Guardar handlers para _find_func_symbols
            if not hasattr(self, '_vt_handlers'):
                self._vt_handlers: dict[int, str] = {}
            self._vt_handlers.update(handlers)

    # ------------------------------------------------------------------
    # Descubrimiento de funciones
    # ------------------------------------------------------------------

    def _find_func_symbols(self, elf) -> dict[int, str]:
        funcs: dict[int, str] = {}

        # Entry point = Reset_Handler
        entry = elf.entrypoint & ~1
        if entry:
            funcs[entry] = 'Reset_Handler'

        # Símbolos ELF normales (todos tendrán Thumb bit)
        for sym in elf.symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _CORTEXM_RUNTIME):
                addr = sym.value & ~1
                funcs[addr] = sym.name

        # Handlers del vector table que no estén ya en el mapa de símbolos
        for addr, name in getattr(self, '_vt_handlers', {}).items():
            if addr not in funcs:
                funcs[addr] = name

        return funcs

    def _find_plt_symbols(self, elf) -> dict[int, str]:
        return {}   # sin PLT en Cortex-M

    # ------------------------------------------------------------------
    # Desensamblado Thumb-2 + MCLASS
    # ------------------------------------------------------------------

    def _disassemble(self, elf) -> dict[int, RawInstruction]:
        """
        Desensambla en modo Thumb-2 + MCLASS, reiniciando en cada función conocida.

        El código Thumb intercala literal pools (datos constantes) entre funciones.
        La decodificación lineal se detiene en el primer pool. La solución es usar
        las direcciones de los símbolos de función para reiniciar la decodificación
        en cada punto de entrada conocido.
        """
        cs = capstone.Cs(
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS,
        )
        cs.detail = True

        func_addrs = getattr(self, '_func_addrs', set())
        all_insns: dict[int, RawInstruction] = {}

        for section in elf.sections:
            if not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                continue
            if section.virtual_address in self._vector_table_sections:
                logger.debug(f'Omitiendo vector table: "{section.name}"')
                continue

            data = bytes(section.content)
            base = section.virtual_address
            end  = base + len(data)

            # Puntos de inicio en esta sección: funciones conocidas + inicio de sección
            starts = sorted(
                {base} | {a for a in func_addrs if base <= a < end}
            )
            # Añadir centinela al final para delimitar el último tramo
            starts.append(end)

            n_before = len(all_insns)
            decoded: set[int] = set()

            for i, start in enumerate(starts[:-1]):
                if start in decoded:
                    continue
                next_start = starts[i + 1]
                offset = start - base
                length = next_start - start
                chunk = data[offset: offset + length]
                if not chunk:
                    continue
                for cs_insn in cs.disasm(chunk, start):
                    if cs_insn.address in decoded:
                        break
                    decoded.add(cs_insn.address)
                    regs_read, regs_written = _get_reg_access(cs_insn)
                    all_insns[cs_insn.address] = RawInstruction(
                        address=cs_insn.address,
                        mnemonic=cs_insn.mnemonic,
                        operands=cs_insn.op_str,
                        bytes_hex=cs_insn.bytes.hex(),
                        size=cs_insn.size,
                        registers_read=regs_read,
                        registers_written=regs_written,
                    )

            logger.debug(
                f'Sección "{section.name}" @ 0x{base:08x}: '
                f'{len(all_insns) - n_before} instrucciones Thumb-2 '
                f'({len(starts)-1} funciones reiniciadas)'
            )

        return all_insns
