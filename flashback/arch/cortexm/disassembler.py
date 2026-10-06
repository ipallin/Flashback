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
)
from flashback.arch.arm32.instruction_sem import (
    COND_BRANCH_MNEMONICS, UNCOND_JUMP_MNEMONICS, CALL_MNEMONICS,
    classify_arm_flow, literal_reference, resolve_arm_branch_target,
)
from flashback.arch.cortexm.discovery import ThumbCodeDiscovery
from flashback.arch.cortexm.vector_table import parse_vector_table, is_vector_table_section
from flashback.core.cfg_builder import (
    BinaryMeta, RawInstruction, ArchMnemonics, CFGBuilder, is_noreturn_name,
)

logger = logging.getLogger(__name__)


def _classify_cortexm(mnemonic: str, operands: str):
    # svc en bare-metal es una llamada al RTOS que continúa en la siguiente
    # instrucción: no termina el bloque.
    return classify_arm_flow(mnemonic, operands, syscalls=False)


_CORTEXM_MNEMONICS = ArchMnemonics(
    cond_branches=COND_BRANCH_MNEMONICS | frozenset({'cbz', 'cbnz'}),
    uncond_jumps=UNCOND_JUMP_MNEMONICS | frozenset({'bx', 'tbb', 'tbh'}),
    calls=CALL_MNEMONICS,
    returns=frozenset({'bx'}),
    syscalls=frozenset(),       # sin syscalls de SO en bare-metal
    # wfi/wfe no detienen el núcleo: la ejecución sigue tras la interrupción
    halts=frozenset({'udf', 'bkpt'}),
    target_resolver=resolve_arm_branch_target,
    classifier=_classify_cortexm,
)


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
        linear_insns = self._disassemble(elf)
        # Quedarse solo con el código alcanzable: descarta literal pools y
        # tablas de salto decodificados como instrucciones y resuelve tbb/tbh.
        discovery = ThumbCodeDiscovery(
            sections=self._code_sections,
            linear=linear_insns,
            decode_run=self._decode_run,
            classify=_classify_cortexm,
            resolve_target=resolve_arm_branch_target,
            func_starts=self._func_addrs,
        ).run(self._func_addrs, noreturn_seeds={
            a for a, name in func_symbols.items() if is_noreturn_name(name)})
        all_insns = discovery.instructions
        logger.info(
            f'Cortex-M: {len(linear_insns)} instrucciones en barrido lineal, '
            f'{len(all_insns)} alcanzables; {len(discovery.jump_tables)} tablas de salto '
            f'resueltas, {discovery.unresolved_indirect} saltos indirectos sin resolver, '
            f'{discovery.data_bytes} bytes de datos en código, '
            f'{len(discovery.noreturn)} funciones que no retornan'
        )
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
            jump_tables=discovery.jump_tables,
            jump_table_index_regs=discovery.jump_table_index_regs,
            literals=self._literals(all_insns),
            noreturn=discovery.noreturn,
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

        # Símbolos ELF normales (todos tendrán Thumb bit). En firmware no hay
        # runtime de C que excluir: main, _exit o SystemInit son funciones más.
        for sym in elf.symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name):
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
        cs = self._capstone()
        func_addrs = getattr(self, '_func_addrs', set())
        all_insns: dict[int, RawInstruction] = {}
        self._code_sections: list[tuple[int, bytes]] = []

        for section in elf.sections:
            if not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                continue
            if section.virtual_address in self._vector_table_sections:
                logger.debug(f'Omitiendo vector table: "{section.name}"')
                continue

            data = bytes(section.content)
            base = section.virtual_address
            end  = base + len(data)
            self._code_sections.append((base, data))

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
                    all_insns[cs_insn.address] = _raw(cs_insn)

            logger.debug(
                f'Sección "{section.name}" @ 0x{base:08x}: '
                f'{len(all_insns) - n_before} instrucciones Thumb-2 '
                f'({len(starts)-1} funciones reiniciadas)'
            )

        return all_insns

    def _literals(self, insns: dict[int, RawInstruction]) -> dict[int, tuple[int, bytes]]:
        """Valor de cada carga relativa a pc (literal pool), leído del binario."""
        literals: dict[int, tuple[int, bytes]] = {}
        for addr, ri in insns.items():
            ref = literal_reference(ri.mnemonic, ri.operands, addr, thumb=True)
            if ref is None:
                continue
            lit_addr, size = ref
            for base, data in self._code_sections:
                if base <= lit_addr and lit_addr + size <= base + len(data):
                    literals[addr] = (lit_addr, data[lit_addr - base: lit_addr - base + size])
                    break
        return literals

    def _capstone(self):
        cs = getattr(self, '_cs', None)
        if cs is None:
            cs = capstone.Cs(
                capstone.CS_ARCH_ARM,
                capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS,
            )
            cs.detail = True
            self._cs = cs
        return cs

    def _decode_run(self, data: bytes, address: int):
        """Decodifica una secuencia de instrucciones a partir de address."""
        for cs_insn in self._capstone().disasm(data, address):
            yield _raw(cs_insn)


def _raw(cs_insn) -> RawInstruction:
    regs_read, regs_written = _get_reg_access(cs_insn)
    return RawInstruction(
        address=cs_insn.address,
        mnemonic=cs_insn.mnemonic,
        operands=cs_insn.op_str,
        bytes_hex=cs_insn.bytes.hex(),
        size=cs_insn.size,
        registers_read=regs_read,
        registers_written=regs_written,
    )
