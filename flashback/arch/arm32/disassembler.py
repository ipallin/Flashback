"""
Disassembler ARM32: parsea binarios ELF ARM (32-bit) con lief y capstone.

PLT ARM32: stubs de 12 bytes cada uno precedidos por un encabezado de 20 bytes.
La estrategia de resolución de PLT usa el stride clásico (20 + n*12) y correlaciona
con las relocalizaciones pltgot ordenadas por dirección de GOT.

Soporte de Thumb: las funciones con bit 0 set en el símbolo están en Thumb mode;
se desensamblán con CS_MODE_THUMB.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import capstone
import lief

from flashback.arch.base import Disassembler
from flashback.core.cfg_builder import (
    BinaryMeta, RawInstruction, ArchMnemonics, CFGBuilder,
)
from flashback.arch.arm32.instruction_sem import (
    COND_BRANCH_MNEMONICS, UNCOND_JUMP_MNEMONICS,
    CALL_MNEMONICS, SYSCALL_MNEMONICS,
    classify_arm_flow, literal_reference, resolve_arm_branch_target,
)

logger = logging.getLogger(__name__)

_C_RUNTIME = frozenset({
    '_start', '_init', '_fini',
    'frame_dummy', 'call_weak_fn',
    'register_tm_clones', 'deregister_tm_clones',
    '__do_global_dtors_aux', '__libc_start_main',
})


_ARM32_MNEMONICS = ArchMnemonics(
    cond_branches=COND_BRANCH_MNEMONICS,
    uncond_jumps=UNCOND_JUMP_MNEMONICS | frozenset({'bx'}),
    calls=CALL_MNEMONICS,
    returns=frozenset({'bx'}),
    syscalls=SYSCALL_MNEMONICS,
    halts=frozenset({'udf', 'bkpt'}),
    target_resolver=resolve_arm_branch_target,
    # Los conjuntos anteriores son orientativos: la clasificación real la hace
    # classify_arm_flow por operando (bx lr vs bx r3, pop {pc}, sufijos .w/cond).
    classifier=classify_arm_flow,
)


class DisassemblerError(Exception):
    pass


class Arm32Disassembler(Disassembler):
    """Disassembler para ELF ARM (32-bit) con lief + capstone."""

    def __init__(self):
        try:
            self.capstone_version = str(capstone.__version__)
        except Exception:
            self.capstone_version = 'unknown'
        try:
            self.lief_version = lief.__version__
        except Exception:
            self.lief_version = 'unknown'

    def disassemble(self, binary_path: str):
        raw_insns, meta = self.load(binary_path)
        return CFGBuilder(
            tool_version=self.version,
            capstone_version=self.capstone_version,
            lief_version=self.lief_version,
            arch_mnemonics=_ARM32_MNEMONICS,
        ).build(raw_insns, meta)

    def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
        path = Path(binary_path)
        self._validate(path)

        logger.info(f'Cargando {path.name} con lief (ARM32)')
        elf = lief.parse(str(path))
        if elf is None:
            raise DisassemblerError(f'lief no pudo parsear: {path}')

        self._validate_arch(elf)

        func_symbols = self._find_func_symbols(elf)
        plt_symbols  = self._find_plt_symbols(elf)
        all_insns    = self._disassemble(elf)
        rodata_va, rodata_hex = self._extract_section_bytes(elf, '.rodata')
        data_va, data_hex = self._extract_section_bytes(elf, '.data')
        bss_va, bss_size = self._extract_bss(elf)

        meta = BinaryMeta(
            path=str(path.resolve()),
            sha256=_sha256(path),
            entry_point=elf.entrypoint & ~1,  # strip Thumb bit
            architecture='arm32',
            is_pie=bool(elf.is_pie),
            is_stripped=_is_stripped(elf),
            func_symbols=func_symbols,
            plt_symbols=plt_symbols,
            rodata_va=rodata_va,
            rodata_hex=rodata_hex,
            data_va=data_va,
            data_hex=data_hex,
            bss_va=bss_va,
            bss_size=bss_size,
            literals=self._literal_values,
        )
        logger.info(
            f'Desensamblado: {len(func_symbols)} funciones, '
            f'{len(plt_symbols)} PLT, {len(all_insns)} instrucciones'
        )
        return all_insns, meta

    # ------------------------------------------------------------------
    # Validación
    # ------------------------------------------------------------------

    def _validate(self, path: Path) -> None:
        if not path.exists():
            raise DisassemblerError(f'Binario no encontrado: {path}')
        if not path.is_file():
            raise DisassemblerError(f'La ruta no es un fichero: {path}')
        with open(path, 'rb') as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            raise DisassemblerError(f'El fichero no es ELF: {path}')

    def _validate_arch(self, elf) -> None:
        arch = elf.header.machine_type
        if arch != lief.ELF.ARCH.ARM:
            raise DisassemblerError(f'Arquitectura no soportada: {arch}. Solo ARM (32-bit).')

    # ------------------------------------------------------------------
    # Descubrimiento de funciones
    # ------------------------------------------------------------------

    def _find_func_symbols(self, elf) -> dict[int, str]:
        funcs: dict[int, str] = {}
        entry = elf.entrypoint & ~1
        if entry:
            funcs[entry] = '_start'
        for sym in elf.symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _C_RUNTIME):
                addr = sym.value & ~1  # strip Thumb bit
                funcs[addr] = sym.name
        for sym in elf.dynamic_symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _C_RUNTIME):
                addr = sym.value & ~1
                if addr not in funcs:
                    funcs[addr] = sym.name
        return funcs

    def _find_plt_symbols(self, elf) -> dict[int, str]:
        """
        PLT ARM32 clásico: encabezado de 20 bytes + stubs de 12 bytes cada uno.
        Los stubs se correlacionan con pltgot_relocations ordenadas por GOT address.
        """
        plt_map: dict[int, str] = {}

        try:
            plt_section = elf.get_section('.plt')
        except Exception:
            plt_section = None
        if plt_section is None:
            return plt_map

        plt_base = plt_section.virtual_address

        # Recopilar relocalizaciones PLT/GOT ordenadas
        relocs: list[tuple[int, str]] = []
        try:
            for reloc in elf.pltgot_relocations:
                if reloc.symbol and reloc.symbol.name:
                    name = _strip_symbol_decorations(reloc.symbol.name)
                    if name:
                        relocs.append((reloc.address, name))
        except Exception:
            return plt_map

        relocs.sort(key=lambda x: x[0])

        # Layout: 20 bytes de encabezado + 12 bytes por stub
        PLT_HEADER = 20
        PLT_STUB  = 12
        for i, (_, name) in enumerate(relocs):
            stub_addr = plt_base + PLT_HEADER + i * PLT_STUB
            plt_map[stub_addr] = name

        return plt_map

    # ------------------------------------------------------------------
    # Desensamblado
    # ------------------------------------------------------------------

    def _disassemble(self, elf) -> dict[int, RawInstruction]:
        """
        Desensambla secciones ejecutables en modo ARM.
        Las secciones Thumb (bit T en e_flags o símbolos con LSB=1) se prueban
        también en modo Thumb; prevalece el modo que produce más instrucciones válidas.
        """
        cs_arm   = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        cs_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        cs_arm.detail   = True
        cs_thumb.detail = True

        all_insns: dict[int, RawInstruction] = {}
        self._literal_values: dict[int, tuple[int, bytes]] = {}

        for section in elf.sections:
            if not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                continue
            if section.name in ('.plt',):
                continue

            data = bytes(section.content)
            base = section.virtual_address

            # Intentar ARM y Thumb; usar el que produzca más instrucciones
            arm_insns   = list(cs_arm.disasm(data, base))
            thumb_insns = list(cs_thumb.disasm(data, base))
            chosen = arm_insns if len(arm_insns) >= len(thumb_insns) else thumb_insns
            thumb = chosen is thumb_insns

            for cs_insn in chosen:
                ref = literal_reference(cs_insn.mnemonic, cs_insn.op_str, cs_insn.address, thumb)
                if ref is not None and base <= ref[0] and ref[0] + ref[1] <= base + len(data):
                    off = ref[0] - base
                    self._literal_values[cs_insn.address] = (ref[0], data[off:off + ref[1]])
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

        return all_insns

    def _extract_section_bytes(self, elf, name: str) -> tuple[int | None, str | None]:
        try:
            section = elf.get_section(name)
            if section is not None:
                data = bytes(section.content)
                return section.virtual_address, data.hex()
        except Exception as e:
            logger.warning(f'No se pudo extraer {name}: {e}')
        return None, None

    def _extract_bss(self, elf) -> tuple[int | None, int | None]:
        try:
            section = elf.get_section('.bss')
            if section is not None:
                return section.virtual_address, int(section.size)
        except Exception as e:
            logger.warning(f'No se pudo extraer .bss: {e}')
        return None, None


# ---------------------------------------------------------------------------
# Utilidades privadas
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _is_stripped(elf) -> bool:
    return len([s for s in elf.symbols
                if s.type == lief.ELF.Symbol.TYPE.FUNC and s.name]) == 0


def _strip_symbol_decorations(name: str) -> str:
    for sep in ('@@', '@'):
        if sep in name:
            name = name.split(sep)[0]
    return name.strip()


def _get_reg_access(cs_insn) -> tuple[list[str], list[str]]:
    try:
        r_ids, w_ids = cs_insn.regs_access()
        return (
            [cs_insn.reg_name(r) for r in r_ids],
            [cs_insn.reg_name(w) for w in w_ids],
        )
    except Exception:
        return [], []
