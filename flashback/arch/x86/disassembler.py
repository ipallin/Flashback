"""
Disassembler x86 (32-bit): parsea binarios ELF i386 con lief y capstone.

PLT x86: cada stub es un salto indirecto ``jmp DWORD PTR [got_slot]``
donde got_slot es la dirección absoluta del slot de la GOT.
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
from flashback.arch.x86.instruction_sem import COND_BRANCH_MNEMONICS

logger = logging.getLogger(__name__)

_C_RUNTIME = frozenset({
    '_start', 'frame_dummy', '_init', '_fini',
    '__libc_csu_init', '__libc_csu_fini',
    'register_tm_clones', 'deregister_tm_clones',
    '__do_global_dtors_aux', '__libc_start_main',
    '__x86.get_pc_thunk.bx', '__x86.get_pc_thunk.cx',
    '__x86.get_pc_thunk.dx', '__x86.get_pc_thunk.ax',
})

_X86_MNEMONICS = ArchMnemonics(
    cond_branches=COND_BRANCH_MNEMONICS,
    uncond_jumps=frozenset({'jmp'}),
    calls=frozenset({'call'}),
    returns=frozenset({'ret', 'retn', 'retf'}),
    syscalls=frozenset({'int'}),
    halts=frozenset({'hlt'}),
)


class DisassemblerError(Exception):
    pass


class X86Disassembler(Disassembler):
    """Disassembler para ELF i386 con lief + capstone."""

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
            arch_mnemonics=_X86_MNEMONICS,
        ).build(raw_insns, meta)

    def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
        path = Path(binary_path)
        self._validate(path)

        logger.info(f'Cargando {path.name} con lief (x86 32-bit)')
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
            entry_point=elf.entrypoint,
            architecture='i386',
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
        if arch != lief.ELF.ARCH.I386:
            raise DisassemblerError(f'Arquitectura no soportada: {arch}. Solo x86 (i386).')

    # ------------------------------------------------------------------
    # Descubrimiento de funciones
    # ------------------------------------------------------------------

    def _find_func_symbols(self, elf) -> dict[int, str]:
        funcs: dict[int, str] = {}
        if elf.entrypoint:
            funcs[elf.entrypoint] = '_start'
        for sym in elf.symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _C_RUNTIME):
                funcs[sym.value] = sym.name
        for sym in elf.dynamic_symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _C_RUNTIME
                    and sym.value not in funcs):
                funcs[sym.value] = sym.name
        return funcs

    def _find_plt_symbols(self, elf) -> dict[int, str]:
        """
        PLT x86: stubs de 16 bytes con encabezado de 16 bytes.
        Cada stub: jmp [got_slot] (6 bytes) + push idx (5 bytes) + jmp plt0 (5 bytes).
        La dirección del slot GOT se lee directamente del operando del jmp.
        """
        plt_map: dict[int, str] = {}

        got_to_name: dict[int, str] = {}
        try:
            for reloc in elf.pltgot_relocations:
                if reloc.symbol and reloc.symbol.name:
                    name = _strip_symbol_decorations(reloc.symbol.name)
                    if name:
                        got_to_name[reloc.address] = name
            for reloc in elf.dynamic_relocations:
                if reloc.symbol and reloc.symbol.name:
                    name = _strip_symbol_decorations(reloc.symbol.name)
                    if name:
                        got_to_name.setdefault(reloc.address, name)
        except Exception:
            return plt_map

        if not got_to_name:
            return plt_map

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        for sect_name in ('.plt', '.plt.got'):
            try:
                section = elf.get_section(sect_name)
            except Exception:
                section = None
            if section is None:
                continue

            data = bytes(section.content)
            base = section.virtual_address
            align = 8 if sect_name == '.plt.got' else 16

            for cs_insn in cs.disasm(data, base):
                if cs_insn.mnemonic != 'jmp':
                    continue
                for op in cs_insn.operands:
                    if (op.type == capstone.x86.X86_OP_MEM
                            and op.mem.base == 0
                            and op.mem.index == 0):
                        got_slot = op.mem.disp & 0xFFFFFFFF
                        name = got_to_name.get(got_slot)
                        if name:
                            stub = base + ((cs_insn.address - base) // align) * align
                            plt_map[stub] = name

        return plt_map

    # ------------------------------------------------------------------
    # Desensamblado
    # ------------------------------------------------------------------

    def _disassemble(self, elf) -> dict[int, RawInstruction]:
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        all_insns: dict[int, RawInstruction] = {}

        for section in elf.sections:
            if not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                continue
            if section.name in ('.plt', '.plt.got'):
                continue

            data = bytes(section.content)
            base = section.virtual_address

            for cs_insn in cs.disasm(data, base):
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
                va = section.virtual_address
                return va, data.hex()
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
