"""
Disassembler ARM64: parsea binarios ELF AArch64 con lief y capstone.

Responsabilidades:
  - Validar que el binario es ELF AArch64.
  - Encontrar funciones desde la tabla de símbolos y el entry point.
  - Resolver entradas de la PLT (funciones de librería importadas).
  - Desensamblar las secciones ejecutables con capstone ARM64.
  - Devolver RawInstruction[] + BinaryMeta para que CFGBuilder construya el grafo.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import capstone
import lief

from flashback.arch.base import Disassembler
from flashback.core.cfg_builder import BinaryMeta, RawInstruction, ArchMnemonics, CFGBuilder
from flashback.arch.arm64.instruction_sem import (
    COND_BRANCH_MNEMONICS, CALL_MNEMONICS, RET_MNEMONICS,
)

logger = logging.getLogger(__name__)

# Funciones del runtime de C que no forman parte del código de usuario.
_C_RUNTIME = frozenset({
    '_start', '_init', '_fini',
    'frame_dummy', 'call_weak_fn',
    'register_tm_clones', 'deregister_tm_clones',
    '__do_global_dtors_aux', '__libc_start_main',
})

# Mnemonics ARM64 para CFGBuilder
_ARM64_COND_BRANCHES = COND_BRANCH_MNEMONICS
_ARM64_UNCOND_JUMPS  = frozenset({'b', 'br', 'braa', 'brab', 'braaz', 'brabz'})
_ARM64_CALLS         = CALL_MNEMONICS
_ARM64_RETURNS       = RET_MNEMONICS
_ARM64_SYSCALLS      = frozenset({'svc'})
_ARM64_HALTS         = frozenset({'hlt', 'brk', 'udf'})


def _arm64_resolve_branch_target(mnemonic: str, operands: str) -> int | None:
    """
    Resuelve la dirección de destino de una rama ARM64.
    Maneja el prefijo # y los formatos de cbz/cbnz/tbz/tbnz donde
    el target es el último operando separado por coma.
    """
    o = operands.strip()
    if not o:
        return None
    # Para cbz/cbnz/tbz/tbnz, el target es el último operando
    if mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        parts = o.rsplit(',', 1)
        o = parts[-1].strip()
    # Quitar prefijo # (notación ARM64 para inmediatos)
    if o.startswith('#'):
        o = o[1:]
    try:
        if o.startswith('0x') or o.startswith('-0x'):
            return int(o, 16)
        if o.lstrip('-').isdigit():
            return int(o)
    except ValueError:
        pass
    return None


_ARM64_MNEMONICS = ArchMnemonics(
    cond_branches=_ARM64_COND_BRANCHES,
    uncond_jumps=_ARM64_UNCOND_JUMPS,
    calls=_ARM64_CALLS,
    returns=_ARM64_RETURNS,
    syscalls=_ARM64_SYSCALLS,
    halts=_ARM64_HALTS,
    target_resolver=_arm64_resolve_branch_target,
)


class DisassemblerError(Exception):
    pass


class Arm64Disassembler(Disassembler):
    """
    Implementación del Disassembler para ELF AArch64 con lief + capstone.
    """

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
        """Override: usa ArchMnemonics ARM64 en CFGBuilder."""
        raw_insns, meta = self.load(binary_path)
        return CFGBuilder(
            tool_version=self.version,
            capstone_version=self.capstone_version,
            lief_version=self.lief_version,
            arch_mnemonics=_ARM64_MNEMONICS,
        ).build(raw_insns, meta)

    def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
        path = Path(binary_path)
        self._validate(path)

        logger.info(f'Cargando {path.name} con lief (ARM64)')
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
            architecture='arm64',
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
        if arch != lief.ELF.ARCH.AARCH64:
            raise DisassemblerError(f'Arquitectura no soportada: {arch}. Solo AArch64.')

    # ------------------------------------------------------------------
    # Descubrimiento de funciones
    # ------------------------------------------------------------------

    def _find_func_symbols(self, elf) -> dict[int, str]:
        """Encuentra funciones de usuario desde la tabla de símbolos."""
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
        Resuelve las entradas de la PLT para ARM64.

        Los stubs PLT de AArch64 siguen el patrón:
          adrp x16, #page      ; carga la página del slot GOT
          ldr  x17, [x16, #N]  ; carga el puntero de función del slot GOT
          br   x17             ; salta al puntero
        La dirección del slot GOT = page(adrp) + offset(ldr).
        Se busca en las relocalizaciones para obtener el nombre del símbolo.
        """
        plt_map: dict[int, str] = {}

        # Slot GOT → nombre de símbolo
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

        try:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            cs.detail = True
        except Exception:
            return plt_map

        for sect_name in ('.plt', '.plt.got'):
            try:
                section = elf.get_section(sect_name)
            except Exception:
                section = None
            if section is None:
                continue

            data  = bytes(section.content)
            base  = section.virtual_address
            insns = list(cs.disasm(data, base))

            i = 0
            while i < len(insns):
                insn = insns[i]
                # Buscar patrón: adrp + ldr + br
                if insn.mnemonic == 'adrp' and i + 2 < len(insns):
                    ldr_insn = insns[i + 1]
                    br_insn  = insns[i + 2]
                    if ldr_insn.mnemonic == 'ldr' and br_insn.mnemonic == 'br':
                        got_slot = _resolve_plt_got_slot(insn, ldr_insn)
                        if got_slot is not None:
                            name = got_to_name.get(got_slot)
                            if name:
                                plt_map[insn.address] = name
                        i += 3
                        continue
                i += 1

        return plt_map

    # ------------------------------------------------------------------
    # Desensamblado
    # ------------------------------------------------------------------

    def _disassemble(self, elf) -> dict[int, RawInstruction]:
        """Desensambla todas las secciones ejecutables."""
        try:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            cs.detail = True
        except Exception as e:
            raise DisassemblerError(f'No se pudo inicializar capstone ARM64: {e}')

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
        """Extrae los bytes de una sección con contenido."""
        try:
            section = elf.get_section(name)
            if section is not None:
                data = bytes(section.content)
                va = section.virtual_address
                logger.debug(f'{name}: {len(data)} bytes en 0x{va:x}')
                return va, data.hex()
        except Exception as e:
            logger.warning(f'No se pudo extraer {name}: {e}')
        return None, None

    def _extract_bss(self, elf) -> tuple[int | None, int | None]:
        try:
            section = elf.get_section('.bss')
            if section is not None:
                va = section.virtual_address
                size = int(section.size)
                logger.debug(f'.bss: {size} bytes en 0x{va:x}')
                return va, size
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
    func_syms = [
        s for s in elf.symbols
        if s.type == lief.ELF.Symbol.TYPE.FUNC and s.name
    ]
    return len(func_syms) == 0


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


def _resolve_plt_got_slot(adrp_insn, ldr_insn) -> int | None:
    """
    Calcula la dirección del slot GOT desde la secuencia adrp + ldr.
    Usa el modo detalle de capstone para extraer operandos.
    """
    try:
        from capstone import arm64 as a64
        # ADRP: operands[1].imm = dirección de página computada
        adrp_page = None
        for op in adrp_insn.operands:
            if op.type == a64.ARM64_OP_IMM:
                adrp_page = op.imm
                break
        if adrp_page is None:
            return None

        # LDR: operand de memoria con base=xN, disp=offset
        ldr_offset = None
        for op in ldr_insn.operands:
            if op.type == a64.ARM64_OP_MEM:
                ldr_offset = op.mem.disp
                break
        if ldr_offset is None:
            return None

        return adrp_page + ldr_offset
    except Exception:
        return None
