"""
Disassembler x86-64: parsea binarios ELF con lief y desensambla con capstone.

Reemplaza el extractor basado en angr. No usa IR intermedio: trabaja
directamente sobre los bytes del binario.

Responsabilidades:
  - Validar que el binario es ELF x86-64.
  - Encontrar funciones desde la tabla de símbolos y el entry point.
  - Resolver entradas de la PLT (funciones de librería importadas).
  - Desensamblar las secciones ejecutables con capstone.
  - Devolver RawInstruction[] + BinaryMeta para que CFGBuilder construya el grafo.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from pathlib import Path

import capstone
import lief

from flashback.arch.base import Disassembler
from flashback.core.cfg_builder import BinaryMeta, RawInstruction

logger = logging.getLogger(__name__)

# Funciones del runtime de C que no forman parte del código de usuario.
_C_RUNTIME = frozenset({
    '_start', 'frame_dummy', '_init', '_fini',
    '__libc_csu_init', '__libc_csu_fini',
    'register_tm_clones', 'deregister_tm_clones',
    '__do_global_dtors_aux', '__libc_start_main',
    '__x86.get_pc_thunk.bx',
})


class DisassemblerError(Exception):
    pass


class X86_64Disassembler(Disassembler):
    """
    Implementación del Disassembler para ELF x86-64 con lief + capstone.
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

    def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
        path = Path(binary_path)
        self._validate(path)

        logger.info(f'Cargando {path.name} con lief')
        elf = lief.parse(str(path))
        if elf is None:
            raise DisassemblerError(f'lief no pudo parsear: {path}')

        self._validate_arch(elf)

        func_symbols = self._find_func_symbols(elf)
        plt_symbols  = self._find_plt_symbols(elf)
        all_insns    = self._disassemble(elf)
        rodata_va, rodata_hex = self._extract_rodata(elf)
        data_va, data_hex = self._extract_section_bytes(elf, '.data')
        bss_va, bss_size = self._extract_bss(elf)
        jump_tables, jump_table_index_regs = self._find_jump_tables(elf, all_insns)

        meta = BinaryMeta(
            path=str(path.resolve()),
            sha256=_sha256(path),
            entry_point=elf.entrypoint,
            architecture='amd64',
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
            jump_tables=jump_tables,
            jump_table_index_regs=jump_table_index_regs,
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
        if arch != lief.ELF.ARCH.X86_64:
            raise DisassemblerError(f'Arquitectura no soportada: {arch}. Solo x86-64.')

    # ------------------------------------------------------------------
    # Descubrimiento de funciones
    # ------------------------------------------------------------------

    def _find_func_symbols(self, elf) -> dict[int, str]:
        """Encuentra funciones de usuario desde la tabla de símbolos."""
        funcs: dict[int, str] = {}

        # Entry point siempre incluido
        if elf.entrypoint:
            funcs[elf.entrypoint] = '_start'

        # Símbolos estáticos
        for sym in elf.symbols:
            if (sym.type == lief.ELF.Symbol.TYPE.FUNC
                    and sym.value != 0
                    and sym.name
                    and sym.name not in _C_RUNTIME):
                funcs[sym.value] = sym.name

        # Símbolos dinámicos definidos en este binario (no importados)
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
        Resuelve las entradas de la PLT (stubs de funciones importadas).

        Estrategia: cada stub de PLT termina en un salto indirecto
        ``jmp qword ptr [rip + disp]`` cuyo destino es el slot de la GOT
        asociado a una relocalización con símbolo. Se desensambla cada
        sección PLT y se asocia el inicio del stub con el símbolo cuya
        relocalización apunta a ese slot.

        Esto cubre de forma uniforme ``.plt`` clásica, ``.plt.sec``
        (binarios con CET, por defecto en gcc moderno: las llamadas
        apuntan a ``.plt.sec``, no a ``.plt``) y ``.plt.got``, sin
        depender de supuestos sobre el orden o el tamaño de las entradas.
        La estrategia anterior (relocalizaciones ordenadas = entradas
        consecutivas) fallaba con ``.plt.sec``: mapeaba los símbolos a las
        direcciones de ``.plt`` mientras los ``call`` del código apuntan a
        ``.plt.sec``, dejando todas las llamadas externas sin anotar.
        """
        plt_map: dict[int, str] = {}

        # Slot de GOT (dirección de la relocalización) → nombre de símbolo
        got_to_name: dict[int, str] = {}
        try:
            for reloc in elf.pltgot_relocations:
                if reloc.symbol and reloc.symbol.name:
                    name = _strip_symbol_decorations(reloc.symbol.name)
                    if name:
                        got_to_name[reloc.address] = name
            # .plt.got usa relocalizaciones GLOB_DAT (dynamic_relocations)
            for reloc in elf.dynamic_relocations:
                if reloc.symbol and reloc.symbol.name:
                    name = _strip_symbol_decorations(reloc.symbol.name)
                    if name:
                        got_to_name.setdefault(reloc.address, name)
        except Exception:
            return plt_map

        if not got_to_name:
            return plt_map

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        for sect_name in ('.plt', '.plt.sec', '.plt.got'):
            try:
                section = elf.get_section(sect_name)
            except Exception:
                section = None
            if section is None:
                continue

            data = bytes(section.content)
            base = section.virtual_address
            # .plt y .plt.sec alinean stubs a 16 bytes; .plt.got a 8
            align = 8 if sect_name == '.plt.got' else 16

            for cs_insn in cs.disasm(data, base):
                if not cs_insn.mnemonic.endswith('jmp'):
                    continue
                for op in cs_insn.operands:
                    if (op.type == capstone.x86.X86_OP_MEM
                            and op.mem.base == capstone.x86.X86_REG_RIP):
                        got_slot = cs_insn.address + cs_insn.size + op.mem.disp
                        name = got_to_name.get(got_slot)
                        if name:
                            stub = base + ((cs_insn.address - base) // align) * align
                            plt_map[stub] = name

        return plt_map

    # ------------------------------------------------------------------
    # Desensamblado
    # ------------------------------------------------------------------

    def _disassemble(self, elf) -> dict[int, RawInstruction]:
        """Desensambla todas las secciones ejecutables."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        all_insns: dict[int, RawInstruction] = {}

        for section in elf.sections:
            if not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                continue
            # Saltar la PLT (stubs externos, no son código de usuario)
            if section.name in ('.plt', '.plt.sec', '.plt.got'):
                continue

            data = bytes(section.content)
            base = section.virtual_address

            for cs_insn in cs.disasm(data, base):
                regs_read, regs_written = _get_reg_access(cs_insn)
                # El prefijo CET 'notrack' (3e) es una pista para el hardware sin
                # efecto semántico en la traducción; se normaliza para que el
                # CFGBuilder y el Translator traten 'notrack jmp' como 'jmp'.
                mnem = cs_insn.mnemonic
                if mnem.startswith('notrack '):
                    mnem = mnem[len('notrack '):]
                all_insns[cs_insn.address] = RawInstruction(
                    address=cs_insn.address,
                    mnemonic=mnem,
                    operands=cs_insn.op_str,
                    bytes_hex=cs_insn.bytes.hex(),
                    size=cs_insn.size,
                    registers_read=regs_read,
                    registers_written=regs_written,
                )

        return all_insns

    def _extract_rodata(self, elf) -> tuple[int | None, str | None]:
        """Extrae la sección .rodata del binario usando lief."""
        return self._extract_section_bytes(elf, '.rodata')

    def _extract_section_bytes(self, elf, name: str) -> tuple[int | None, str | None]:
        """Extrae los bytes de una sección con contenido (p. ej. .rodata, .data)."""
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
        """
        Extrae la dirección y el tamaño de .bss (sin contenido: es memoria
        inicializada a cero, por lo que solo se necesita su tamaño).
        """
        try:
            section = elf.get_section('.bss')
            if section is not None:
                va = section.virtual_address
                size = int(section.size)
                logger.debug(f'.bss: {size} bytes en 0x{va:x} (zero-init)')
                return va, size
        except Exception as e:
            logger.warning(f'No se pudo extraer .bss: {e}')
        return None, None

    def _find_jump_tables(
        self, elf, raw_insns: dict[int, RawInstruction],
    ) -> tuple[dict[int, list[int]], dict[int, str]]:
        """
        Fase 1: heurística para detectar tablas de salto (switch-case) en x86-64.

        Detecta dos patrones generados por GCC/Clang:

        P1 – Indexado absoluto (no PIE):
            jmp qword ptr [ridx*8 + TABLE_VA]
            Entradas: punteros de 64 bits en .rodata/.data

        P2 – RIP-relativo con movsxd (PIE):
            lea rdx, [rip + TABLE_OFFSET]
            movsxd rax, dword ptr [rdx + rcx*4]
            add rdx, rax
            jmp rdx
            Entradas: offsets de 32 bits relativos a TABLE_VA

        P3 – Base+index en memoria (GCC O2, no PIE):
            jmp qword ptr [rdx + rax*8]
            precedido de: lea rdx, [rip + TABLE_VA]
            Entradas: punteros de 64 bits

        Limitación documentada: VSA completo queda fuera de alcance.
        """
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        is_pie = bool(elf.is_pie)

        # Secciones de datos donde pueden residir las tablas
        data_sects: list[tuple[int, bytes]] = []
        for name in ('.rodata', '.data', '.data.rel.ro'):
            try:
                sect = elf.get_section(name)
            except Exception:
                sect = None
            if sect is not None:
                data_sects.append((sect.virtual_address, bytes(sect.content)))

        jump_tables: dict[int, list[int]] = {}
        index_regs: dict[int, str] = {}

        for section in elf.sections:
            if not section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                continue
            if section.name in ('.plt', '.plt.sec', '.plt.got'):
                continue

            sect_data = bytes(section.content)
            sect_base = section.virtual_address
            # Ventana deslizante con detalle capstone para backward scan
            prev_insns: list = []

            for cs_insn in cs.disasm(sect_data, sect_base):
                if not cs_insn.mnemonic.endswith('jmp'):
                    prev_insns.append(cs_insn)
                    if len(prev_insns) > 24:
                        prev_insns.pop(0)
                    continue

                if not cs_insn.operands:
                    prev_insns.append(cs_insn)
                    continue

                op = cs_insn.operands[0]
                table_va: int | None = None
                idx_reg: str = ''
                p4_rel_base: int | None = None

                if op.type == capstone.x86.X86_OP_MEM:
                    m = op.mem
                    # P1: [ridx*scale + disp] — sin base, disp es la dirección de la tabla
                    if (m.base == 0 and m.index != 0
                            and m.scale in (4, 8) and m.disp > 0):
                        table_va = m.disp
                        idx_reg = cs_insn.reg_name(m.index)

                    # P3: [base_reg + idx*scale] — backward slice para lea base_reg,[rip+off]
                    elif (m.base != 0 and m.index != 0
                          and m.scale in (4, 8)
                          and m.base != capstone.x86.X86_REG_RIP):
                        base_reg_id = m.base
                        for pi in reversed(prev_insns):
                            if pi.mnemonic != 'lea' or not pi.operands:
                                continue
                            dst_op = pi.operands[0]
                            src_op = pi.operands[1]
                            if (dst_op.type == capstone.x86.X86_OP_REG
                                    and dst_op.reg == base_reg_id
                                    and src_op.type == capstone.x86.X86_OP_MEM
                                    and src_op.mem.base == capstone.x86.X86_REG_RIP):
                                table_va = pi.address + pi.size + src_op.mem.disp
                                idx_reg = cs_insn.reg_name(m.index)
                                break

                elif op.type == capstone.x86.X86_OP_REG:
                    # P2: jmp rdx — buscar hacia atrás: lea rdx,[rip+off] + movsxd
                    jmp_reg_id = op.reg
                    lea_va: int | None = None
                    movsxd_idx: str = ''
                    # P4 (GCC -O0 no-PIE): mov eax,[idx + tablebase];
                    #   lea tablebase,[rip+X]; lea relbase,[rip+Y]; add rax,relbase; jmp rax
                    #   tabla de offsets rel32 relativos a relbase.
                    p4_table_va: int | None = None
                    p4_rel_base: int | None = None
                    p4_idx: str = ''
                    p4_scaled_idx: str = ''
                    rip_leas: list[int] = []
                    for pi in reversed(prev_insns):
                        if pi.mnemonic == 'lea' and pi.operands:
                            dst_op = pi.operands[0]
                            src_op = pi.operands[1]
                            if (dst_op.type == capstone.x86.X86_OP_REG
                                    and dst_op.reg == jmp_reg_id
                                    and src_op.type == capstone.x86.X86_OP_MEM
                                    and src_op.mem.base == capstone.x86.X86_REG_RIP):
                                lea_va = pi.address + pi.size + src_op.mem.disp
                            # recoger todas las lea [rip+x] para el patrón P4
                            if (src_op.type == capstone.x86.X86_OP_MEM
                                    and src_op.mem.base == capstone.x86.X86_REG_RIP):
                                rip_leas.append(pi.address + pi.size + src_op.mem.disp)
                        elif pi.mnemonic in ('movsxd', 'movsx') and pi.operands:
                            src_op = pi.operands[1]
                            if (src_op.type == capstone.x86.X86_OP_MEM
                                    and src_op.mem.scale in (4, 8)
                                    and src_op.mem.index != 0):
                                movsxd_idx = pi.reg_name(src_op.mem.index)
                        elif pi.mnemonic == 'mov' and pi.operands:
                            # mov eax, dword ptr [base + idx]  → lectura de la tabla (4 bytes)
                            src_op = pi.operands[1]
                            if (src_op.type == capstone.x86.X86_OP_MEM
                                    and src_op.mem.index != 0
                                    and src_op.mem.base != 0
                                    and src_op.mem.base != capstone.x86.X86_REG_RIP):
                                p4_idx = pi.reg_name(src_op.mem.index)
                        # lea reg, [idxreg*scale]  → fuente inequívoca del índice
                        if (pi.mnemonic == 'lea' and pi.operands
                                and pi.operands[1].type == capstone.x86.X86_OP_MEM
                                and pi.operands[1].mem.scale in (4, 8)
                                and pi.operands[1].mem.index != 0
                                and pi.operands[1].mem.base == 0):
                            p4_scaled_idx = pi.reg_name(pi.operands[1].mem.index)
                    if p4_scaled_idx and len(rip_leas) >= 2:
                        # P4 (GCC -O0 no-PIE): tabla de offsets rel32 con base
                        # separada. Tiene prioridad porque el lea que carga el
                        # registro de salto también casa con P2 pero sin índice.
                        p4_table_va = rip_leas[-1]
                        p4_rel_base = rip_leas[0]
                        table_va = p4_table_va
                        idx_reg = p4_scaled_idx
                    elif lea_va is not None:
                        table_va = lea_va
                        idx_reg = movsxd_idx
                    elif p4_idx and len(rip_leas) >= 2:
                        p4_table_va = rip_leas[-1]
                        p4_rel_base = rip_leas[0]
                        table_va = p4_table_va
                        idx_reg = p4_scaled_idx or p4_idx

                prev_insns.append(cs_insn)
                if len(prev_insns) > 24:
                    prev_insns.pop(0)

                if table_va is None:
                    continue

                targets = _read_jt_entries(table_va, data_sects, raw_insns, is_pie,
                                           rel_base=p4_rel_base)
                if len(targets) >= 2:
                    jump_tables[cs_insn.address] = targets
                    index_regs[cs_insn.address] = idx_reg
                    logger.debug(
                        f'Tabla de salto en 0x{cs_insn.address:x}: '
                        f'{len(targets)} destinos, base=0x{table_va:x}, idx={idx_reg}'
                    )

            prev_insns.clear()

        logger.info(f'Tablas de salto detectadas: {len(jump_tables)}')
        return jump_tables, index_regs


# ---------------------------------------------------------------------------
# Utilidades privadas
# ---------------------------------------------------------------------------

def _read_jt_entries(
    table_va: int,
    data_sects: list[tuple[int, bytes]],
    raw_insns: dict[int, RawInstruction],
    is_pie: bool,
    max_entries: int = 256,
    rel_base: int | None = None,
) -> list[int]:
    """
    Lee las entradas de una tabla de salto desde las secciones de datos.

    No asume el formato a partir del flag PIE (que resultaba insuficiente para
    los binarios no-PIE de GCC con entradas de 4 bytes relativas). En su lugar
    prueba los tres formatos habituales y devuelve el que produzca el mayor
    número de destinos válidos (entradas que apuntan a instrucciones conocidas):

      - rel32: offsets de 32 bits con signo relativos a una base (rel_base si se
        conoce; en su defecto, la propia dirección de la tabla). Es el formato
        de GCC, tanto en PIE como en no-PIE.
      - abs64: punteros absolutos de 64 bits (GCC/Clang no-PIE clásico).
      - abs32: punteros absolutos de 32 bits (modelo de memoria pequeño no-PIE).

    Para en cuanto una entrada no apunta a una instrucción conocida.
    """
    base_for_rel = rel_base if rel_base is not None else table_va

    def _read(fmt: str) -> list[int]:
        for sect_va, sect_data in data_sects:
            if not (sect_va <= table_va < sect_va + len(sect_data)):
                continue
            offset = table_va - sect_va
            out: list[int] = []
            for i in range(max_entries):
                if fmt == 'rel32':
                    pos = offset + i * 4
                    if pos + 4 > len(sect_data):
                        break
                    (rel,) = struct.unpack_from('<i', sect_data, pos)
                    target = base_for_rel + rel
                elif fmt == 'abs64':
                    pos = offset + i * 8
                    if pos + 8 > len(sect_data):
                        break
                    (target,) = struct.unpack_from('<Q', sect_data, pos)
                else:  # abs32
                    pos = offset + i * 4
                    if pos + 4 > len(sect_data):
                        break
                    (target,) = struct.unpack_from('<I', sect_data, pos)
                if target == 0 or target not in raw_insns:
                    break
                out.append(target)
            return out
        return []

    # Probar los tres formatos y quedarse con el que más destinos válidos da.
    candidates = [_read('rel32'), _read('abs64'), _read('abs32')]
    best = max(candidates, key=len)
    return best


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
    """Quita @plt, @@GLIBC_2.x, etc."""
    for sep in ('@@', '@'):
        if sep in name:
            name = name.split(sep)[0]
    return name.strip()


def _get_reg_access(cs_insn) -> tuple[list[str], list[str]]:
    """Extrae registros leídos y escritos de una instrucción capstone."""
    try:
        r_ids, w_ids = cs_insn.regs_access()
        return (
            [cs_insn.reg_name(r) for r in r_ids],
            [cs_insn.reg_name(w) for w in w_ids],
        )
    except Exception:
        return [], []
