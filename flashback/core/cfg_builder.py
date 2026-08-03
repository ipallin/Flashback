"""
CFGBuilder: construye el EnrichedCFG a partir de instrucciones ya desensambladas.

Recibe datos crudos producidos por un Disassembler y produce la estructura
de grafos completa (bloques básicos, aristas, funciones) con integridad
referencial garantizada.

La separación Disassembler → CFGBuilder permite que la lógica de construcción
del grafo sea agnóstica de arquitectura: cambia el Disassembler (x86_64, arm64),
no este módulo.
"""

from __future__ import annotations

import bisect
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional
from pathlib import Path

from flashback.core.models import (
    EnrichedCFG, Function, BasicBlock, Instruction, Edge,
    Metadata, BinaryInfo, hex_addr, JumpTableAnnotation,
)

logger = logging.getLogger(__name__)


@dataclass
class ArchMnemonics:
    """Conjuntos de mnemonics específicos de arquitectura para CFGBuilder."""
    cond_branches: frozenset   # ramas condicionales (2 sucesores: tomada + fall)
    uncond_jumps: frozenset    # saltos incondicionales (1 o 0 sucesores)
    calls: frozenset           # instrucciones call (1 sucesor = return address)
    returns: frozenset         # instrucciones de retorno (0 sucesores)
    syscalls: frozenset        # syscall-like (1 sucesor fall-through)
    halts: frozenset           # halt-like (0 sucesores)
    # Resolver de target: (mnemonic, operands) -> int | None
    target_resolver: Optional[Callable[[str, str], Optional[int]]] = None

    @property
    def all_terminators(self) -> frozenset:
        return (self.cond_branches | self.uncond_jumps | self.calls
                | self.returns | self.syscalls | self.halts)

    def resolve_target(self, mnemonic: str, operands: str) -> Optional[int]:
        if self.target_resolver is not None:
            return self.target_resolver(mnemonic, operands)
        return _resolve_direct_addr(operands)


@dataclass
class RawInstruction:
    """Instrucción desensamblada tal como la produce el Disassembler."""
    address: int
    mnemonic: str
    operands: str
    bytes_hex: str
    size: int
    registers_read: list[str] = field(default_factory=list)
    registers_written: list[str] = field(default_factory=list)


@dataclass
class BinaryMeta:
    """Metadatos del binario extraídos por el Disassembler."""
    path: str
    sha256: str
    entry_point: int
    architecture: str = 'amd64'
    is_pie: bool = False
    is_stripped: bool = False
    # addr → name para todas las funciones (incluyendo PLT)
    func_symbols: dict[int, str] = field(default_factory=dict)
    # addr → name solo para funciones PLT (externas)
    plt_symbols: dict[int, str] = field(default_factory=dict)
    rodata_va: Optional[int] = None   # Dirección virtual de .rodata
    rodata_hex: Optional[str] = None  # Bytes de .rodata en hex
    data_va: Optional[int] = None     # Dirección virtual de .data
    data_hex: Optional[str] = None    # Bytes de .data en hex
    bss_va: Optional[int] = None      # Dirección virtual de .bss
    bss_size: Optional[int] = None    # Tamaño de .bss (zero-init)
    # Tablas de salto resueltas por el disassembler (Fase 1):
    #   addr_del_jmp → lista de targets VA (absolutos)
    jump_tables: dict = field(default_factory=dict)
    #   addr_del_jmp → nombre del registro índice ('rax', 'rcx', ...)
    jump_table_index_regs: dict = field(default_factory=dict)


class CFGBuilder:
    """
    Construye un EnrichedCFG (pipeline_stage='initial') a partir de:
      - Un dict[int, RawInstruction] con todas las instrucciones desensambladas.
      - Un BinaryMeta con metadatos del binario.
      - Versión de la herramienta y versiones de las librerías usadas.
    """

    def __init__(self, tool_version: str = '0.1.0',
                 capstone_version: str = '', lief_version: str = '',
                 arch_mnemonics: Optional[ArchMnemonics] = None):
        self.tool_version = tool_version
        self.capstone_version = capstone_version
        self.lief_version = lief_version
        self._arch_m = arch_mnemonics if arch_mnemonics is not None else _X86_MNEMONICS

    def build(self, raw_insns: dict[int, RawInstruction], meta: BinaryMeta) -> EnrichedCFG:
        logger.info(f'Construyendo CFG: {len(raw_insns)} instrucciones, '
                    f'{len(meta.func_symbols)} funciones')

        cfg = EnrichedCFG(
            metadata=Metadata(
                generator='flashback',
                generator_version=self.tool_version,
                pipeline_stage='initial',
                capstone_version=self.capstone_version or None,
                lief_version=self.lief_version or None,
            ),
            binary_info=BinaryInfo(
                filename=Path(meta.path).name,
                path=meta.path,
                sha256=meta.sha256,
                entry_point=hex_addr(meta.entry_point),
                architecture=meta.architecture,
                is_pie=meta.is_pie,
                is_stripped=meta.is_stripped,
                rodata_va=meta.rodata_va,
                rodata_hex=meta.rodata_hex,
                data_va=meta.data_va,
                data_hex=meta.data_hex,
                bss_va=meta.bss_va,
                bss_size=meta.bss_size,
            ),
        )

        # 1. Añadir funciones PLT (externas, sin bloques)
        for plt_addr, plt_name in meta.plt_symbols.items():
            addr_str = hex_addr(plt_addr)
            cfg.functions[addr_str] = Function(
                address=addr_str, name=plt_name,
                is_plt=True, is_external=True,
                entry_block=addr_str,
            )

        # 2. Identificar todos los bloques básicos
        func_starts = set(meta.func_symbols.keys())
        arch_m = self._arch_m
        block_starts = _identify_block_starts(raw_insns, func_starts, arch_m,
                                              jump_tables=meta.jump_tables)
        raw_blocks   = _build_raw_blocks(raw_insns, block_starts, arch_m)

        # 3. Asignar cada bloque a una función
        block_to_func = _assign_blocks_to_functions(raw_blocks, func_starts)

        # 4. Añadir funciones de usuario
        func_blocks: dict[int, list[int]] = {f: [] for f in func_starts}
        for block_addr, func_addr in block_to_func.items():
            if func_addr in func_blocks:
                func_blocks[func_addr].append(block_addr)

        for func_addr, func_name in meta.func_symbols.items():
            addr_str   = hex_addr(func_addr)
            block_list = sorted(func_blocks.get(func_addr, []))
            cfg.functions[addr_str] = Function(
                address=addr_str, name=func_name,
                is_plt=False, is_external=False,
                entry_block=addr_str,
                blocks=[hex_addr(b) for b in block_list],
            )

        # 5. Construir bloques e instrucciones
        for block_start, insn_addrs in raw_blocks.items():
            func_addr = block_to_func.get(block_start)
            if func_addr is None:
                continue

            block_addr_str = hex_addr(block_start)
            func_addr_str  = hex_addr(func_addr)

            for addr in insn_addrs:
                ri = raw_insns[addr]
                cfg.instructions[hex_addr(addr)] = Instruction(
                    address=hex_addr(addr),
                    mnemonic=ri.mnemonic,
                    operands=ri.operands,
                    bytes=ri.bytes_hex,
                    size=ri.size,
                    block=block_addr_str,
                    registers_read=ri.registers_read,
                    registers_written=ri.registers_written,
                )

            last_ri = raw_insns[insn_addrs[-1]]
            successors = _compute_successors(
                last_ri, raw_insns, block_starts,
                meta.plt_symbols, meta.func_symbols, arch_m,
                jump_tables=meta.jump_tables,
            )
            # Anotar instrucciones que son sitios de tabla de salto (Fase 1)
            if meta.jump_tables and last_ri.address in meta.jump_tables:
                jt_targets = meta.jump_tables[last_ri.address]
                idx_reg = meta.jump_table_index_regs.get(last_ri.address, '')
                ann = JumpTableAnnotation(
                    added_by='cfg_builder',
                    index_register=idx_reg,
                    base_address=last_ri.address,
                    targets=[hex_addr(t) for t in jt_targets],
                )
                cfg.instructions[hex_addr(last_ri.address)].annotations.append(ann)

            total_size = sum(raw_insns[a].size for a in insn_addrs)

            cfg.basic_blocks[block_addr_str] = BasicBlock(
                address=block_addr_str, size=total_size,
                function=func_addr_str,
                instructions=[hex_addr(a) for a in insn_addrs],
                successors=[hex_addr(s) for s in successors],
            )

        # 6. Rellenar predecessors
        for block_addr, block in cfg.basic_blocks.items():
            for succ_addr in block.successors:
                if succ_addr in cfg.basic_blocks:
                    if block_addr not in cfg.basic_blocks[succ_addr].predecessors:
                        cfg.basic_blocks[succ_addr].predecessors.append(block_addr)

        # 7. Construir aristas
        cfg.edges = _build_edges(raw_insns, cfg.basic_blocks, cfg.functions, arch_m)

        # 8. Rellenar calls_to / called_from entre funciones
        _fill_call_relations(cfg, raw_insns, arch_m)

        n_funcs  = sum(1 for f in cfg.functions.values() if not f.is_plt)
        n_blocks = len(cfg.basic_blocks)
        n_insns  = len(cfg.instructions)
        logger.info(f'CFG construido: {n_funcs} funciones, {n_blocks} bloques, '
                    f'{n_insns} instrucciones, {len(cfg.edges)} aristas')
        return cfg


# ---------------------------------------------------------------------------
# Algoritmo de construcción de bloques
# ---------------------------------------------------------------------------

# Mnemonics x86-64 por defecto (usados cuando no se pasa arch_mnemonics)
_X86_MNEMONICS = ArchMnemonics(
    cond_branches=frozenset({
        'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
        'jb', 'jbe', 'ja', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
        'jrcxz', 'jecxz', 'loop', 'loope', 'loopne',
    }),
    uncond_jumps=frozenset({'jmp'}),
    calls=frozenset({'call'}),
    returns=frozenset({'ret', 'retn', 'retf'}),
    syscalls=frozenset({'syscall', 'int'}),
    halts=frozenset({'hlt'}),
)


def _is_terminator(ri: RawInstruction, arch_m: ArchMnemonics) -> bool:
    return ri.mnemonic in arch_m.all_terminators


def _is_conditional_branch(m: str, arch_m: ArchMnemonics) -> bool:
    return m in arch_m.cond_branches


def _resolve_direct_addr(operands: str) -> int | None:
    o = operands.strip()
    try:
        if o.startswith('0x') or o.startswith('-0x'):
            return int(o, 16)
        if o.lstrip('-').isdigit():
            return int(o)
    except ValueError:
        pass
    return None


def _identify_block_starts(raw_insns: dict[int, RawInstruction],
                            func_starts: set[int],
                            arch_m: ArchMnemonics,
                            jump_tables: dict | None = None) -> set[int]:
    """Identifica todas las direcciones que inician un bloque básico."""
    starts = set(func_starts)

    for addr, ri in sorted(raw_insns.items()):
        if ri.mnemonic in arch_m.calls:
            ret_addr = addr + ri.size
            if ret_addr in raw_insns:
                starts.add(ret_addr)

        elif ri.mnemonic in arch_m.uncond_jumps:
            target = arch_m.resolve_target(ri.mnemonic, ri.operands)
            if target and target in raw_insns:
                starts.add(target)
            # Targets de tabla de salto (switch-case, Fase 1)
            if jump_tables and addr in jump_tables:
                for t in jump_tables[addr]:
                    if t in raw_insns:
                        starts.add(t)
            fall = addr + ri.size
            if fall in raw_insns:
                starts.add(fall)

        elif _is_conditional_branch(ri.mnemonic, arch_m):
            target = arch_m.resolve_target(ri.mnemonic, ri.operands)
            if target and target in raw_insns:
                starts.add(target)
            fall = addr + ri.size
            if fall in raw_insns:
                starts.add(fall)

        elif ri.mnemonic in arch_m.returns or ri.mnemonic in arch_m.syscalls:
            fall = addr + ri.size
            if fall in raw_insns:
                starts.add(fall)

    return starts


def _build_raw_blocks(raw_insns: dict[int, RawInstruction],
                      block_starts: set[int],
                      arch_m: ArchMnemonics) -> dict[int, list[int]]:
    """
    Construye bloques básicos: cada bloque es una lista de direcciones de
    instrucciones en orden. Un bloque termina en un terminador O cuando
    la siguiente instrucción es un block_start conocido.
    """
    sorted_starts = sorted(block_starts)
    starts_set    = set(sorted_starts)
    blocks: dict[int, list[int]] = {}

    for i, start in enumerate(sorted_starts):
        if start not in raw_insns:
            continue
        next_start = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else float('inf')

        insn_list: list[int] = []
        addr = start
        while addr in raw_insns:
            insn_list.append(addr)
            ri = raw_insns[addr]
            if _is_terminator(ri, arch_m):
                break
            next_addr = addr + ri.size
            # Cortar si la siguiente dirección es un block_start
            if next_addr in starts_set and next_addr != start:
                break
            if next_addr >= next_start:
                break
            addr = next_addr

        if insn_list:
            blocks[start] = insn_list

    return blocks


def _assign_blocks_to_functions(raw_blocks: dict[int, list[int]],
                                  func_starts: set[int]) -> dict[int, int]:
    """
    Asigna cada bloque a la función cuya entrada está más próxima por abajo.
    Heurística válida para código compilado sin CFG obfuscation.
    """
    sorted_funcs = sorted(func_starts)
    assignment: dict[int, int] = {}

    for block_addr in raw_blocks:
        # Función más cercana por abajo — O(log n) con bisect
        idx = bisect.bisect_right(sorted_funcs, block_addr) - 1
        if idx >= 0:
            assignment[block_addr] = sorted_funcs[idx]

    return assignment


def _compute_successors(ri: RawInstruction, raw_insns: dict[int, RawInstruction],
                         block_starts: set[int],
                         plt_symbols: dict[int, str],
                         func_symbols: dict[int, str],
                         arch_m: ArchMnemonics,
                         jump_tables: dict | None = None) -> list[int]:
    """Calcula los sucesores de un bloque a partir de su última instrucción."""
    m    = ri.mnemonic
    addr = ri.address

    if m in arch_m.returns:
        return []
    if m in arch_m.syscalls:
        fall = addr + ri.size
        return [fall] if fall in raw_insns else []
    if m in arch_m.halts:
        return []
    if m in arch_m.calls:
        fall = addr + ri.size
        return [fall] if fall in raw_insns else []
    if m in arch_m.uncond_jumps:
        target = arch_m.resolve_target(m, ri.operands)
        if target and target in raw_insns:
            return [target]
        # Tabla de salto resuelta por el disassembler (Fase 1)
        if jump_tables and ri.address in jump_tables:
            return [t for t in jump_tables[ri.address] if t in raw_insns]
        return []  # Salto indirecto no resuelto
    if _is_conditional_branch(m, arch_m):
        target = arch_m.resolve_target(m, ri.operands)
        fall   = addr + ri.size
        succs  = []
        if target and target in raw_insns:
            succs.append(target)
        if fall in raw_insns:
            succs.append(fall)
        return succs
    # Fall-through normal
    fall = addr + ri.size
    return [fall] if fall in raw_insns else []


def _build_edges(raw_insns: dict[int, RawInstruction],
                 basic_blocks: dict,
                 functions: dict,
                 arch_m: ArchMnemonics) -> list[Edge]:
    """Construye la lista de aristas del CFG."""
    edges: list[Edge] = []
    seen: set[tuple] = set()

    for _block_addr, block in basic_blocks.items():
        if not block.instructions:
            continue
        last_insn_addr = block.instructions[-1]
        last_insn = raw_insns.get(int(last_insn_addr, 16))
        if last_insn is None:
            continue

        m = last_insn.mnemonic

        for succ_addr in block.successors:
            key = (last_insn_addr, succ_addr)
            if key in seen:
                continue
            seen.add(key)

            if m in arch_m.returns:
                edge_type = 'return'
            elif m in arch_m.syscalls:
                edge_type = 'syscall'
            elif m in arch_m.calls:
                edge_type = 'call'
            elif m in arch_m.uncond_jumps:
                edge_type = 'unconditional_jump'
            elif _is_conditional_branch(m, arch_m):
                edge_type = 'conditional_jump'
            else:
                edge_type = 'fall_through'

            condition = None
            if edge_type == 'conditional_jump':
                condition = m  # e.g. 'je', 'jne', etc.

            edges.append(Edge(
                source=last_insn_addr,
                target=succ_addr,
                type=edge_type,
                condition=condition,
            ))

    return edges


def _fill_call_relations(cfg: EnrichedCFG, raw_insns: dict[int, RawInstruction],
                         arch_m: ArchMnemonics) -> None:
    """Rellena calls_to / called_from entre funciones."""
    for _block_addr, block in cfg.basic_blocks.items():
        if not block.instructions:
            continue
        last_addr_str = block.instructions[-1]
        # Lookup directo O(1): raw_insns usa int keys, last_addr_str es hex string
        last_insn = raw_insns.get(int(last_addr_str, 16))
        if last_insn is None or last_insn.mnemonic not in arch_m.calls:
            continue

        target_int = arch_m.resolve_target(last_insn.mnemonic, last_insn.operands)
        if target_int is None:
            continue

        target_str = hex_addr(target_int)
        caller_str = block.function

        if target_str not in cfg.functions or caller_str not in cfg.functions:
            continue

        caller_func = cfg.functions[caller_str]
        callee_func = cfg.functions[target_str]

        if target_str not in caller_func.calls_to:
            caller_func.calls_to.append(target_str)
        if caller_str not in callee_func.called_from:
            callee_func.called_from.append(caller_str)
