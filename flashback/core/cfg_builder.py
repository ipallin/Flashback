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
    Metadata, BinaryInfo, hex_addr, JumpTableAnnotation, LiteralLoadAnnotation,
    UNKNOWN_TARGET,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Flow:
    """
    Efecto de una instrucción terminadora sobre el flujo de control.

    kind:
      'branch'        salto directo (si el target no se resuelve se trata como indirecto)
      'indirect_jump' salto a registro/memoria (bx rN, ldr pc, tbb...)
      'call'          llamada (directa o indirecta según se resuelva el target)
      'return'        retorno de función
      'syscall'       llamada al sistema (continúa en fall-through)
      'halt'          detiene la ejecución
    conditional: la instrucción puede no ejecutarse y continuar en fall-through.
    """
    kind: str
    conditional: bool = False


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
    # Clasificador propio (mnemonic, operands) -> Flow | None. Necesario cuando
    # el mnemónico no basta (ARM: 'bx lr' vs 'bx r3', 'pop {pc}', sufijos .w/cond).
    classifier: Optional[Callable[[str, str], Optional[Flow]]] = None

    @property
    def all_terminators(self) -> frozenset:
        return (self.cond_branches | self.uncond_jumps | self.calls
                | self.returns | self.syscalls | self.halts)

    def resolve_target(self, mnemonic: str, operands: str) -> Optional[int]:
        if self.target_resolver is not None:
            return self.target_resolver(mnemonic, operands)
        return _resolve_direct_addr(operands)

    def flow(self, ri: 'RawInstruction') -> Optional[Flow]:
        """Clasifica una instrucción; None si no termina el bloque."""
        if self.classifier is not None:
            return self.classifier(ri.mnemonic, ri.operands)
        m = ri.mnemonic
        if m in self.returns:
            return Flow('return')
        if m in self.syscalls:
            return Flow('syscall')
        if m in self.halts:
            return Flow('halt')
        if m in self.calls:
            return Flow('call')
        if m in self.uncond_jumps:
            return Flow('branch')
        if m in self.cond_branches:
            return Flow('branch', conditional=True)
        return None


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
    # Cargas relativas a pc: addr_instrucción → (addr_literal, bytes leídos)
    literals: dict = field(default_factory=dict)
    # Funciones que no retornan detectadas por el disassembler (además de las
    # reconocidas por nombre, ver NORETURN_NAMES)
    noreturn: set = field(default_factory=set)


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
                is_noreturn=is_noreturn_name(plt_name),
            )

        # 2. Identificar todos los bloques básicos
        func_starts = set(meta.func_symbols.keys())
        arch_m = self._arch_m
        noreturn = set(meta.noreturn) | {
            addr for addr, name in {**meta.func_symbols, **meta.plt_symbols}.items()
            if is_noreturn_name(name)
        }
        block_starts = _identify_block_starts(raw_insns, func_starts, arch_m,
                                              jump_tables=meta.jump_tables,
                                              plt_addrs=set(meta.plt_symbols),
                                              noreturn=noreturn)
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
                is_noreturn=func_addr in noreturn,
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
                if addr in meta.literals:
                    lit_addr, lit_data = meta.literals[addr]
                    cfg.instructions[hex_addr(addr)].annotations.append(LiteralLoadAnnotation(
                        added_by='cfg_builder', address=hex_addr(lit_addr), data=lit_data.hex(),
                    ))

            last_ri = raw_insns[insn_addrs[-1]]
            successors = _compute_successors(
                last_ri, raw_insns, arch_m, jump_tables=meta.jump_tables,
                noreturn=noreturn,
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
        cfg.edges = _build_edges(raw_insns, cfg.basic_blocks, cfg.functions, arch_m,
                                 jump_tables=meta.jump_tables, noreturn=noreturn)

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

# Funciones de biblioteca que nunca retornan (como las que Ghidra marca noreturn)
NORETURN_NAMES = frozenset({
    'abort', 'exit', '_exit', '_Exit', 'quick_exit', 'pthread_exit', 'thrd_exit',
    '__assert_func', '__assert_fail', '__assert_rtn', '__assert', '__stack_chk_fail',
    '__chk_fail', '__fortify_fail', '__libc_start_main', 'longjmp', 'siglongjmp',
    '_longjmp', '__longjmp_chk', 'err', 'errx', 'verr', 'verrx', 'panic',
    '__cxa_throw', '__cxa_rethrow', '__cxa_bad_cast', '__cxa_bad_typeid',
    '__cxa_call_unexpected', '_Unwind_Resume', '__ubsan_handle_builtin_unreachable',
    '_ZSt9terminatev', '_ZSt10unexpectedv',
})


def is_noreturn_name(name: str) -> bool:
    """Nombre (sin versión @GLIBC) de una función que nunca retorna."""
    base = name.split('@')[0]
    if base.startswith('__wrap_') or base.startswith('__real_'):
        base = base[7:]
    return base in NORETURN_NAMES or base.startswith('_ZSt') and '__throw_' in base


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
    return arch_m.flow(ri) is not None


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


def _direct_target(ri: RawInstruction, flow: Flow, arch_m: ArchMnemonics) -> int | None:
    """Target estático de un salto/llamada directo; None si es indirecto."""
    if flow.kind not in ('branch', 'call'):
        return None
    return arch_m.resolve_target(ri.mnemonic, ri.operands)


def _jump_targets(ri: RawInstruction, flow: Flow,
                  raw_insns: dict[int, RawInstruction],
                  arch_m: ArchMnemonics,
                  jump_tables: dict | None) -> list[int]:
    """Destinos intra-código de un salto: directo o tabla de salto resuelta."""
    target = _direct_target(ri, flow, arch_m)
    if target and target in raw_insns:
        return [target]
    # Tabla de salto resuelta por el disassembler (Fase 1)
    if jump_tables and ri.address in jump_tables:
        return [t for t in jump_tables[ri.address] if t in raw_insns]
    return []  # Salto indirecto no resuelto


def _identify_block_starts(raw_insns: dict[int, RawInstruction],
                            func_starts: set[int],
                            arch_m: ArchMnemonics,
                            jump_tables: dict | None = None,
                            plt_addrs: set[int] | None = None,
                            noreturn: set[int] | None = None) -> set[int]:
    """Identifica todas las direcciones que inician un bloque básico."""
    starts = set(func_starts)
    plt_addrs = plt_addrs or set()
    noreturn = noreturn or set()

    for addr, ri in raw_insns.items():
        flow = arch_m.flow(ri)
        if flow is None:
            continue
        fall = addr + ri.size

        if flow.kind == 'call':
            # El destino de una llamada directa es la entrada de una función;
            # si no tiene símbolo, al menos debe empezar un bloque.
            target = _direct_target(ri, flow, arch_m)
            if target and target in raw_insns and target not in plt_addrs:
                starts.add(target)
            if fall in raw_insns and (flow.conditional or target not in noreturn):
                starts.add(fall)

        elif flow.kind in ('branch', 'indirect_jump'):
            for t in _jump_targets(ri, flow, raw_insns, arch_m, jump_tables):
                starts.add(t)
            if fall in raw_insns:
                starts.add(fall)

        elif flow.kind in ('return', 'syscall') or flow.conditional:
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
                         arch_m: ArchMnemonics,
                         jump_tables: dict | None = None,
                         noreturn: set[int] | None = None) -> list[int]:
    """
    Calcula los sucesores intra-procedurales de un bloque a partir de su última
    instrucción. Las llamadas continúan en la dirección de retorno; el destino
    de la llamada solo aparece en la lista de aristas (tipo 'call').
    """
    fall = ri.address + ri.size
    has_fall = fall in raw_insns
    flow = arch_m.flow(ri)

    if flow is not None and flow.kind == 'call' and not flow.conditional \
            and noreturn and _direct_target(ri, flow, arch_m) in noreturn:
        return []           # llamada a una función que no retorna
    if flow is None or flow.kind in ('call', 'syscall'):
        return [fall] if has_fall else []
    if flow.kind in ('return', 'halt'):
        return [fall] if flow.conditional and has_fall else []

    succs = _jump_targets(ri, flow, raw_insns, arch_m, jump_tables)
    if flow.conditional and has_fall:
        succs.append(fall)
    return succs


def _build_edges(raw_insns: dict[int, RawInstruction],
                 basic_blocks: dict,
                 functions: dict,
                 arch_m: ArchMnemonics,
                 jump_tables: dict | None = None,
                 noreturn: set[int] | None = None) -> list[Edge]:
    """
    Construye la lista de aristas del CFG.

    Todas las aristas llevan source_block y condition explícitos. Cuando el
    destino no se conoce estáticamente (salto o llamada indirecta sin resolver)
    la arista apunta a UNKNOWN_TARGET en lugar de omitirse.

    condition:
      'always'      la arista se toma siempre que se ejecuta la instrucción
      '<mnem>'      salto condicional tomado (p.ej. 'beq', 'jne', 'cbz')
      'not <mnem>'  rama no tomada de un condicional (fall-through)
      'case N,M'    entradas N, M de una tabla de salto resuelta

    Un salto directo a la entrada de otra función es un 'tail_call'. Tras una
    llamada a una función que no retorna no hay arista fall_through.
    """
    edges: list[Edge] = []
    seen: set[tuple] = set()
    noreturn = noreturn or set()

    def add(source: str, block_addr: str, target: str, edge_type: str, condition: str):
        key = (source, target, edge_type)
        if key in seen:
            return
        seen.add(key)
        edges.append(Edge(source=source, target=target, type=edge_type,
                          condition=condition, source_block=block_addr))

    def code_target(addr: int) -> str | None:
        h = hex_addr(addr)
        return h if h in basic_blocks or h in functions else None

    for block_addr, block in basic_blocks.items():
        if not block.instructions:
            continue
        src = block.instructions[-1]
        ri = raw_insns.get(int(src, 16))
        if ri is None:
            continue

        m = ri.mnemonic
        flow = arch_m.flow(ri)
        fall = hex_addr(ri.address + ri.size)
        has_fall = fall in basic_blocks
        taken = m if flow is not None and flow.conditional else 'always'

        if flow is None:
            for succ in block.successors:
                add(src, block_addr, succ, 'fall_through', 'always')
            continue

        if flow.kind in ('return', 'halt'):
            # El destino de un retorno es el llamador: no se modela como arista.
            if flow.conditional and has_fall:
                add(src, block_addr, fall, 'fall_through', f'not {m}')
            continue

        if flow.kind == 'syscall':
            if has_fall:
                add(src, block_addr, fall, 'syscall', 'always')
            continue

        if flow.kind == 'call':
            target = _direct_target(ri, flow, arch_m)
            callee = code_target(target) if target else None
            if callee is not None:
                add(src, block_addr, callee, 'call', taken)
            else:
                add(src, block_addr, UNKNOWN_TARGET, 'call_indirect', taken)
            if has_fall and (flow.conditional or target not in noreturn):
                add(src, block_addr, fall, 'fall_through', 'always')
            continue

        # branch / indirect_jump
        target = _direct_target(ri, flow, arch_m)
        table = jump_tables.get(ri.address) if jump_tables else None
        if target and target in raw_insns:
            dst = hex_addr(target)
            if dst in functions and dst != block.function:
                edge_type = 'tail_call'
            else:
                edge_type = 'conditional_jump' if flow.conditional else 'unconditional_jump'
            add(src, block_addr, dst, edge_type, taken)
        elif target and code_target(target):
            # Salto directo a una función sin código en el CFG (p.ej. PLT)
            add(src, block_addr, code_target(target), 'tail_call', taken)
        elif table:
            cases: dict[int, list[int]] = {}
            for idx, t in enumerate(table):
                if t in raw_insns:
                    cases.setdefault(t, []).append(idx)
            for t, idxs in cases.items():
                add(src, block_addr, hex_addr(t), 'indirect_jump',
                    'case ' + ','.join(str(i) for i in idxs))
        else:
            add(src, block_addr, UNKNOWN_TARGET, 'indirect_jump', taken)
        if flow.conditional and has_fall:
            add(src, block_addr, fall, 'fall_through', f'not {m}')

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
        if last_insn is None:
            continue
        flow = arch_m.flow(last_insn)
        if flow is None or flow.kind != 'call':
            continue

        target_int = _direct_target(last_insn, flow, arch_m)
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
