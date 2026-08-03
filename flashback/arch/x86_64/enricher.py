"""
Enricher x86-64: añade anotaciones semánticas al CFG inicial.

Carga los prototipos de libc desde flashback/data/libc_prototypes.json
y la tabla de syscalls desde flashback/data/syscalls_x86_64.json.
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from pathlib import Path

from flashback.arch.base import Enricher
from flashback.arch.x86_64 import syscall_table as sc_table
from flashback.arch.x86_64.instruction_sem import is_prologue_block, is_epilogue_block
from flashback.core.models import (
    EnrichedCFG, BasicBlock,
    FunctionalClassAnnotation, ExternalCallAnnotation,
    SyscallAnnotation, TraceRecommendationAnnotation,
    TracePointAnnotation, ResolvedIndirectAnnotation, GranularityType,
)

logger = logging.getLogger(__name__)

_PROTO_FILE = Path(__file__).parent.parent.parent / 'data' / 'libc_prototypes.json'

_LIBC_PROTOTYPES: dict[str, dict] | None = None


def _load_prototypes() -> dict[str, dict]:
    global _LIBC_PROTOTYPES
    if _LIBC_PROTOTYPES is None:
        with open(_PROTO_FILE, encoding='utf-8') as f:
            _LIBC_PROTOTYPES = json.load(f)
    return _LIBC_PROTOTYPES


class X86_64Enricher(Enricher):
    """
    Enriquece un CFG inicial (x86-64) añadiendo:
      - external_call en instrucciones call a PLT
      - syscall en instrucciones syscall
      - functional_class en cada bloque
      - trace_recommendation en cada bloque
      - trace_point en instrucciones concretas
    """

    def enrich(self, cfg: EnrichedCFG, granularity: str = 'selective') -> EnrichedCFG:
        logger.info(f'Enriqueciendo CFG (granularidad: {granularity})')
        enriched = deepcopy(cfg)
        enriched.metadata.pipeline_stage = 'enriched'

        self._annotate_external_calls(enriched)
        self._annotate_syscalls(enriched)
        self._resolve_indirect_calls(enriched)
        self._classify_blocks(enriched)
        self._annotate_trace_recommendations(enriched, granularity)
        self._annotate_trace_points(enriched)

        n = (sum(len(b.annotations) for b in enriched.basic_blocks.values())
             + sum(len(i.annotations) for i in enriched.instructions.values()))
        logger.info(f'Enriquecimiento completado: {n} anotaciones')
        return enriched

    # ------------------------------------------------------------------
    # Pasos
    # ------------------------------------------------------------------

    def _annotate_external_calls(self, cfg: EnrichedCFG) -> None:
        protos = _load_prototypes()
        for insn in cfg.instructions.values():
            if insn.mnemonic != 'call':
                continue
            target_addr = _resolve_call_target(insn.operands)
            if target_addr is None:
                continue
            target_func = cfg.functions.get(hex(target_addr))
            if target_func is None or not target_func.is_plt:
                continue

            func_name = _normalize_name(target_func.name)
            proto_info = protos.get(func_name)
            insn.annotations.append(ExternalCallAnnotation(
                added_by='enricher',
                function_name=func_name,
                library='libc.so.6',
                prototype=proto_info.get('proto') if proto_info else None,
                argument_registers=proto_info.get('args', []) if proto_info else [],
            ))

    def _annotate_syscalls(self, cfg: EnrichedCFG) -> None:
        for insn in cfg.instructions.values():
            if insn.mnemonic != 'syscall':
                continue
            num = _recover_syscall_number(insn.address, cfg)
            info = sc_table.lookup(num) if num is not None else None
            insn.annotations.append(SyscallAnnotation(
                added_by='enricher',
                syscall_number=num if num is not None else -1,
                syscall_name=info['name'] if info else 'unknown',
                argument_registers=info.get('args', []) if info else [],
                return_register='rax',
            ))

    def _resolve_indirect_calls(self, cfg: EnrichedCFG) -> None:
        """
        Fase 2: backward slice local para llamadas indirectas (call REG).

        Para cada 'call REG' dentro de un bloque busca hacia atrás, en las
        instrucciones del mismo bloque, la última escritura de REG.  Si esa
        escritura es un 'mov REG, IMM' donde IMM coincide con una función
        conocida en el CFG, añade ResolvedIndirectAnnotation.

        Limitación documentada: no cruza límites de bloque. La resolución
        de dependencias inter-bloque requiere Value Set Analysis (VSA), que
        está fuera del alcance de esta herramienta.
        """
        known_funcs = set(cfg.functions.keys())
        resolved_count = 0

        for block in cfg.basic_blocks.values():
            insns = [cfg.instructions[a] for a in block.instructions
                     if a in cfg.instructions]
            for idx, insn in enumerate(insns):
                if insn.mnemonic != 'call':
                    continue
                # Saltar calls directas ya cubiertas por PLT/CFGBuilder
                if _resolve_call_target(insn.operands) is not None:
                    continue
                reg = _extract_call_reg(insn.operands)
                if reg is None:
                    continue
                resolved = _backslice_register(reg, insns[:idx], known_funcs)
                if resolved is not None:
                    insn.annotations.append(ResolvedIndirectAnnotation(
                        added_by='enricher',
                        resolved_target=resolved,
                        method='backslice_local',
                    ))
                    resolved_count += 1

        if resolved_count:
            logger.info(f'Llamadas indirectas resueltas por backward slice: {resolved_count}')

    def _classify_blocks(self, cfg: EnrichedCFG) -> None:
        for block in cfg.basic_blocks.values():
            block.annotations.append(FunctionalClassAnnotation(
                added_by='enricher',
                category=self._classify_block(block, cfg),
            ))

    def _classify_block(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        insns = [cfg.instructions[a] for a in block.instructions if a in cfg.instructions]
        if not insns:
            return 'function_body'

        mnemonics = [i.mnemonic for i in insns]
        operands  = [i.operands for i in insns]

        func = cfg.functions.get(block.function)
        if func and block.address != func.entry_block and not block.predecessors:
            return 'unreachable'

        for insn in insns:
            if any(a.type == 'external_call' for a in insn.annotations):
                return 'external_call_site'
            if any(a.type == 'resolved_indirect' for a in insn.annotations):
                return 'indirect_call_site'

        if 'syscall' in mnemonics:
            return 'syscall_site'

        # Bloque terminado por tabla de salto (Fase 1)
        if any(a.type == 'jump_table' for a in insns[-1].annotations):
            return 'jump_table_site'

        if mnemonics[-1] in ('ret', 'retn', 'retf'):
            if is_epilogue_block(mnemonics):
                return 'function_epilogue'
            return 'return_block'

        if is_prologue_block(mnemonics, operands):
            return 'function_prologue'

        # Cabecera de bucle: back-edge (un predecesor es también sucesor)
        for pred in block.predecessors:
            if pred in block.successors:
                return 'loop_header'

        return 'function_body'

    def _annotate_trace_recommendations(self, cfg: EnrichedCFG, granularity: str) -> None:
        for block in cfg.basic_blocks.values():
            gran, rationale = self._decide_granularity(block, granularity)
            block.annotations.append(TraceRecommendationAnnotation(
                added_by='enricher',
                granularity=gran,
                rationale=rationale,
            ))

    def _decide_granularity(self, block: BasicBlock, policy: str) -> tuple[GranularityType, str]:
        if policy != 'selective':
            return policy, f'Global policy: {policy}'  # type: ignore

        func_class_anns = [a for a in block.annotations if a.type == 'functional_class']
        category = func_class_anns[0].category if func_class_anns else 'function_body'

        table: dict[str, tuple[GranularityType, str]] = {
            'function_prologue':  ('none',        'Prologue: no trace value'),
            'function_epilogue':  ('none',        'Epilogue: no trace value'),
            'unreachable':        ('none',        'Unreachable block'),
            'external_call_site': ('instruction', 'External call: fine-grained trace'),
            'syscall_site':       ('instruction', 'Syscall: fine-grained trace'),
            'indirect_call_site': ('instruction', 'Indirect call resolved: fine-grained trace'),
            'jump_table_site':    ('instruction', 'Jump table: trace all targets'),
            'loop_header':        ('block',       'Loop header: count iterations'),
            'return_block':       ('block',       'Return block: trace exit'),
            'function_body':      ('block',       'General body: block trace'),
        }
        return table.get(category, ('block', 'Default'))

    def _annotate_trace_points(self, cfg: EnrichedCFG) -> None:
        for block in cfg.basic_blocks.values():
            recs = [a for a in block.annotations if a.type == 'trace_recommendation']
            if not recs:
                continue
            granularity = recs[0].granularity

            if granularity == 'none':
                continue

            insns = [cfg.instructions[a] for a in block.instructions if a in cfg.instructions]
            if not insns:
                continue

            if granularity == 'block':
                insns[0].annotations.append(TracePointAnnotation(
                    added_by='enricher', reason='block_entry',
                ))
            elif granularity == 'instruction':
                for insn in insns:
                    reason = 'block_entry'
                    if any(a.type == 'external_call' for a in insn.annotations):
                        reason = 'external_call_site'
                    elif insn.mnemonic == 'syscall':
                        reason = 'syscall_site'
                    insn.annotations.append(TracePointAnnotation(
                        added_by='enricher', reason=reason,
                    ))


# ---------------------------------------------------------------------------
# Utilidades privadas
# ---------------------------------------------------------------------------

def _resolve_call_target(operands: str) -> int | None:
    o = operands.strip()
    try:
        if o.startswith('0x') or o.startswith('-0x'):
            return int(o, 16)
        if o.lstrip('-').isdigit():
            return int(o)
    except ValueError:
        pass
    return None


def _normalize_name(name: str) -> str:
    for sep in ('@@', '@'):
        if sep in name:
            name = name.split(sep)[0]
    return name.strip()


_X86_64_REGS = frozenset({
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
})


def _extract_call_reg(operands: str) -> str | None:
    """Extrae el registro destino de un 'call REG'; None si no es call-a-registro."""
    op = operands.strip().lower()
    return op if op in _X86_64_REGS else None


def _backslice_register(
    reg: str,
    preceding_insns: list,
    known_funcs: set[str],
) -> str | None:
    """
    Backward slice local: busca hacia atrás la última escritura de 'reg'
    y devuelve la dirección de función si está en known_funcs.

    Solo resuelve el patrón 'mov/movabs REG, IMM' donde IMM es una dirección
    de función conocida en el CFG actual.
    """
    for insn in reversed(preceding_insns):
        if reg not in insn.registers_written:
            continue
        if insn.mnemonic in ('mov', 'movabs'):
            parts = insn.operands.split(',', 1)
            if len(parts) == 2:
                src = parts[1].strip()
                addr = _try_parse_addr(src)
                if addr is not None and addr in known_funcs:
                    return addr
        break  # el registro fue redefinido pero no con un inmediato resoluble
    return None


def _try_parse_addr(s: str) -> str | None:
    """Parsea una string como entero y devuelve 'hex(val)' o None."""
    s = s.strip()
    try:
        if s.startswith(('0x', '0X')):
            return hex(int(s, 16))
        if s.lstrip('-').isdigit():
            val = int(s)
            if val > 0:
                return hex(val)
    except ValueError:
        pass
    return None


def _recover_syscall_number(syscall_addr: str, cfg: EnrichedCFG) -> int | None:
    insn = cfg.instructions.get(syscall_addr)
    if insn is None:
        return None
    block = cfg.basic_blocks.get(insn.block)
    if block is None:
        return None
    try:
        idx = block.instructions.index(syscall_addr)
    except ValueError:
        return None

    for prev_addr in reversed(block.instructions[:idx]):
        prev = cfg.instructions.get(prev_addr)
        if prev is None:
            continue
        if prev.mnemonic == 'mov' and prev.operands.startswith('rax,'):
            val_str = prev.operands.split(',', 1)[1].strip()
            try:
                return int(val_str, 0)
            except ValueError:
                return None
        if 'rax' in prev.registers_written:
            break
    return None
