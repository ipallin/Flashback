"""
Enricher ARM32: anotaciones semánticas para CFG ARM (32-bit).

- Llamadas externas vía `bl`/`blx` a PLT.
- Syscalls vía `svc` o `swi` (número en r7).
- Clasificación funcional con heurísticas push-lr / pop-pc.
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from pathlib import Path

from flashback.arch.base import Enricher
from flashback.arch.arm32 import syscall_table as sc_table
from flashback.arch.arm32.instruction_sem import is_prologue_block, is_epilogue_block
from flashback.core.models import (
    EnrichedCFG, BasicBlock,
    FunctionalClassAnnotation, ExternalCallAnnotation,
    SyscallAnnotation, TraceRecommendationAnnotation,
    TracePointAnnotation, GranularityType,
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


class Arm32Enricher(Enricher):

    def enrich(self, cfg: EnrichedCFG, granularity: str = 'selective') -> EnrichedCFG:
        logger.info(f'Enriqueciendo CFG ARM32 (granularidad: {granularity})')
        enriched = deepcopy(cfg)
        enriched.metadata.pipeline_stage = 'enriched'

        self._annotate_external_calls(enriched)
        self._annotate_syscalls(enriched)
        self._classify_blocks(enriched)
        self._annotate_trace_recommendations(enriched, granularity)
        self._annotate_trace_points(enriched)

        n = (sum(len(b.annotations) for b in enriched.basic_blocks.values())
             + sum(len(i.annotations) for i in enriched.instructions.values()))
        logger.info(f'Enriquecimiento ARM32 completado: {n} anotaciones')
        return enriched

    def _annotate_external_calls(self, cfg: EnrichedCFG) -> None:
        protos = _load_prototypes()
        for insn in cfg.instructions.values():
            if insn.mnemonic not in ('bl', 'blx'):
                continue
            target_addr = _resolve_call_target(insn.mnemonic, insn.operands)
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
            if insn.mnemonic not in ('svc', 'swi'):
                continue
            num = _recover_syscall_number(insn.address, cfg)
            info = sc_table.lookup(num) if num is not None else None
            insn.annotations.append(SyscallAnnotation(
                added_by='enricher',
                syscall_number=num if num is not None else -1,
                syscall_name=info['name'] if info else 'unknown',
                argument_registers=info.get('args', []) if info else [],
                return_register='r0',
            ))

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

        if any(i.mnemonic in ('svc', 'swi') for i in insns):
            return 'syscall_site'

        if is_epilogue_block(mnemonics, operands):
            return 'function_epilogue'

        if is_prologue_block(mnemonics, operands):
            return 'function_prologue'

        for pred in block.predecessors:
            if pred in block.successors:
                return 'loop_header'

        return 'function_body'

    def _annotate_trace_recommendations(self, cfg: EnrichedCFG, granularity: str) -> None:
        for block in cfg.basic_blocks.values():
            gran, rationale = self._decide_granularity(block, granularity)
            block.annotations.append(TraceRecommendationAnnotation(
                added_by='enricher', granularity=gran, rationale=rationale,
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
            'loop_header':        ('block',       'Loop header: count iterations'),
            'return_block':       ('block',       'Return block: trace exit'),
            'function_body':      ('block',       'General body: block trace'),
        }
        return table.get(category, ('block', 'Default'))

    def _annotate_trace_points(self, cfg: EnrichedCFG) -> None:
        for block in cfg.basic_blocks.values():
            recs = [a for a in block.annotations if a.type == 'trace_recommendation']
            if not recs or recs[0].granularity == 'none':
                continue
            insns = [cfg.instructions[a] for a in block.instructions if a in cfg.instructions]
            if not insns:
                continue
            if recs[0].granularity == 'block':
                insns[0].annotations.append(TracePointAnnotation(
                    added_by='enricher', reason='block_entry',
                ))
            elif recs[0].granularity == 'instruction':
                for insn in insns:
                    reason = 'block_entry'
                    if any(a.type == 'external_call' for a in insn.annotations):
                        reason = 'external_call_site'
                    elif insn.mnemonic in ('svc', 'swi'):
                        reason = 'syscall_site'
                    insn.annotations.append(TracePointAnnotation(
                        added_by='enricher', reason=reason,
                    ))


# ---------------------------------------------------------------------------
# Utilidades privadas
# ---------------------------------------------------------------------------

def _resolve_call_target(mnemonic: str, operands: str) -> int | None:
    o = operands.strip()
    if mnemonic == 'blx' and not o.startswith('#') and not o.startswith('0x'):
        return None   # llamada indirecta a registro
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


def _normalize_name(name: str) -> str:
    for sep in ('@@', '@'):
        if sep in name:
            name = name.split(sep)[0]
    return name.strip()


def _recover_syscall_number(svc_addr: str, cfg: EnrichedCFG) -> int | None:
    """Busca hacia atrás 'mov r7, #N' o 'movw r7, #N' antes de svc."""
    insn = cfg.instructions.get(svc_addr)
    if insn is None:
        return None
    block = cfg.basic_blocks.get(insn.block)
    if block is None:
        return None
    try:
        idx = block.instructions.index(svc_addr)
    except ValueError:
        return None

    for prev_addr in reversed(block.instructions[:idx]):
        prev = cfg.instructions.get(prev_addr)
        if prev is None:
            continue
        if prev.mnemonic in ('mov', 'movw') and prev.operands.startswith('r7,'):
            val_str = prev.operands.split(',', 1)[1].strip()
            if val_str.startswith('#'):
                val_str = val_str[1:]
            try:
                return int(val_str, 0)
            except ValueError:
                return None
        if 'r7' in (prev.registers_written or []):
            break
    return None
