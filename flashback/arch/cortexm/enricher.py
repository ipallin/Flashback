"""
Enricher Cortex-M: anotaciones para firmware ARM bare-metal.

Diferencias respecto a Arm32Enricher:
  - Sin PLT ni dynamic linker → _annotate_external_calls() es no-op.
  - Sin syscalls de SO → _annotate_syscalls() es no-op.
  - Los bloques de IRQ handler se clasifican como 'irq_handler'.
  - Las instrucciones de barrera (dmb/dsb/isb) se clasifican como 'memory_barrier'.
"""

from __future__ import annotations

import logging

from flashback.arch.arm32.enricher import Arm32Enricher
from flashback.arch.arm32.instruction_sem import is_prologue_block, is_epilogue_block
from flashback.core.models import (
    EnrichedCFG, BasicBlock,
    GranularityType,
)

logger = logging.getLogger(__name__)

_IRQ_HANDLER_NAMES = frozenset({
    'NMI_Handler', 'HardFault_Handler', 'MemManage_Handler',
    'BusFault_Handler', 'UsageFault_Handler', 'SVC_Handler',
    'DebugMon_Handler', 'PendSV_Handler', 'SysTick_Handler',
})

_BARRIER_MNEMONICS = frozenset({'dmb', 'dsb', 'isb'})
_SLEEP_MNEMONICS   = frozenset({'wfi', 'wfe', 'sev'})


class CortexMEnricher(Arm32Enricher):
    """Enricher para CFG Cortex-M (bare-metal, sin OS)."""

    def enrich(self, cfg: EnrichedCFG, granularity: str = 'selective') -> EnrichedCFG:
        logger.info(f'Enriqueciendo CFG Cortex-M (granularidad: {granularity})')
        # deepcopy es demasiado lento para binarios grandes (>100K instrucciones)
        enriched = cfg
        enriched.metadata.pipeline_stage = 'enriched'

        # Sin PLT ni syscalls — omitir esas anotaciones
        self._classify_blocks(enriched)
        self._annotate_trace_recommendations(enriched, granularity)
        self._annotate_trace_points(enriched)

        n = (sum(len(b.annotations) for b in enriched.basic_blocks.values())
             + sum(len(i.annotations) for i in enriched.instructions.values()))
        logger.info(f'Enriquecimiento Cortex-M completado: {n} anotaciones')
        return enriched

    def _annotate_external_calls(self, cfg: EnrichedCFG) -> None:
        pass   # sin dynamic linker en bare-metal

    def _annotate_syscalls(self, cfg: EnrichedCFG) -> None:
        pass   # sin SO en bare-metal

    def _classify_block(self, block: BasicBlock, cfg: EnrichedCFG) -> str:
        insns = [cfg.instructions[a] for a in block.instructions if a in cfg.instructions]
        if not insns:
            return 'function_body'

        mnemonics = [i.mnemonic for i in insns]
        operands  = [i.operands for i in insns]

        # Bloque de entrada de IRQ handler
        func = cfg.functions.get(block.function)
        if func and func.name in _IRQ_HANDLER_NAMES:
            if block.address == func.entry_block:
                return 'irq_handler'

        # Bloque inalcanzable
        if func and block.address != func.entry_block and not block.predecessors:
            return 'unreachable'

        # Barrera de memoria
        if all(m in _BARRIER_MNEMONICS for m in mnemonics):
            return 'memory_barrier'

        # Sleep / wait
        if any(m in _SLEEP_MNEMONICS for m in mnemonics):
            return 'sleep_site'

        if is_epilogue_block(mnemonics, operands):
            return 'function_epilogue'

        if is_prologue_block(mnemonics, operands):
            return 'function_prologue'

        for pred in block.predecessors:
            if pred in block.successors:
                return 'loop_header'

        return 'function_body'

    def _decide_granularity(self, block: BasicBlock, policy: str) -> tuple[GranularityType, str]:
        if policy != 'selective':
            return policy, f'Global policy: {policy}'  # type: ignore
        func_class_anns = [a for a in block.annotations if a.type == 'functional_class']
        category = func_class_anns[0].category if func_class_anns else 'function_body'
        table: dict[str, tuple[GranularityType, str]] = {
            'function_prologue': ('none',        'Prologue: no trace value'),
            'function_epilogue': ('none',        'Epilogue: no trace value'),
            'unreachable':       ('none',        'Unreachable block'),
            'memory_barrier':    ('none',        'Memory barrier: implementation detail'),
            'irq_handler':       ('instruction', 'IRQ entry: fine-grained trace'),
            'sleep_site':        ('block',       'Sleep/wait: trace when reached'),
            'loop_header':       ('block',       'Loop header: count iterations'),
            'function_body':     ('block',       'General body: block trace'),
        }
        return table.get(category, ('block', 'Default'))
