"""
Pruebas de trazabilidad bidireccional.

Verifican que:
  - Cada instrucción con trace_point genera exactamente una llamada __trace().
  - Los comentarios de trazabilidad estática están presentes en el C generado.
  - Las granularidades afectan al número de puntos de traza generados.
  - El CFG enriquecido gobierna las decisiones de granularidad (no el Translator).
"""

from flashback.core.models import (
    EnrichedCFG, BinaryInfo, Metadata, Function, BasicBlock, Instruction,
    TracePointAnnotation, TraceRecommendationAnnotation, FunctionalClassAnnotation,
)
from flashback.core.translator import Translator


def _make_cfg_with_blocks(n_blocks: int = 3) -> EnrichedCFG:
    """Construye un CFG enriquecido de prueba con n_blocks bloques en main."""
    cfg = EnrichedCFG(
        metadata=Metadata(generator='test', generator_version='0', pipeline_stage='enriched'),
        binary_info=BinaryInfo(filename='t.elf', sha256='a' * 64, entry_point='0x1000'),
    )
    block_addrs = [f'0x{0x1000 + i * 0x10:x}' for i in range(n_blocks)]
    cfg.functions['0x1000'] = Function(
        address='0x1000', name='main', is_plt=False, is_external=False,
        entry_block='0x1000', blocks=block_addrs,
    )
    for baddr in block_addrs:
        iaddr = f'0x{int(baddr, 16) + 1:x}'
        cfg.basic_blocks[baddr] = BasicBlock(
            address=baddr, size=2, function='0x1000',
            instructions=[baddr, iaddr],
        )
        cfg.instructions[baddr] = Instruction(
            address=baddr, mnemonic='push', operands='rbp',
            bytes='55', size=1, block=baddr,
        )
        cfg.instructions[iaddr] = Instruction(
            address=iaddr, mnemonic='nop', operands='',
            bytes='90', size=1, block=baddr,
        )
    return cfg


# ------------------------------------------------------------------
# Comentarios de trazabilidad estática
# ------------------------------------------------------------------

class TestTrazabilidadEstatica:

    def test_cada_instruccion_tiene_comentario(self):
        cfg = _make_cfg_with_blocks(2)
        out = Translator().translate(cfg)
        for insn in cfg.instructions.values():
            expected = f'/* {insn.address}: {insn.mnemonic} {insn.operands} */'
            assert expected in out, f'Falta comentario para {insn.address}'

    def test_comentario_incluye_direccion(self):
        cfg = _make_cfg_with_blocks(1)
        out = Translator().translate(cfg)
        assert '0x1000' in out
        assert '0x1001' in out


# ------------------------------------------------------------------
# Trazabilidad dinámica: __trace()
# ------------------------------------------------------------------

class TestTrazabilidadDinamica:

    def test_trace_point_genera_llamada(self):
        cfg = _make_cfg_with_blocks(1)
        cfg.instructions['0x1000'].annotations.append(
            TracePointAnnotation(added_by='test', reason='block_entry')
        )
        assert '__trace(0x1000ULL)' in Translator().translate(cfg)

    def test_sin_trace_points_no_hay_llamadas(self):
        cfg = _make_cfg_with_blocks(2)
        out = Translator().translate(cfg)
        # Buscar llamadas reales (con dirección hex), no la definición del runtime
        assert '__trace(0x' not in out

    def test_multiples_trace_points(self):
        cfg = _make_cfg_with_blocks(3)
        for baddr in cfg.basic_blocks:
            insn = cfg.instructions.get(baddr)
            if insn:
                insn.annotations.append(TracePointAnnotation(added_by='test', reason='block_entry'))
        out = Translator().translate(cfg)
        assert out.count('__trace(0x') == 3


# ------------------------------------------------------------------
# Granularidad controlada por el CFG enriquecido
# ------------------------------------------------------------------

class TestGranularidad:

    def _enrich_with_policy(self, policy: str) -> EnrichedCFG:
        from flashback.arch.x86_64.enricher import X86_64Enricher
        cfg = _make_cfg_with_blocks(4)
        cfg.metadata.pipeline_stage = 'initial'
        # Añadir functional_class manualmente para testear la política
        for block in cfg.basic_blocks.values():
            block.annotations.append(
                FunctionalClassAnnotation(added_by='test', category='function_body')
            )
        return X86_64Enricher().enrich(cfg, granularity=policy)

    def test_granularidad_none_no_genera_trace(self):
        cfg = self._enrich_with_policy('none')
        out = Translator().translate(cfg)
        assert '__trace(0x' not in out

    def test_granularidad_block_genera_un_trace_por_bloque(self):
        cfg = self._enrich_with_policy('block')
        out = Translator().translate(cfg)
        n_blocks = len(cfg.basic_blocks)
        assert out.count('__trace(0x') == n_blocks

    def test_granularidad_instruction_genera_trace_por_instruccion(self):
        cfg = self._enrich_with_policy('instruction')
        out = Translator().translate(cfg)
        n_insns = len(cfg.instructions)
        assert out.count('__trace(0x') == n_insns

    def test_selective_no_traza_prologo(self):
        from flashback.arch.x86_64.enricher import X86_64Enricher
        cfg = _make_cfg_with_blocks(1)
        cfg.metadata.pipeline_stage = 'initial'
        cfg.basic_blocks['0x1000'].annotations.append(
            FunctionalClassAnnotation(added_by='test', category='function_prologue')
        )
        enriched = X86_64Enricher().enrich(cfg, granularity='selective')
        out = Translator().translate(enriched)
        assert '__trace(0x' not in out


# ------------------------------------------------------------------
# Integridad referencial: el enricher decide, el translator obedece
# ------------------------------------------------------------------

class TestSeparacionResponsabilidades:

    def test_translator_no_crea_trace_points(self):
        """El Translator no debe añadir trace_points; solo lee los que hay."""
        cfg = _make_cfg_with_blocks(2)
        out = Translator().translate(cfg)
        assert '__trace(0x' not in out

    def test_trace_recommendation_sin_trace_point_no_genera_trace(self):
        """trace_recommendation en el bloque no es suficiente; hace falta trace_point en instrucción."""
        cfg = _make_cfg_with_blocks(1)
        cfg.basic_blocks['0x1000'].annotations.append(
            TraceRecommendationAnnotation(added_by='test', granularity='block')
        )
        out = Translator().translate(cfg)
        assert '__trace(0x' not in out
