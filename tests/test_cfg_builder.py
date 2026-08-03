"""
Pruebas del CFGBuilder y sus funciones auxiliares (PCB01-PCB06).

Verifican que el CFGBuilder construye correctamente bloques básicos,
aristas, funciones y relaciones entre ellas a partir de instrucciones crudas.
"""

from flashback.core.cfg_builder import (
    CFGBuilder, BinaryMeta, RawInstruction, ArchMnemonics,
    _identify_block_starts, _build_raw_blocks, _assign_blocks_to_functions,
    _resolve_direct_addr,
)
from flashback.core.models import EnrichedCFG


# ---------------------------------------------------------------------------
# Fixtures de mnemonics y datos mínimos
# ---------------------------------------------------------------------------

_TEST_MNEMONICS = ArchMnemonics(
    cond_branches=frozenset({'je', 'jne'}),
    uncond_jumps=frozenset({'jmp'}),
    calls=frozenset({'call'}),
    returns=frozenset({'ret'}),
    syscalls=frozenset({'syscall'}),
    halts=frozenset({'hlt'}),
)


def _insn(addr: int, mnemonic: str, operands: str = '', size: int = 1) -> RawInstruction:
    return RawInstruction(
        address=addr, mnemonic=mnemonic, operands=operands,
        bytes_hex='90', size=size,
    )


def _meta(func_addrs: dict[int, str] | None = None) -> BinaryMeta:
    return BinaryMeta(
        path='/fake/binary',
        sha256='a' * 64,
        entry_point=0x1000,
        architecture='amd64',
        func_symbols=func_addrs or {0x1000: 'main'},
        plt_symbols={},
    )


# ---------------------------------------------------------------------------
# PCB01 – _resolve_direct_addr
# ---------------------------------------------------------------------------

class TestResolveDirect:

    def test_hex_address(self):
        assert _resolve_direct_addr('0x1234') == 0x1234

    def test_decimal_address(self):
        assert _resolve_direct_addr('100') == 100

    def test_negative(self):
        assert _resolve_direct_addr('-4') == -4

    def test_register_returns_none(self):
        assert _resolve_direct_addr('rax') is None

    def test_memory_returns_none(self):
        assert _resolve_direct_addr('[rax + 8]') is None


# ---------------------------------------------------------------------------
# PCB02 – _identify_block_starts
# ---------------------------------------------------------------------------

class TestIdentifyBlockStarts:

    def test_func_start_is_always_a_block_start(self):
        raw = {0x1000: _insn(0x1000, 'nop')}
        starts = _identify_block_starts(raw, {0x1000}, _TEST_MNEMONICS)
        assert 0x1000 in starts

    def test_jump_target_creates_block_start(self):
        raw = {
            0x1000: _insn(0x1000, 'jmp', '0x1010', size=2),
            0x1010: _insn(0x1010, 'ret'),
        }
        starts = _identify_block_starts(raw, {0x1000}, _TEST_MNEMONICS)
        assert 0x1010 in starts

    def test_conditional_branch_creates_two_starts(self):
        raw = {
            0x1000: _insn(0x1000, 'je', '0x1010', size=2),
            0x1002: _insn(0x1002, 'nop'),
            0x1010: _insn(0x1010, 'ret'),
        }
        starts = _identify_block_starts(raw, {0x1000}, _TEST_MNEMONICS)
        # fall-through y destino del salto
        assert 0x1002 in starts
        assert 0x1010 in starts

    def test_call_creates_return_address_block(self):
        raw = {
            0x1000: _insn(0x1000, 'call', '0x2000', size=5),
            0x1005: _insn(0x1005, 'ret'),
        }
        starts = _identify_block_starts(raw, {0x1000}, _TEST_MNEMONICS)
        assert 0x1005 in starts


# ---------------------------------------------------------------------------
# PCB03 – _build_raw_blocks
# ---------------------------------------------------------------------------

class TestBuildRawBlocks:

    def test_single_block(self):
        raw = {
            0x1000: _insn(0x1000, 'nop'),
            0x1001: _insn(0x1001, 'ret'),
        }
        blocks = _build_raw_blocks(raw, {0x1000}, _TEST_MNEMONICS)
        assert 0x1000 in blocks
        assert blocks[0x1000] == [0x1000, 0x1001]

    def test_terminador_corta_bloque(self):
        raw = {
            0x1000: _insn(0x1000, 'nop'),
            0x1001: _insn(0x1001, 'jmp', '0x2000'),
            0x1002: _insn(0x1002, 'nop'),
        }
        starts = {0x1000, 0x1002}
        blocks = _build_raw_blocks(raw, starts, _TEST_MNEMONICS)
        assert blocks[0x1000] == [0x1000, 0x1001]
        assert blocks[0x1002] == [0x1002]

    def test_bloque_vacio_si_no_hay_instrucciones(self):
        raw = {0x2000: _insn(0x2000, 'nop')}
        # start en 0x1000 no existe en raw → no debe aparecer en resultado
        blocks = _build_raw_blocks(raw, {0x1000, 0x2000}, _TEST_MNEMONICS)
        assert 0x1000 not in blocks
        assert 0x2000 in blocks


# ---------------------------------------------------------------------------
# PCB04 – _assign_blocks_to_functions
# ---------------------------------------------------------------------------

class TestAssignBlocksToFunctions:

    def test_bloque_asignado_a_funcion_mas_cercana(self):
        raw_blocks = {0x1000: [0x1000], 0x1010: [0x1010], 0x2000: [0x2000]}
        func_starts = {0x1000, 0x2000}
        assignment = _assign_blocks_to_functions(raw_blocks, func_starts)
        assert assignment[0x1000] == 0x1000
        assert assignment[0x1010] == 0x1000  # más cercano por abajo es 0x1000
        assert assignment[0x2000] == 0x2000

    def test_bloque_antes_de_cualquier_funcion_no_asignado(self):
        raw_blocks = {0x0500: [0x0500]}
        func_starts = {0x1000}
        assignment = _assign_blocks_to_functions(raw_blocks, func_starts)
        assert 0x0500 not in assignment


# ---------------------------------------------------------------------------
# PCB05 – CFGBuilder.build (integración interna sin ELF real)
# ---------------------------------------------------------------------------

class TestCFGBuilder:

    def _build_simple(self) -> EnrichedCFG:
        raw = {
            0x1000: _insn(0x1000, 'nop', size=1),
            0x1001: _insn(0x1001, 'call', '0x2000', size=5),
            0x1006: _insn(0x1006, 'ret', size=1),
            0x2000: _insn(0x2000, 'nop', size=1),
            0x2001: _insn(0x2001, 'ret', size=1),
        }
        meta = BinaryMeta(
            path='/fake/test', sha256='b' * 64, entry_point=0x1000,
            architecture='amd64',
            func_symbols={0x1000: 'main', 0x2000: 'helper'},
            plt_symbols={},
        )
        return CFGBuilder(arch_mnemonics=_TEST_MNEMONICS).build(raw, meta)

    def test_funciones_creadas(self):
        cfg = self._build_simple()
        names = {f.name for f in cfg.functions.values()}
        assert 'main' in names
        assert 'helper' in names

    def test_bloques_creados(self):
        cfg = self._build_simple()
        assert len(cfg.basic_blocks) >= 2

    def test_instrucciones_creadas(self):
        cfg = self._build_simple()
        assert len(cfg.instructions) >= 4

    def test_pipeline_stage_inicial(self):
        cfg = self._build_simple()
        assert cfg.metadata.pipeline_stage == 'initial'

    def test_predecessores_rellenados(self):
        raw = {
            0x1000: _insn(0x1000, 'je', '0x1010', size=2),
            0x1002: _insn(0x1002, 'nop', size=1),
            0x1003: _insn(0x1003, 'ret', size=1),
            0x1010: _insn(0x1010, 'ret', size=1),
        }
        meta = BinaryMeta(
            path='/fake', sha256='c' * 64, entry_point=0x1000,
            func_symbols={0x1000: 'main'}, plt_symbols={},
        )
        cfg = CFGBuilder(arch_mnemonics=_TEST_MNEMONICS).build(raw, meta)
        block_0x1002 = cfg.basic_blocks.get('0x1002')
        if block_0x1002:
            assert '0x1000' in block_0x1002.predecessors

    def test_plt_symbols_crean_funciones_externas(self):
        raw = {
            0x1000: _insn(0x1000, 'call', '0x3000', size=5),
            0x1005: _insn(0x1005, 'ret', size=1),
        }
        meta = BinaryMeta(
            path='/fake', sha256='d' * 64, entry_point=0x1000,
            func_symbols={0x1000: 'main'},
            plt_symbols={0x3000: 'puts'},
        )
        cfg = CFGBuilder(arch_mnemonics=_TEST_MNEMONICS).build(raw, meta)
        assert '0x3000' in cfg.functions
        assert cfg.functions['0x3000'].is_plt
        assert cfg.functions['0x3000'].is_external


# ---------------------------------------------------------------------------
# PCB06 – ArchMnemonics
# ---------------------------------------------------------------------------

class TestArchMnemonics:

    def test_all_terminators_union(self):
        m = _TEST_MNEMONICS
        expected = (m.cond_branches | m.uncond_jumps | m.calls
                    | m.returns | m.syscalls | m.halts)
        assert m.all_terminators == expected

    def test_resolve_target_default(self):
        m = _TEST_MNEMONICS
        assert m.resolve_target('jmp', '0x1234') == 0x1234

    def test_resolve_target_custom_resolver(self):
        def my_resolver(mnem, ops):
            return 0xDEAD
        m = ArchMnemonics(
            cond_branches=frozenset(), uncond_jumps=frozenset({'jmp'}),
            calls=frozenset(), returns=frozenset(), syscalls=frozenset(),
            halts=frozenset(), target_resolver=my_resolver,
        )
        assert m.resolve_target('jmp', 'anything') == 0xDEAD
