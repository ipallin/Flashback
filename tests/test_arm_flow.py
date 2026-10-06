"""
Pruebas del flujo de control ARM/Thumb-2 (PAF01-PAF06).

Verifican la clasificación de terminadores ARM (retornos pop/ldm/ldr pc,
saltos .w y condicionales en bloques IT, bx lr frente a bx rN), la resolución
de destinos de cbz/cbnz, las aristas explícitas del CFGBuilder (condition,
source_block, destinos 'unknown', aristas call) y el descubrimiento de código
Thumb por alcanzabilidad (tablas tbb y literal pools).
"""

import capstone
import pytest

from flashback.arch.arm32.instruction_sem import (
    classify_arm_flow, resolve_arm_branch_target, split_arm_mnemonic,
)
from flashback.arch.cortexm.disassembler import _CORTEXM_MNEMONICS, _raw
from flashback.arch.cortexm.discovery import ThumbCodeDiscovery
from flashback.core.cfg_builder import BinaryMeta, CFGBuilder, Flow, RawInstruction
from flashback.core.models import UNKNOWN_TARGET


def _insn(addr: int, mnemonic: str, operands: str = '', size: int = 2) -> RawInstruction:
    return RawInstruction(address=addr, mnemonic=mnemonic, operands=operands,
                          bytes_hex='00' * size, size=size)


def _build(raw: dict[int, RawInstruction], funcs: dict[int, str], jump_tables=None):
    meta = BinaryMeta(path='/fake/fw.elf', sha256='a' * 64, entry_point=min(funcs),
                      architecture='cortexm', func_symbols=funcs,
                      jump_tables=jump_tables or {})
    cfg = CFGBuilder(arch_mnemonics=_CORTEXM_MNEMONICS).build(raw, meta)
    cfg.validate()
    return cfg


# ---------------------------------------------------------------------------
# PAF01 – split_arm_mnemonic
# ---------------------------------------------------------------------------

class TestSplitArmMnemonic:

    @pytest.mark.parametrize('mnemonic, expected', [
        ('b', ('b', None)),
        ('b.w', ('b', None)),
        ('beq.w', ('b', 'eq')),
        ('bls', ('b', 'ls')),       # no es 'bl' + 's'
        ('blo', ('b', 'lo')),
        ('bleq', ('bl', 'eq')),
        ('blx', ('blx', None)),
        ('bxeq', ('bx', 'eq')),
        ('popne', ('pop', 'ne')),
        ('bal', ('b', None)),       # 'always' no es condicional
        ('movs', ('movs', None)),
    ])
    def test_split(self, mnemonic, expected):
        assert split_arm_mnemonic(mnemonic) == expected


# ---------------------------------------------------------------------------
# PAF02 – classify_arm_flow
# ---------------------------------------------------------------------------

class TestClassifyArmFlow:

    @pytest.mark.parametrize('mnemonic, operands, expected', [
        ('pop', '{r4, pc}', Flow('return')),
        ('pop.w', '{r4, r5, r6, pc}', Flow('return')),
        ('pophi', '{r4, r5, pc}', Flow('return', True)),
        ('ldmia', 'sp!, {r4, pc}', Flow('return')),
        ('ldr', 'pc, [sp], #4', Flow('return')),
        ('bx', 'lr', Flow('return')),
        ('bxeq', 'lr', Flow('return', True)),
        ('mov', 'pc, lr', Flow('return')),
        ('bx', 'r3', Flow('indirect_jump')),
        ('ldr.w', 'pc, [r1, r3, lsl #2]', Flow('indirect_jump')),
        ('tbb', '[pc, r3]', Flow('indirect_jump')),
        ('tbh', '[pc, r3, lsl #1]', Flow('indirect_jump')),
        ('add', 'pc, r0', Flow('indirect_jump')),
        ('b.w', '#0x8000100', Flow('branch')),
        ('bne.w', '#0x8000100', Flow('branch', True)),
        ('cbz', 'r3, #0x8000100', Flow('branch', True)),
        ('bl', '#0x8000100', Flow('call')),
        ('blx', 'r3', Flow('call')),
        ('udf', '#0xfe', Flow('halt')),
    ])
    def test_terminators(self, mnemonic, operands, expected):
        assert classify_arm_flow(mnemonic, operands) == expected

    @pytest.mark.parametrize('mnemonic, operands', [
        ('pop', '{r4, r5}'),
        ('pop.w', '{r4, r5, r6, lr}'),
        ('ldr', 'r0, [pc, #0x1c]'),
        ('moveq', 'r0, #1'),
        ('wfi', ''),
        ('wfe', ''),
    ])
    def test_non_terminators(self, mnemonic, operands):
        assert classify_arm_flow(mnemonic, operands) is None

    def test_svc_depends_on_syscalls_flag(self):
        assert classify_arm_flow('svc', '#0') == Flow('syscall')
        assert classify_arm_flow('svc', '#0', syscalls=False) is None


# ---------------------------------------------------------------------------
# PAF03 – resolve_arm_branch_target
# ---------------------------------------------------------------------------

class TestResolveArmBranchTarget:

    def test_cbz_uses_last_operand(self):
        assert resolve_arm_branch_target('cbz', 'r3, #0x8001234') == 0x8001234

    def test_wide_branch(self):
        assert resolve_arm_branch_target('b.w', '#0x809058c') == 0x809058c

    def test_register_is_none(self):
        assert resolve_arm_branch_target('bx', 'lr') is None
        assert resolve_arm_branch_target('tbb', '[pc, r3]') is None


# ---------------------------------------------------------------------------
# PAF04 – CFGBuilder con el clasificador Cortex-M
# ---------------------------------------------------------------------------

class TestCortexMBlocks:

    def test_pop_pc_ends_block_without_successors(self):
        raw = {
            0x100: _insn(0x100, 'push', '{r4, lr}'),
            0x102: _insn(0x102, 'pop', '{r4, pc}'),
            0x104: _insn(0x104, 'movs', 'r0, #0'),
            0x106: _insn(0x106, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f', 0x104: 'g'})
        assert cfg.basic_blocks['0x100'].successors == []
        assert not any(e.source_block == '0x100' for e in cfg.edges)

    def test_conditional_return_falls_through(self):
        raw = {
            0x100: _insn(0x100, 'pophi', '{r4, pc}'),
            0x102: _insn(0x102, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f'})
        assert cfg.basic_blocks['0x100'].successors == ['0x102']
        [edge] = [e for e in cfg.edges if e.source_block == '0x100']
        assert edge.type == 'fall_through'
        assert edge.condition == 'not pophi'

    def test_cbz_has_two_successors(self):
        raw = {
            0x100: _insn(0x100, 'cbz', 'r0, #0x106'),
            0x102: _insn(0x102, 'movs', 'r0, #1'),
            0x104: _insn(0x104, 'bx', 'lr'),
            0x106: _insn(0x106, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f'})
        assert cfg.basic_blocks['0x100'].successors == ['0x106', '0x102']
        edges = {e.target: e for e in cfg.edges if e.source_block == '0x100'}
        assert edges['0x106'].type == 'conditional_jump'
        assert edges['0x106'].condition == 'cbz'
        assert edges['0x102'].condition == 'not cbz'

    def test_wide_branch_splits_block(self):
        raw = {
            0x100: _insn(0x100, 'b.w', '#0x108', size=4),
            0x104: _insn(0x104, 'movs', 'r0, #1'),
            0x106: _insn(0x106, 'bx', 'lr'),
            0x108: _insn(0x108, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f'})
        assert cfg.basic_blocks['0x100'].successors == ['0x108']

    def test_bx_register_goes_to_unknown(self):
        raw = {0x100: _insn(0x100, 'bx', 'r3')}
        cfg = _build(raw, {0x100: 'f'})
        [edge] = cfg.edges
        assert edge.type == 'indirect_jump'
        assert edge.target == UNKNOWN_TARGET
        assert edge.condition == 'always'

    def test_call_edges(self):
        raw = {
            0x100: _insn(0x100, 'bl', '#0x200', size=4),
            0x104: _insn(0x104, 'blx', 'r3'),
            0x106: _insn(0x106, 'bx', 'lr'),
            0x200: _insn(0x200, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f', 0x200: 'g'})
        by_type = {(e.source, e.type): e for e in cfg.edges}
        assert by_type[('0x100', 'call')].target == '0x200'
        assert by_type[('0x100', 'fall_through')].target == '0x104'
        assert by_type[('0x104', 'call_indirect')].target == UNKNOWN_TARGET
        assert cfg.functions['0x100'].calls_to == ['0x200']

    def test_every_edge_has_condition_and_source_block(self):
        raw = {
            0x100: _insn(0x100, 'cmp', 'r0, #0'),
            0x102: _insn(0x102, 'bne', '#0x108'),
            0x104: _insn(0x104, 'bl', '#0x200', size=4),
            0x108: _insn(0x108, 'pop', '{r4, pc}'),
            0x200: _insn(0x200, 'bx', 'r1'),
        }
        cfg = _build(raw, {0x100: 'f', 0x200: 'g'})
        for edge in cfg.edges:
            assert edge.condition
            assert cfg.instructions[edge.source].block == edge.source_block


# ---------------------------------------------------------------------------
# PAF05 – ThumbCodeDiscovery: tbb y literal pools
# ---------------------------------------------------------------------------

_BASE = 0x08000000
# 0x00 cmp r0, #2 / 0x02 bhi 0x14 / 0x04 tbb [pc, r0] / 0x08 tabla {2,3,4}+pad
# 0x0c movs r0, #1 / 0x0e movs r0, #2 / 0x10 bx lr / 0x12 nop (inalcanzable)
# 0x14 ldr r0, [pc, #0] / 0x16 bx lr / 0x18 literal (se decodifica como 'b .')
_FIRMWARE = bytes.fromhex(
    '0228' '07d8' 'dfe800f0' '02030400'
    '0120' '0220' '7047' '00bf'
    '0048' '7047' 'fee7fee7'
)


def _linear(code: bytes, base: int) -> dict[int, RawInstruction]:
    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    cs.detail = True
    return {i.address: _raw(i) for i in cs.disasm(code, base)}


def _discover():
    linear = _linear(_FIRMWARE, _BASE)

    def decode_run(data, address):
        return _linear(data, address).values()

    return linear, ThumbCodeDiscovery(
        sections=[(_BASE, _FIRMWARE)],
        linear=linear,
        decode_run=decode_run,
        classify=_CORTEXM_MNEMONICS.classifier,
        resolve_target=resolve_arm_branch_target,
        func_starts={_BASE},
    ).run({_BASE})


class TestThumbCodeDiscovery:

    def test_linear_sweep_decodes_data_as_code(self):
        linear, _ = _discover()
        assert _BASE + 0x08 in linear      # bytes de la tabla
        assert _BASE + 0x18 in linear      # literal pool

    def test_tbb_table_resolved(self):
        _, result = _discover()
        tbb = _BASE + 0x04
        assert result.jump_tables[tbb] == [_BASE + 0x0c, _BASE + 0x0e, _BASE + 0x10]
        assert result.jump_table_index_regs[tbb] == 'r0'

    def test_data_is_not_code(self):
        _, result = _discover()
        insns = result.instructions
        assert _BASE + 0x08 not in insns   # tabla tbb
        assert _BASE + 0x18 not in insns   # literal
        assert _BASE + 0x1a not in insns
        assert _BASE + 0x12 not in insns   # inalcanzable tras bx lr
        assert _BASE + 0x14 in insns       # destino de bhi

    def test_switch_edges(self):
        _, result = _discover()
        cfg = _build(result.instructions, {_BASE: 'f'}, result.jump_tables)
        cases = {e.target: e.condition for e in cfg.edges
                 if e.source == hex(_BASE + 0x04)}
        assert cases == {
            hex(_BASE + 0x0c): 'case 0',
            hex(_BASE + 0x0e): 'case 1',
            hex(_BASE + 0x10): 'case 2',
        }


# ---------------------------------------------------------------------------
# PAF06 – Translator ARM: llamadas, saltos .w y tail calls
# ---------------------------------------------------------------------------

class TestArmTranslatorFlow:

    def _translate(self, raw, funcs):
        from flashback.arch.cortexm import CortexMEnricher, CortexMTranslator
        cfg = CortexMEnricher().enrich(_build(raw, funcs), granularity='none')
        return CortexMTranslator(tool_version='test').translate(cfg)

    def test_calls_are_emitted(self):
        raw = {
            0x100: _insn(0x100, 'bl', '#0x200', size=4),
            0x104: _insn(0x104, 'bx', 'lr'),
            0x200: _insn(0x200, 'bx', 'lr'),
        }
        c = self._translate(raw, {0x100: 'f', 0x200: 'g'})
        assert 'func_200();' in c

    def test_wide_conditional_branch(self):
        raw = {
            0x100: _insn(0x100, 'bne.w', '#0x106', size=4),
            0x104: _insn(0x104, 'bx', 'lr'),
            0x106: _insn(0x106, 'bx', 'lr'),
        }
        c = self._translate(raw, {0x100: 'f'})
        assert 'if (!Z) goto block_106;' in c
        assert 'UNSUPPORTED: bne.w' not in c

    def test_tail_call_is_not_a_cross_function_goto(self):
        raw = {
            0x100: _insn(0x100, 'b.w', '#0x200', size=4),
            0x200: _insn(0x200, 'bx', 'lr'),
        }
        c = self._translate(raw, {0x100: 'f', 0x200: 'g'})
        assert 'func_200(); return;' in c
        assert 'goto block_200' not in c


# ---------------------------------------------------------------------------
# PAF07 – Aristas tail_call, funciones que no retornan y deduplicación por tipo
# ---------------------------------------------------------------------------

class TestCallSemantics:

    def test_branch_to_other_function_is_tail_call(self):
        raw = {
            0x100: _insn(0x100, 'b.w', '#0x200', size=4),
            0x200: _insn(0x200, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f', 0x200: 'g'})
        [edge] = cfg.edges
        assert (edge.type, edge.target) == ('tail_call', '0x200')

    def test_branch_inside_function_is_jump(self):
        raw = {
            0x100: _insn(0x100, 'b', '#0x104'),
            0x102: _insn(0x102, 'nop'),
            0x104: _insn(0x104, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f'})
        assert [e.type for e in cfg.edges if e.source_block == '0x100'] == ['unconditional_jump']

    def test_call_and_fall_through_to_same_address(self):
        # 'bl siguiente' (obtener pc): se conservan la arista call y la fall_through
        raw = {
            0x100: _insn(0x100, 'bl', '#0x104', size=4),
            0x104: _insn(0x104, 'bx', 'lr'),
        }
        cfg = _build(raw, {0x100: 'f'})
        assert sorted(e.type for e in cfg.edges) == ['call', 'fall_through']

    def test_no_fall_through_after_noreturn_call_by_name(self):
        raw = {
            0x100: _insn(0x100, 'bl', '#0x200', size=4),
            0x104: _insn(0x104, 'movs', 'r0, r0'),     # relleno tras abort()
            0x200: _insn(0x200, 'b', '#0x200'),
        }
        cfg = _build(raw, {0x100: 'f', 0x200: 'abort'})
        assert cfg.functions['0x200'].is_noreturn
        assert cfg.basic_blocks['0x100'].successors == []
        assert [e.type for e in cfg.edges if e.source_block == '0x100'] == ['call']

    def test_conditional_noreturn_call_keeps_fall_through(self):
        raw = {
            0x100: _insn(0x100, 'bleq', '#0x200', size=4),
            0x104: _insn(0x104, 'bx', 'lr'),
            0x200: _insn(0x200, 'b', '#0x200'),
        }
        cfg = _build(raw, {0x100: 'f', 0x200: '_exit'})
        assert cfg.basic_blocks['0x100'].successors == ['0x104']


# 0x00 bl panic / 0x04 movs r0, r0 (relleno) / 0x06 bx lr (inalcanzable)
# 0x08 panic: b . (bucle infinito, sin retorno)
_NORETURN_FW = bytes.fromhex('00f002f8' '0000' '7047' 'fee7')


class TestNoreturnDiscovery:

    def test_infinite_loop_function_is_noreturn(self):
        linear = _linear(_NORETURN_FW, _BASE)

        def decode_run(data, address):
            return _linear(data, address).values()

        result = ThumbCodeDiscovery(
            sections=[(_BASE, _NORETURN_FW)], linear=linear, decode_run=decode_run,
            classify=_CORTEXM_MNEMONICS.classifier, resolve_target=resolve_arm_branch_target,
            func_starts={_BASE, _BASE + 8},
        ).run({_BASE, _BASE + 8})
        assert result.noreturn == {_BASE, _BASE + 8}    # f solo llama a panic
        assert _BASE + 4 not in result.instructions     # relleno tras la llamada
        assert _BASE + 6 not in result.instructions


class TestCortexMFunctionSymbols:

    def test_runtime_functions_are_kept(self, tmp_path):
        import lief
        from flashback.arch.cortexm.disassembler import CortexMDisassembler

        class _Sym:
            def __init__(self, name, value):
                self.name, self.value = name, value
                self.type = lief.ELF.Symbol.TYPE.FUNC

        class _Elf:
            entrypoint = 0x8000101
            symbols = [_Sym('main', 0x8000201), _Sym('_exit', 0x8000301)]

        funcs = CortexMDisassembler()._find_func_symbols(_Elf())
        assert funcs[0x8000200] == 'main'
        assert funcs[0x8000300] == '_exit'
