"""
Pruebas de resolución de saltos indirectos: Fase 1 y Fase 2 (PJ01-PJ06, PB01-PB05, PM01-PM02).

Fase 1 – Tablas de salto (switch-case):
  PJ01  _read_jt_entries resuelve correctamente entradas absolutas de 8 bytes (no-PIE)
  PJ02  _read_jt_entries resuelve correctamente offsets de 4 bytes (PIE)
  PJ03  _read_jt_entries para cuando una entrada no apunta a instrucción conocida
  PJ04  _read_jt_entries devuelve [] si table_va no está en ninguna sección
  PJ05  cfg_builder añade JumpTableAnnotation en el terminador cuando jump_table conocida
  PJ06  _emit_jump_table_switch genera switch C con gotos por cada destino

Fase 2 – Backward slice para llamadas indirectas:
  PB01  _backslice_register resuelve 'mov rax, IMM' con función conocida
  PB02  _backslice_register devuelve None si la dirección no está en known_funcs
  PB03  _backslice_register devuelve None si no hay definición previa del registro
  PB04  _resolve_indirect_calls anota ResolvedIndirectAnnotation en 'call rax' resoluble
  PB05  _resolve_indirect_calls no anota calls directas ya resueltas

Modelos:
  PM01  JumpTableAnnotation round-trip correcto
  PM02  ResolvedIndirectAnnotation round-trip correcto
"""

import struct

from flashback.arch.x86_64.disassembler import _read_jt_entries
from flashback.arch.x86_64.enricher import (
    X86_64Enricher, _backslice_register, _extract_call_reg,
)
from flashback.core.cfg_builder import (
    BinaryMeta, RawInstruction, ArchMnemonics, CFGBuilder,
)
from flashback.core.models import (
    EnrichedCFG, BinaryInfo, Metadata, Function, BasicBlock, Instruction,
    JumpTableAnnotation, ResolvedIndirectAnnotation, deserialize_annotation,
)
from flashback.core.translator import Translator


# ---------------------------------------------------------------------------
# Helpers compartidos
# ---------------------------------------------------------------------------

_ARCH_M = ArchMnemonics(
    cond_branches=frozenset({'je', 'jne', 'jl', 'jg'}),
    uncond_jumps=frozenset({'jmp'}),
    calls=frozenset({'call'}),
    returns=frozenset({'ret'}),
    syscalls=frozenset({'syscall'}),
    halts=frozenset({'hlt'}),
)


def _insn(addr: int, mnemonic: str, operands: str = '', size: int = 1,
          regs_written: list[str] | None = None) -> RawInstruction:
    return RawInstruction(
        address=addr, mnemonic=mnemonic, operands=operands,
        bytes_hex='90', size=size,
        registers_written=regs_written or [],
    )


def _make_cfg_with_indirect_call(
    call_addr: int = 0x1010,
    mov_addr: int = 0x1008,
    target_func_addr: int = 0x2000,
    target_func_name: str = 'helper',
) -> EnrichedCFG:
    """CFG mínimo con 'mov rax, IMM; call rax' en el mismo bloque."""
    cfg = EnrichedCFG(
        metadata=Metadata(generator='test', generator_version='0',
                          pipeline_stage='initial',
                          capstone_version='5', lief_version='0.14'),
        binary_info=BinaryInfo(filename='t.elf', sha256='a' * 64,
                               entry_point='0x1000', architecture='amd64',
                               is_pie=False, is_stripped=False),
    )
    tf = hex(target_func_addr)
    cfg.functions['0x1000'] = Function(
        address='0x1000', name='main', is_plt=False, is_external=False,
        entry_block='0x1000', blocks=['0x1000'],
    )
    cfg.functions[tf] = Function(
        address=tf, name=target_func_name, is_plt=False, is_external=False,
        entry_block=tf,
    )
    cfg.basic_blocks['0x1000'] = BasicBlock(
        address='0x1000', size=20, function='0x1000',
        instructions=[hex(mov_addr), hex(call_addr)],
    )
    cfg.instructions[hex(mov_addr)] = Instruction(
        address=hex(mov_addr), mnemonic='mov',
        operands=f'rax, {hex(target_func_addr)}',
        bytes='48b8', size=8, block='0x1000',
        registers_written=['rax'],
    )
    cfg.instructions[hex(call_addr)] = Instruction(
        address=hex(call_addr), mnemonic='call',
        operands='rax',
        bytes='ffd0', size=2, block='0x1000',
    )
    return cfg


# ---------------------------------------------------------------------------
# PJ01-PJ04 – _read_jt_entries
# ---------------------------------------------------------------------------

class TestReadJtEntries:

    def _make_insns(self, addrs: list[int]) -> dict[int, RawInstruction]:
        return {a: _insn(a, 'nop') for a in addrs}

    def test_pj01_abs64_no_pie(self):
        """Entradas absolutas de 8 bytes (no-PIE): devuelve los destinos en orden."""
        targets = [0x1000, 0x1010, 0x1020]
        table_va = 0x2000
        data = struct.pack('<' + 'Q' * len(targets), *targets)
        raw_insns = self._make_insns(targets)
        result = _read_jt_entries(table_va, [(table_va, data)], raw_insns, is_pie=False)
        assert result == targets

    def test_pj02_rel32_pie(self):
        """Entradas de 4 bytes con signo (PIE): target = table_va + rel."""
        table_va = 0x3000
        targets = [0x3100, 0x3200, 0x3300]
        offsets = [t - table_va for t in targets]
        data = struct.pack('<' + 'i' * len(offsets), *offsets)
        raw_insns = self._make_insns(targets)
        result = _read_jt_entries(table_va, [(table_va, data)], raw_insns, is_pie=True)
        assert result == targets

    def test_pj03_para_en_entrada_invalida(self):
        """Para de leer cuando una entrada no apunta a instrucción conocida."""
        table_va = 0x2000
        valid = [0x1000, 0x1010]
        invalid = 0xDEAD_BEEF
        data = struct.pack('<QQQ', valid[0], invalid, valid[1])
        raw_insns = self._make_insns(valid)
        result = _read_jt_entries(table_va, [(table_va, data)], raw_insns, is_pie=False)
        assert result == [valid[0]]  # para al llegar a invalid

    def test_pj04_tabla_fuera_de_seccion(self):
        """Devuelve [] si table_va no está cubierto por ninguna sección."""
        raw_insns = self._make_insns([0x1000])
        result = _read_jt_entries(0xFFFF_0000, [(0x2000, b'\x00' * 64)], raw_insns, False)
        assert result == []


# ---------------------------------------------------------------------------
# PJ05 – JumpTableAnnotation en el terminador (vía CFGBuilder)
# ---------------------------------------------------------------------------

class TestJumpTableInCFGBuilder:

    def test_pj05_jump_table_annotation_en_terminador(self):
        """
        Cuando meta.jump_tables tiene una entrada para el 'jmp' terminal,
        CFGBuilder añade JumpTableAnnotation a esa instrucción.
        """
        jmp_addr = 0x1004
        targets = [0x2000, 0x3000]
        raw = {
            0x1000: _insn(0x1000, 'nop', size=4),
            jmp_addr: _insn(jmp_addr, 'jmp', 'rax', size=2),
            0x2000: _insn(0x2000, 'ret'),
            0x3000: _insn(0x3000, 'ret'),
        }
        meta = BinaryMeta(
            path='/fake', sha256='b' * 64, entry_point=0x1000,
            architecture='amd64',
            func_symbols={0x1000: 'main'},
            plt_symbols={},
            jump_tables={jmp_addr: targets},
            jump_table_index_regs={jmp_addr: 'rax'},
        )
        cfg = CFGBuilder(arch_mnemonics=_ARCH_M).build(raw, meta)
        jmp_insn = cfg.instructions.get(hex(jmp_addr))
        assert jmp_insn is not None, 'Instrucción jmp no encontrada en el CFG'
        jt_anns = [a for a in jmp_insn.annotations if a.type == 'jump_table']
        assert len(jt_anns) == 1
        assert jt_anns[0].index_register == 'rax'
        assert set(jt_anns[0].targets) == {hex(t) for t in targets}


# ---------------------------------------------------------------------------
# PJ06 – _emit_jump_table_switch en el translator
# ---------------------------------------------------------------------------

class TestEmitJumpTableSwitch:

    def _make_translator(self) -> Translator:
        return Translator(tool_version='test-0.0')

    def test_pj06_genera_switch_con_gotos(self):
        """_emit_jump_table_switch genera un switch C con un case por destino."""
        tr = self._make_translator()
        jt_ann = JumpTableAnnotation(
            added_by='test',
            index_register='rax',
            base_address=0x1004,
            targets=['0x2000', '0x3000', '0x4000'],
        )
        block = BasicBlock(
            address='0x1000', size=8, function='0x1000',
            instructions=['0x1000', '0x1004'],
            successors=['0x2000', '0x3000', '0x4000'],
        )
        result = tr._emit_jump_table_switch(jt_ann, block)
        assert 'switch' in result
        assert 'goto block_2000' in result
        assert 'goto block_3000' in result
        assert 'goto block_4000' in result
        assert 'case 0' in result
        assert 'case 1' in result
        assert 'case 2' in result
        assert 'default: abort()' in result


# ---------------------------------------------------------------------------
# PB01-PB03 – _backslice_register
# ---------------------------------------------------------------------------

class TestBacksliceRegister:

    def _insn_model(self, mnemonic: str, operands: str,
                    regs_written: list[str]) -> Instruction:
        return Instruction(
            address='0x1000', mnemonic=mnemonic, operands=operands,
            bytes='90', size=1, block='0x1000',
            registers_written=regs_written,
        )

    def test_pb01_resuelve_mov_imm(self):
        """Resuelve 'mov rax, 0x2000' si 0x2000 está en known_funcs."""
        known = {'0x2000'}
        insns = [self._insn_model('mov', 'rax, 0x2000', ['rax'])]
        result = _backslice_register('rax', insns, known)
        assert result == '0x2000'

    def test_pb02_imm_no_en_known_funcs(self):
        """Devuelve None si IMM no corresponde a ninguna función conocida."""
        known = {'0x9999'}
        insns = [self._insn_model('mov', 'rax, 0x2000', ['rax'])]
        result = _backslice_register('rax', insns, known)
        assert result is None

    def test_pb03_sin_definicion_previa(self):
        """Devuelve None si el registro nunca fue escrito en las instrucciones previas."""
        known = {'0x2000'}
        insns = [self._insn_model('nop', '', [])]
        result = _backslice_register('rax', insns, known)
        assert result is None

    def test_pb03b_otro_registro_no_interfiere(self):
        """Solo busca escrituras del registro solicitado."""
        known = {'0x2000'}
        insns = [self._insn_model('mov', 'rbx, 0x2000', ['rbx'])]
        result = _backslice_register('rax', insns, known)
        assert result is None


# ---------------------------------------------------------------------------
# PB04-PB05 – _resolve_indirect_calls (X86_64Enricher)
# ---------------------------------------------------------------------------

class TestResolveIndirectCalls:

    def test_pb04_anota_call_rax_resoluble(self):
        """
        _resolve_indirect_calls añade ResolvedIndirectAnnotation cuando
        'call rax' está precedido de 'mov rax, <func_addr>' en el mismo bloque.
        """
        cfg = _make_cfg_with_indirect_call(
            call_addr=0x1010, mov_addr=0x1008,
            target_func_addr=0x2000, target_func_name='helper',
        )
        enricher = X86_64Enricher()
        enricher._resolve_indirect_calls(cfg)

        call_insn = cfg.instructions[hex(0x1010)]
        resolved_anns = [a for a in call_insn.annotations if a.type == 'resolved_indirect']
        assert len(resolved_anns) == 1
        assert resolved_anns[0].resolved_target == hex(0x2000)
        assert resolved_anns[0].method == 'backslice_local'

    def test_pb05_call_directa_no_anotada(self):
        """
        Una 'call 0x2000' directa no recibe ResolvedIndirectAnnotation
        porque ya está resuelta por el CFGBuilder/PLT.
        """
        cfg = EnrichedCFG(
            metadata=Metadata(generator='t', generator_version='0',
                              pipeline_stage='initial',
                              capstone_version='5', lief_version='0.14'),
            binary_info=BinaryInfo(filename='t.elf', sha256='a' * 64,
                                   entry_point='0x1000', architecture='amd64',
                                   is_pie=False, is_stripped=False),
        )
        cfg.functions['0x1000'] = Function(
            address='0x1000', name='main', is_plt=False, is_external=False,
            entry_block='0x1000', blocks=['0x1000'],
        )
        cfg.functions['0x2000'] = Function(
            address='0x2000', name='helper', is_plt=False, is_external=False,
            entry_block='0x2000',
        )
        cfg.basic_blocks['0x1000'] = BasicBlock(
            address='0x1000', size=6, function='0x1000',
            instructions=['0x1000'],
        )
        cfg.instructions['0x1000'] = Instruction(
            address='0x1000', mnemonic='call', operands='0x2000',
            bytes='e8', size=5, block='0x1000',
        )
        enricher = X86_64Enricher()
        enricher._resolve_indirect_calls(cfg)
        call_insn = cfg.instructions['0x1000']
        assert not any(a.type == 'resolved_indirect' for a in call_insn.annotations)


# ---------------------------------------------------------------------------
# PM01-PM02 – Round-trip de anotaciones en modelos
# ---------------------------------------------------------------------------

class TestAnnotationModels:

    def test_pm01_jump_table_annotation_round_trip(self):
        """JumpTableAnnotation serializa y deserializa sin pérdida."""
        ann = JumpTableAnnotation(
            added_by='disassembler',
            index_register='rcx',
            base_address=0x402000,
            targets=['0x401000', '0x401020', '0x401040'],
        )
        d = ann.__dict__.copy()
        d['type'] = ann.type
        d['added_by'] = ann.added_by
        restored = deserialize_annotation(d)
        assert restored.type == 'jump_table'
        assert restored.index_register == 'rcx'  # type: ignore[attr-defined]
        assert restored.base_address == 0x402000  # type: ignore[attr-defined]
        assert restored.targets == ['0x401000', '0x401020', '0x401040']  # type: ignore[attr-defined]

    def test_pm02_resolved_indirect_annotation_round_trip(self):
        """ResolvedIndirectAnnotation serializa y deserializa sin pérdida."""
        ann = ResolvedIndirectAnnotation(
            added_by='enricher',
            resolved_target='0x2000',
            method='backslice_local',
        )
        d = ann.__dict__.copy()
        d['type'] = ann.type
        d['added_by'] = ann.added_by
        restored = deserialize_annotation(d)
        assert restored.type == 'resolved_indirect'
        assert restored.resolved_target == '0x2000'  # type: ignore[attr-defined]
        assert restored.method == 'backslice_local'  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Auxiliares adicionales de _extract_call_reg
# ---------------------------------------------------------------------------

class TestExtractCallReg:

    def test_rax_es_registro(self):
        assert _extract_call_reg('rax') == 'rax'

    def test_r15_es_registro(self):
        assert _extract_call_reg('r15') == 'r15'

    def test_memoria_no_es_registro(self):
        assert _extract_call_reg('qword ptr [rax]') is None

    def test_inmediato_no_es_registro(self):
        assert _extract_call_reg('0x1234') is None
