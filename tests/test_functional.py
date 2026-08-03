"""
Pruebas de corrección funcional del Translator (PF01-PF06).

Verifican que el código C generado tiene la estructura correcta y que
las instrucciones individuales se traducen bien.
"""

import pytest
from flashback.core.models import (
    EnrichedCFG, BinaryInfo, Metadata, Function, BasicBlock, Instruction,
    TracePointAnnotation, ExternalCallAnnotation, SyscallAnnotation,
)
from flashback.core.translator import Translator, TranslatorError, _reg_to_c, _mem_addr_expr


def _make_cfg() -> EnrichedCFG:
    cfg = EnrichedCFG(
        metadata=Metadata(generator='test', generator_version='0.0.1', pipeline_stage='enriched'),
        binary_info=BinaryInfo(filename='test.elf', sha256='b' * 64, entry_point='0x401000'),
    )
    cfg.functions['0x401000'] = Function(
        address='0x401000', name='main', is_plt=False, is_external=False,
        entry_block='0x401000', blocks=['0x401000'],
    )
    cfg.basic_blocks['0x401000'] = BasicBlock(
        address='0x401000', size=4, function='0x401000',
        instructions=['0x401000', '0x401001'],
    )
    cfg.instructions['0x401000'] = Instruction(
        address='0x401000', mnemonic='push', operands='rbp',
        bytes='55', size=1, block='0x401000',
    )
    cfg.instructions['0x401001'] = Instruction(
        address='0x401001', mnemonic='ret', operands='',
        bytes='c3', size=1, block='0x401000',
    )
    return cfg


# ------------------------------------------------------------------
# PF01 – Estructura básica del fichero C generado
# ------------------------------------------------------------------

class TestPF01_Estructura:

    def test_devuelve_string(self):
        assert isinstance(Translator().translate(_make_cfg()), str)

    def test_falla_con_cfg_inicial(self):
        cfg = _make_cfg()
        cfg.metadata.pipeline_stage = 'initial'
        with pytest.raises(TranslatorError):
            Translator().translate(cfg)

    def test_incluye_stdint(self):
        assert '#include <stdint.h>' in Translator().translate(_make_cfg())

    def test_incluye_registros(self):
        out = Translator().translate(_make_cfg())
        assert 'static uint64_t rax' in out
        assert 'static uint64_t rsp' in out

    def test_incluye_flags(self):
        assert 'static uint8_t ZF' in Translator().translate(_make_cfg())

    def test_incluye_runtime_traza(self):
        assert '__trace_buffer' in Translator().translate(_make_cfg())

    def test_incluye_main(self):
        assert 'int main(' in Translator().translate(_make_cfg())

    def test_incluye_label_funcion(self):
        assert 'func_401000' in Translator().translate(_make_cfg())


# ------------------------------------------------------------------
# PF02 – Portabilidad (stack simulado)
# ------------------------------------------------------------------

class TestPF02_Portabilidad:

    def test_sim_stack_presente(self):
        assert '__sim_stack' in Translator().translate(_make_cfg())

    def test_rsp_apunta_a_sim_stack(self):
        assert '__sim_stack + SIM_STACK_SIZE' in Translator().translate(_make_cfg())

    def test_no_usa_stack_real(self):
        assert '__builtin_frame_address' not in Translator().translate(_make_cfg())

    def test_macros_sim_read_write(self):
        out = Translator().translate(_make_cfg())
        assert 'SIM_READ64' in out
        assert 'SIM_WRITE64' in out

    def test_push_usa_sim_write(self):
        assert 'SIM_WRITE64(rsp,' in Translator().translate(_make_cfg())

    def test_pop_usa_sim_read(self):
        cfg = _make_cfg()
        cfg.basic_blocks['0x401000'].instructions.append('0x401002')
        cfg.instructions['0x401002'] = Instruction(
            address='0x401002', mnemonic='pop', operands='rbp',
            bytes='5d', size=1, block='0x401000',
        )
        assert 'SIM_READ64(rsp)' in Translator().translate(cfg)

    def test_uintptr_t_en_casts(self):
        assert 'uintptr_t' in Translator().translate(_make_cfg())

    def test_asercion_64bit(self):
        assert '__assert_64bit_ptr' in Translator().translate(_make_cfg())

    def test_cabecera_menciona_arm64(self):
        out = Translator().translate(_make_cfg())
        assert 'ARM64' in out or 'arm64' in out.lower() or 'aarch64' in out.lower()

    def test_stack_size_personalizado(self):
        out = Translator(sim_stack_mb=16).translate(_make_cfg())
        assert str(16 * 1024 * 1024) in out


# ------------------------------------------------------------------
# PF03 – Llamadas externas portables
# ------------------------------------------------------------------

class TestPF03_LlamadasExternas:

    def _cfg_con_call(self, func_name: str) -> EnrichedCFG:
        cfg = _make_cfg()
        cfg.functions['0x401030'] = Function(
            address='0x401030', name=func_name, is_plt=True, is_external=True,
            entry_block='0x401030',
        )
        cfg.basic_blocks['0x401000'].instructions.append('0x401005')
        cfg.instructions['0x401005'] = Instruction(
            address='0x401005', mnemonic='call', operands='0x401030',
            bytes='e8000000', size=5, block='0x401000',
            annotations=[ExternalCallAnnotation(added_by='enricher', function_name=func_name, library='libc.so.6')],
        )
        return cfg

    def test_printf_usa_uintptr_t(self):
        out = Translator().translate(self._cfg_con_call('printf'))
        assert 'printf(' in out
        assert 'uintptr_t' in out

    def test_funcion_conocida_genera_llamada_directa(self):
        out = Translator().translate(self._cfg_con_call('printf'))
        assert 'printf(' in out
        assert 'TODO' not in out

    def test_funcion_void_no_asigna_rax(self):
        out = Translator().translate(self._cfg_con_call('free'))
        assert 'free(' in out
        assert not any('rax' in l for l in out.splitlines() if 'free(' in l)

    def test_malloc_retorna_a_rax(self):
        out = Translator().translate(self._cfg_con_call('malloc'))
        assert any('rax' in l for l in out.splitlines() if 'malloc(' in l)

    def test_funcion_desconocida_genera_llamada_generica(self):
        out = Translator().translate(self._cfg_con_call('funcion_xyz_desconocida'))
        assert 'funcion_xyz_desconocida(' in out


# ------------------------------------------------------------------
# PF04 – Syscalls portables
# ------------------------------------------------------------------

class TestPF04_Syscalls:

    def _cfg_con_syscall(self, num: int, name: str) -> EnrichedCFG:
        cfg = _make_cfg()
        cfg.basic_blocks['0x401000'].instructions.append('0x401010')
        cfg.instructions['0x401010'] = Instruction(
            address='0x401010', mnemonic='syscall', operands='',
            bytes='0f05', size=2, block='0x401000',
            annotations=[SyscallAnnotation(
                added_by='enricher', syscall_number=num, syscall_name=name,
                argument_registers=['rdi', 'rsi', 'rdx'],
            )],
        )
        return cfg

    def test_write_syscall_usa_libc_write(self):
        out = Translator().translate(self._cfg_con_syscall(1, 'write'))
        assert 'write(' in out

    def test_syscall_desconocida_usa_syscall_portable(self):
        out = Translator().translate(self._cfg_con_syscall(999, 'unknown_sc'))
        assert 'syscall(' in out

    def test_exit_syscall_usa_libc_exit(self):
        out = Translator().translate(self._cfg_con_syscall(60, 'exit'))
        assert 'exit(' in out


# ------------------------------------------------------------------
# PF05 – Trazabilidad
# ------------------------------------------------------------------

class TestPF05_Trazabilidad:

    def test_trace_point_emite_llamada_trace(self):
        cfg = _make_cfg()
        cfg.instructions['0x401000'].annotations.append(
            TracePointAnnotation(added_by='enricher', reason='block_entry')
        )
        assert '__trace(0x401000ULL)' in Translator().translate(cfg)

    def test_sin_trace_point_no_hay_llamada(self):
        assert '__trace(0x401000ULL)' not in Translator().translate(_make_cfg())

    def test_comentario_de_trazabilidad_siempre_presente(self):
        assert '/* 0x401000: push rbp */' in Translator().translate(_make_cfg())


# ------------------------------------------------------------------
# PF06 – Traducción de instrucciones
# ------------------------------------------------------------------

class TestPF06_Instrucciones:

    def _cfg_con_mnemonic(self, mnemonic: str, operands: str) -> EnrichedCFG:
        cfg = _make_cfg()
        cfg.instructions['0x401000'].mnemonic = mnemonic
        cfg.instructions['0x401000'].operands = operands
        return cfg

    def test_nop(self):
        assert '/* nop */' in Translator().translate(self._cfg_con_mnemonic('nop', ''))

    def test_ret(self):
        assert 'return;' in Translator().translate(_make_cfg())

    def test_xor_mismo_reg(self):
        out = Translator().translate(self._cfg_con_mnemonic('xor', 'eax, eax'))
        assert '= 0;' in out

    def test_cmp_actualiza_flags(self):
        out = Translator().translate(self._cfg_con_mnemonic('cmp', 'rax, rbx'))
        assert 'ZF' in out and 'CF' in out


# ------------------------------------------------------------------
# Utilidades
# ------------------------------------------------------------------

class TestRegToC:

    def test_64bit(self):       assert _reg_to_c('rax') == 'rax'
    def test_32bit_cast(self):  assert 'uint32_t' in _reg_to_c('eax') and 'rax' in _reg_to_c('eax')
    def test_8bit_high(self):   assert 'rax' in _reg_to_c('ah') and '>> 8' in _reg_to_c('ah')
    def test_hex_imm(self):     assert '0x10' in _reg_to_c('0x10')
    def test_neg_imm(self):     assert 'int64_t' in _reg_to_c('-4')
    def test_mem_devuelve_none(self): assert _reg_to_c('qword ptr [rbp - 8]') is None


class TestMemAddrExpr:

    def test_simple(self):          assert _mem_addr_expr('[rbp - 8]') == 'rbp - 8'
    def test_con_size_prefix(self): assert _mem_addr_expr('qword ptr [rbp - 8]') == 'rbp - 8'
    def test_no_memoria(self):      assert _mem_addr_expr('rax') is None
