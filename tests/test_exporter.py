"""
Pruebas del Exporter y serialización de modelos (PE01-PE04).

Verifican que el CFG puede guardarse a JSON, recargarse y que el resultado
es estructuralmente idéntico al original, incluyendo validación de schema.
"""

import json
import pytest

from flashback.core.models import (
    EnrichedCFG, BinaryInfo, Metadata, Function, BasicBlock,
    Instruction, Edge, ExternalCallAnnotation, SyscallAnnotation,
    TracePointAnnotation, FunctionalClassAnnotation,
    deserialize_annotation, hex_addr, CFGValidationError,
)
from flashback.core.exporter import Exporter, ExporterError


# ---------------------------------------------------------------------------
# Fixture: CFG enriquecido mínimo con todas las entidades
# ---------------------------------------------------------------------------

def _make_full_cfg() -> EnrichedCFG:
    cfg = EnrichedCFG(
        metadata=Metadata(
            generator='test', generator_version='0.0.1',
            pipeline_stage='enriched',
            capstone_version='5.0', lief_version='0.14',
        ),
        binary_info=BinaryInfo(
            filename='test.elf', sha256='a' * 64,
            entry_point='0x1000', architecture='amd64',
            is_pie=False, is_stripped=False,
        ),
    )
    cfg.functions['0x1000'] = Function(
        address='0x1000', name='main', is_plt=False, is_external=False,
        entry_block='0x1000', blocks=['0x1000', '0x1010'],
    )
    cfg.functions['0x2000'] = Function(
        address='0x2000', name='puts', is_plt=True, is_external=True,
        entry_block='0x2000',
    )
    cfg.basic_blocks['0x1000'] = BasicBlock(
        address='0x1000', size=8, function='0x1000',
        instructions=['0x1000', '0x1004'],
        successors=['0x1010'],
        annotations=[FunctionalClassAnnotation(added_by='test', category='function_prologue')],
    )
    cfg.basic_blocks['0x1010'] = BasicBlock(
        address='0x1010', size=4, function='0x1000',
        instructions=['0x1010'],
        predecessors=['0x1000'],
    )
    cfg.instructions['0x1000'] = Instruction(
        address='0x1000', mnemonic='push', operands='rbp',
        bytes='55', size=1, block='0x1000',
        annotations=[TracePointAnnotation(added_by='test', reason='block_entry')],
    )
    cfg.instructions['0x1004'] = Instruction(
        address='0x1004', mnemonic='call', operands='0x2000',
        bytes='e8000000', size=5, block='0x1000',
        annotations=[ExternalCallAnnotation(
            added_by='test', function_name='puts',
            library='libc.so.6', prototype='int puts(const char*)',
            argument_registers=['rdi'],
        )],
    )
    cfg.instructions['0x1010'] = Instruction(
        address='0x1010', mnemonic='ret', operands='',
        bytes='c3', size=1, block='0x1010',
        annotations=[SyscallAnnotation(
            added_by='test', syscall_number=60, syscall_name='exit',
            argument_registers=['rdi'], return_register='rax',
        )],
    )
    cfg.edges = [
        Edge(source='0x1000', target='0x1010', type='fall_through'),
    ]
    return cfg


# ---------------------------------------------------------------------------
# PE01 – Serialización/deserialización round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:

    def test_to_dict_from_dict_identity(self):
        original = _make_full_cfg()
        d = original.to_dict()
        restored = EnrichedCFG.from_dict(d)
        assert restored.metadata.generator == original.metadata.generator
        assert restored.binary_info.filename == original.binary_info.filename
        assert set(restored.functions) == set(original.functions)
        assert set(restored.basic_blocks) == set(original.basic_blocks)
        assert set(restored.instructions) == set(original.instructions)

    def test_anotaciones_se_restauran(self):
        original = _make_full_cfg()
        restored = EnrichedCFG.from_dict(original.to_dict())
        anns = restored.instructions['0x1000'].annotations
        assert any(a.type == 'trace_point' for a in anns)

    def test_external_call_annotation_round_trip(self):
        original = _make_full_cfg()
        restored = EnrichedCFG.from_dict(original.to_dict())
        call_anns = [a for a in restored.instructions['0x1004'].annotations
                     if a.type == 'external_call']
        assert len(call_anns) == 1
        assert call_anns[0].function_name == 'puts'  # type: ignore

    def test_syscall_annotation_round_trip(self):
        original = _make_full_cfg()
        restored = EnrichedCFG.from_dict(original.to_dict())
        sys_anns = [a for a in restored.instructions['0x1010'].annotations
                    if a.type == 'syscall']
        assert len(sys_anns) == 1
        assert sys_anns[0].syscall_number == 60  # type: ignore

    def test_edges_se_restauran(self):
        original = _make_full_cfg()
        restored = EnrichedCFG.from_dict(original.to_dict())
        assert len(restored.edges) == 1
        assert restored.edges[0].type == 'fall_through'


# ---------------------------------------------------------------------------
# PE02 – Exporter.save / Exporter.load
# ---------------------------------------------------------------------------

class TestExporterSaveLoad:

    def test_save_crea_fichero(self, tmp_path):
        cfg = _make_full_cfg()
        exp = Exporter()
        out = exp.save(cfg, str(tmp_path / 'cfg.json'))
        assert out.exists()
        assert out.stat().st_size > 0

    def test_save_es_json_valido(self, tmp_path):
        cfg = _make_full_cfg()
        exp = Exporter()
        out = exp.save(cfg, str(tmp_path / 'cfg.json'))
        with open(out) as f:
            data = json.load(f)
        assert 'schema_version' in data
        assert 'functions' in data

    def test_load_reconstruye_cfg(self, tmp_path):
        cfg = _make_full_cfg()
        exp = Exporter()
        path = str(tmp_path / 'cfg.json')
        exp.save(cfg, path)
        loaded = exp.load(path)
        assert 'main' in {f.name for f in loaded.functions.values()}

    def test_load_fichero_inexistente_lanza_error(self):
        exp = Exporter()
        with pytest.raises(ExporterError):
            exp.load('/ruta/que/no/existe.json')

    def test_save_crea_directorios_intermedios(self, tmp_path):
        cfg = _make_full_cfg()
        exp = Exporter()
        deep_path = str(tmp_path / 'a' / 'b' / 'c' / 'cfg.json')
        out = exp.save(cfg, deep_path)
        assert out.exists()


# ---------------------------------------------------------------------------
# PE03 – Validación del CFG
# ---------------------------------------------------------------------------

class TestCFGValidation:

    def test_cfg_valido_no_lanza(self):
        cfg = _make_full_cfg()
        cfg.validate()  # no debe lanzar

    def test_funcion_con_entry_block_inexistente_invalida(self):
        cfg = _make_full_cfg()
        cfg.functions['0x1000'].entry_block = '0xDEAD'
        with pytest.raises(CFGValidationError):
            cfg.validate()

    def test_bloque_con_instruccion_inexistente_invalido(self):
        cfg = _make_full_cfg()
        cfg.basic_blocks['0x1000'].instructions.append('0xCAFE')
        with pytest.raises(CFGValidationError):
            cfg.validate()

    def test_instruccion_con_bloque_inexistente_invalida(self):
        cfg = _make_full_cfg()
        cfg.instructions['0x1000'].block = '0xBAD'
        with pytest.raises(CFGValidationError):
            cfg.validate()


# ---------------------------------------------------------------------------
# PE04 – Modelos: hex_addr y deserialize_annotation
# ---------------------------------------------------------------------------

class TestModels:

    def test_hex_addr_int(self):
        assert hex_addr(0x1234) == '0x1234'

    def test_hex_addr_string(self):
        assert hex_addr('0xABCD') == '0xabcd'

    def test_hex_addr_sin_prefijo_lanza(self):
        with pytest.raises(ValueError):
            hex_addr('1234')

    def test_hex_addr_tipo_invalido_lanza(self):
        with pytest.raises(TypeError):
            hex_addr(3.14)  # type: ignore

    def test_deserialize_annotation_tipo_desconocido(self):
        ann = deserialize_annotation({'type': 'unknown_type', 'added_by': 'test'})
        assert ann.type == 'unknown_type'

    def test_deserialize_annotation_external_call(self):
        data = {
            'type': 'external_call',
            'added_by': 'enricher',
            'function_name': 'malloc',
            'library': 'libc.so.6',
        }
        ann = deserialize_annotation(data)
        assert ann.type == 'external_call'
        assert ann.function_name == 'malloc'  # type: ignore

    def test_cfg_from_dict_version_incompatible(self):
        cfg = _make_full_cfg()
        d = cfg.to_dict()
        d['schema_version'] = '99.0.0'
        with pytest.raises(CFGValidationError):
            EnrichedCFG.from_dict(d)

    def test_cfg_from_dict_sin_schema_version(self):
        cfg = _make_full_cfg()
        d = cfg.to_dict()
        del d['schema_version']
        with pytest.raises(CFGValidationError):
            EnrichedCFG.from_dict(d)
