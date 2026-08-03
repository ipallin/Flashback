"""
Modelo de datos del CFG enriquecido.

Estructura central del pipeline: es la representación intercambiada entre
Disassembler → CFGBuilder → Enricher → Translator.

El esquema JSON formal está en docs/02_cfg_schema.json.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal, Optional
import json
import hashlib

SCHEMA_VERSION = '1.0.0'

HexAddr = str  # Siempre '0xNNNNNN' en minúsculas

GranularityType = Literal['none', 'block', 'instruction', 'selective']
FunctionalCategory = Literal[
    'function_prologue', 'function_epilogue', 'function_body',
    'external_call_site', 'syscall_site', 'loop_header',
    'return_block', 'unreachable',
    'jump_table_site', 'indirect_call_site',
]
TracePointReason = Literal[
    'block_entry', 'external_call_site', 'syscall_site',
    'loop_backedge', 'user_request'
]
EdgeType = Literal[
    'fall_through', 'unconditional_jump', 'conditional_jump',
    'call', 'call_indirect', 'return', 'indirect_jump', 'syscall'
]
PipelineStage = Literal['initial', 'enriched']


def hex_addr(value: int | str) -> HexAddr:
    if isinstance(value, int):
        return f'0x{value:x}'
    if isinstance(value, str):
        if not value.startswith('0x'):
            raise ValueError(f'Dirección sin prefijo 0x: {value}')
        return value.lower()
    raise TypeError(f'Tipo no soportado para dirección: {type(value)}')


# ---------------------------------------------------------------------------
# Anotaciones
# ---------------------------------------------------------------------------

@dataclass
class Annotation:
    type: str
    added_by: str


@dataclass
class ExternalCallAnnotation(Annotation):
    function_name: str = ''
    library: str = ''
    prototype: Optional[str] = None
    argument_registers: list[str] = field(default_factory=list)

    def __init__(self, added_by: str, function_name: str = '', library: str = '',
                 prototype: Optional[str] = None, argument_registers: Optional[list] = None, **_):
        super().__init__(type='external_call', added_by=added_by)
        self.function_name = function_name
        self.library = library
        self.prototype = prototype
        self.argument_registers = argument_registers or []


@dataclass
class SyscallAnnotation(Annotation):
    syscall_number: int = 0
    syscall_name: Optional[str] = None
    argument_registers: list[str] = field(default_factory=list)
    return_register: Optional[str] = None

    def __init__(self, added_by: str, syscall_number: int = 0,
                 syscall_name: Optional[str] = None,
                 argument_registers: Optional[list] = None,
                 return_register: Optional[str] = None, **_):
        super().__init__(type='syscall', added_by=added_by)
        self.syscall_number = syscall_number
        self.syscall_name = syscall_name
        self.argument_registers = argument_registers or []
        self.return_register = return_register


@dataclass
class FunctionalClassAnnotation(Annotation):
    category: FunctionalCategory = 'function_body'
    description: Optional[str] = None

    def __init__(self, added_by: str, category: FunctionalCategory = 'function_body',
                 description: Optional[str] = None, **_):
        super().__init__(type='functional_class', added_by=added_by)
        self.category = category
        self.description = description


@dataclass
class TraceRecommendationAnnotation(Annotation):
    granularity: GranularityType = 'block'
    rationale: Optional[str] = None

    def __init__(self, added_by: str, granularity: GranularityType = 'block',
                 rationale: Optional[str] = None, **_):
        super().__init__(type='trace_recommendation', added_by=added_by)
        self.granularity = granularity
        self.rationale = rationale


@dataclass
class TracePointAnnotation(Annotation):
    reason: TracePointReason = 'block_entry'

    def __init__(self, added_by: str, reason: TracePointReason = 'block_entry', **_):
        super().__init__(type='trace_point', added_by=added_by)
        self.reason = reason


@dataclass
class JumpTableAnnotation(Annotation):
    """Tabla de salto switch-case resuelta estáticamente (Fase 1)."""
    index_register: str = ''
    base_address: int = 0
    targets: list = field(default_factory=list)  # list[HexAddr]

    def __init__(self, added_by: str, index_register: str = '',
                 base_address: int = 0, targets: list | None = None, **_):
        super().__init__(type='jump_table', added_by=added_by)
        self.index_register = index_register
        self.base_address = base_address
        self.targets = targets or []


@dataclass
class ResolvedIndirectAnnotation(Annotation):
    """Llamada o salto indirecto resuelto por backward slice local (Fase 2)."""
    resolved_target: str = ''
    method: str = 'backslice_local'

    def __init__(self, added_by: str, resolved_target: str = '',
                 method: str = 'backslice_local', **_):
        super().__init__(type='resolved_indirect', added_by=added_by)
        self.resolved_target = resolved_target
        self.method = method


ANNOTATION_REGISTRY: dict[str, type[Annotation]] = {
    'external_call': ExternalCallAnnotation,
    'syscall': SyscallAnnotation,
    'functional_class': FunctionalClassAnnotation,
    'trace_recommendation': TraceRecommendationAnnotation,
    'trace_point': TracePointAnnotation,
    'jump_table': JumpTableAnnotation,
    'resolved_indirect': ResolvedIndirectAnnotation,
}


def deserialize_annotation(data: dict) -> Annotation:
    ann_type = data.get('type')
    if ann_type not in ANNOTATION_REGISTRY:
        return Annotation(type=ann_type, added_by=data.get('added_by', 'unknown'))
    cls = ANNOTATION_REGISTRY[ann_type]
    kwargs = {k: v for k, v in data.items() if k != 'type'}
    return cls(type=ann_type, **kwargs)


# ---------------------------------------------------------------------------
# Accesos a memoria
# ---------------------------------------------------------------------------

@dataclass
class MemoryAccess:
    type: Literal['read', 'write', 'read_write']
    size: int
    scale: Literal[1, 2, 4, 8] = 1
    offset: int = 0
    base_register: Optional[str] = None
    index_register: Optional[str] = None


# ---------------------------------------------------------------------------
# Entidades del CFG
# ---------------------------------------------------------------------------

@dataclass
class Function:
    address: HexAddr
    name: str
    is_plt: bool
    is_external: bool
    entry_block: HexAddr
    blocks: list[HexAddr] = field(default_factory=list)
    called_from: list[HexAddr] = field(default_factory=list)
    calls_to: list[HexAddr] = field(default_factory=list)
    annotations: list[Annotation] = field(default_factory=list)


@dataclass
class BasicBlock:
    address: HexAddr
    size: int
    function: HexAddr
    instructions: list[HexAddr] = field(default_factory=list)
    successors: list[HexAddr] = field(default_factory=list)
    predecessors: list[HexAddr] = field(default_factory=list)
    annotations: list[Annotation] = field(default_factory=list)


@dataclass
class Instruction:
    address: HexAddr
    mnemonic: str
    operands: str
    bytes: str
    size: int
    block: HexAddr
    registers_read: list[str] = field(default_factory=list)
    registers_written: list[str] = field(default_factory=list)
    memory_accesses: list[MemoryAccess] = field(default_factory=list)
    annotations: list[Annotation] = field(default_factory=list)


@dataclass
class Edge:
    source: HexAddr
    target: HexAddr
    type: EdgeType
    condition: Optional[str] = None
    annotations: list[Annotation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Metadata y binary info
# ---------------------------------------------------------------------------

@dataclass
class Metadata:
    generator: str = 'flashback'
    generator_version: str = '0.1.0'
    generation_timestamp: str = ''
    pipeline_stage: PipelineStage = 'initial'
    capstone_version: Optional[str] = None
    lief_version: Optional[str] = None
    extensions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.generation_timestamp:
            self.generation_timestamp = (
                datetime.now(timezone.utc)
                .isoformat(timespec='seconds')
                .replace('+00:00', 'Z')
            )


@dataclass
class BinaryInfo:
    filename: str
    sha256: str
    entry_point: HexAddr
    architecture: Literal['amd64', 'arm64', 'i386', 'arm32', 'cortexm'] = 'amd64'
    bits: Literal[64] = 64
    endianness: Literal['little'] = 'little'
    format: Literal['ELF'] = 'ELF'
    path: Optional[str] = None
    is_pie: Optional[bool] = None
    is_stripped: Optional[bool] = None
    rodata_va: Optional[int] = None   # Dirección virtual de .rodata
    rodata_hex: Optional[str] = None  # Bytes de .rodata en hex
    data_va: Optional[int] = None     # Dirección virtual de .data
    data_hex: Optional[str] = None    # Bytes de .data en hex
    bss_va: Optional[int] = None      # Dirección virtual de .bss
    bss_size: Optional[int] = None    # Tamaño de .bss (zero-init)


# ---------------------------------------------------------------------------
# CFG completo
# ---------------------------------------------------------------------------

class CFGValidationError(Exception):
    pass


@dataclass
class EnrichedCFG:
    metadata: Metadata
    binary_info: BinaryInfo
    functions: dict[HexAddr, Function] = field(default_factory=dict)
    basic_blocks: dict[HexAddr, BasicBlock] = field(default_factory=dict)
    instructions: dict[HexAddr, Instruction] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            'schema_version': self.schema_version,
            'metadata': asdict(self.metadata),
            'binary_info': _clean_none(asdict(self.binary_info)),
            'functions': {a: _clean_none(asdict(f)) for a, f in self.functions.items()},
            'basic_blocks': {a: _clean_none(asdict(b)) for a, b in self.basic_blocks.items()},
            'instructions': {a: _clean_none(asdict(i)) for a, i in self.instructions.items()},
            'edges': [_clean_none(asdict(e)) for e in self.edges],
        }

    def save(self, path: str, indent: int = 2) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> EnrichedCFG:
        version = data.get('schema_version')
        if not version:
            raise CFGValidationError('Falta schema_version en el fichero')
        if int(version.split('.')[0]) != int(SCHEMA_VERSION.split('.')[0]):
            raise CFGValidationError(
                f'Versión incompatible: fichero={version}, código={SCHEMA_VERSION}'
            )
        metadata_data = data['metadata'].copy()
        # Compatibilidad con ficheros generados por versión anterior (angr_version, etc.)
        for old_key in ('angr_version', 'pyelftools_version'):
            metadata_data.pop(old_key, None)

        metadata = Metadata(**metadata_data)
        binary_info = BinaryInfo(**data['binary_info'])
        functions = {a: _function_from_dict(f) for a, f in data.get('functions', {}).items()}
        basic_blocks = {a: _block_from_dict(b) for a, b in data.get('basic_blocks', {}).items()}
        instructions = {a: _instruction_from_dict(i) for a, i in data.get('instructions', {}).items()}
        edges = [_edge_from_dict(e) for e in data.get('edges', [])]
        return cls(
            schema_version=version,
            metadata=metadata,
            binary_info=binary_info,
            functions=functions,
            basic_blocks=basic_blocks,
            instructions=instructions,
            edges=edges,
        )

    @classmethod
    def load(cls, path: str) -> EnrichedCFG:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)

    def validate(self) -> None:
        errors: list[str] = []

        for addr, func in self.functions.items():
            if func.address != addr:
                errors.append(f'I1: función en {addr} tiene address {func.address}')
            if not func.is_external and func.entry_block not in self.basic_blocks:
                errors.append(f'I1: función {addr} referencia entry_block inexistente {func.entry_block}')
            for block_addr in func.blocks:
                if block_addr not in self.basic_blocks:
                    errors.append(f'I1: función {addr} referencia bloque inexistente {block_addr}')
            for called_addr in func.calls_to:
                if called_addr not in self.functions:
                    errors.append(f'I1: función {addr} llama a función inexistente {called_addr}')

        for addr, block in self.basic_blocks.items():
            if block.address != addr:
                errors.append(f'I2: bloque en {addr} tiene address {block.address}')
            if block.function not in self.functions:
                errors.append(f'I2: bloque {addr} pertenece a función inexistente {block.function}')
            elif addr not in self.functions[block.function].blocks:
                errors.append(f'I2: bloque {addr} no está en functions[{block.function}].blocks')
            for insn_addr in block.instructions:
                if insn_addr not in self.instructions:
                    errors.append(f'I2: bloque {addr} referencia instrucción inexistente {insn_addr}')

        for addr, insn in self.instructions.items():
            if insn.address != addr:
                errors.append(f'I3: instrucción en {addr} tiene address {insn.address}')
            if insn.block not in self.basic_blocks:
                errors.append(f'I3: instrucción {addr} pertenece a bloque inexistente {insn.block}')
            elif addr not in self.basic_blocks[insn.block].instructions:
                errors.append(f'I3: instrucción {addr} no está en basic_blocks[{insn.block}].instructions')

        for i, edge in enumerate(self.edges):
            if edge.source not in self.instructions:
                errors.append(f'I4: arista #{i} tiene source inexistente {edge.source}')
            if edge.target not in self.basic_blocks and edge.target not in self.functions:
                errors.append(f'I4: arista #{i} tiene target inexistente {edge.target}')
            if edge.type == 'conditional_jump' and edge.condition is None:
                errors.append(f'I4: arista condicional #{i} no tiene condition')

        for addr, block in self.basic_blocks.items():
            for succ in block.successors:
                if succ in self.basic_blocks:
                    if addr not in self.basic_blocks[succ].predecessors:
                        errors.append(
                            f'I5: bloque {addr} tiene sucesor {succ} pero {succ} no lo tiene como predecesor'
                        )

        if errors:
            raise CFGValidationError(
                f'CFG inválido, {len(errors)} errores:\n' + '\n'.join(f'  - {e}' for e in errors)
            )

    def get_annotations_of_type(self, element, ann_type: str) -> list[Annotation]:
        return [a for a in element.annotations if a.type == ann_type]

    def trace_granularity_for_block(self, block_addr: HexAddr) -> GranularityType:
        block = self.basic_blocks.get(block_addr)
        if block is None:
            return 'none'
        recs = self.get_annotations_of_type(block, 'trace_recommendation')
        return recs[0].granularity if recs else 'none'  # type: ignore


# ---------------------------------------------------------------------------
# Helpers de deserialización
# ---------------------------------------------------------------------------

def _function_from_dict(data: dict) -> Function:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    return Function(
        address=data['address'], name=data['name'],
        is_plt=data['is_plt'], is_external=data['is_external'],
        entry_block=data['entry_block'],
        blocks=data.get('blocks', []),
        called_from=data.get('called_from', []),
        calls_to=data.get('calls_to', []),
        annotations=anns,
    )


def _block_from_dict(data: dict) -> BasicBlock:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    return BasicBlock(
        address=data['address'], size=data['size'], function=data['function'],
        instructions=data.get('instructions', []),
        successors=data.get('successors', []),
        predecessors=data.get('predecessors', []),
        annotations=anns,
    )


def _instruction_from_dict(data: dict) -> Instruction:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    mems = [MemoryAccess(**m) for m in data.get('memory_accesses', [])]
    return Instruction(
        address=data['address'], mnemonic=data['mnemonic'],
        operands=data['operands'], bytes=data['bytes'], size=data['size'],
        block=data['block'],
        registers_read=data.get('registers_read', []),
        registers_written=data.get('registers_written', []),
        memory_accesses=mems, annotations=anns,
    )


def _edge_from_dict(data: dict) -> Edge:
    anns = [deserialize_annotation(a) for a in data.get('annotations', [])]
    return Edge(
        source=data['source'], target=data['target'],
        type=data['type'], condition=data.get('condition'),
        annotations=anns,
    )


def _clean_none(d):
    if isinstance(d, dict):
        return {k: _clean_none(v) for k, v in d.items() if v is not None}
    if isinstance(d, list):
        return [_clean_none(x) for x in d]
    return d


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()
