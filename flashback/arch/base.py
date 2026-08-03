"""
Interfaces abstractas de arquitectura.

Cada ISA soportada implementa estas clases en su propio subpaquete (arch/x86_64/, etc.).
La lógica de core/ solo depende de estas interfaces, no de implementaciones concretas.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flashback.core.models import EnrichedCFG
from flashback.core.cfg_builder import BinaryMeta, RawInstruction


class Disassembler(ABC):
    """
    Parsea un binario y produce instrucciones crudas + metadatos.
    La construcción del CFG la hace CFGBuilder con esos datos.
    """

    @abstractmethod
    def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
        """
        Carga un binario y devuelve:
          - raw_insns: dict[addr_int → RawInstruction]
          - meta: metadatos del binario (funciones, PLT, entry point…)
        """

    def disassemble(self, binary_path: str) -> EnrichedCFG:
        """Atajo: load() + CFGBuilder.build()."""
        from flashback.core.cfg_builder import CFGBuilder
        raw_insns, meta = self.load(binary_path)
        return CFGBuilder(
            tool_version=self.version,
            capstone_version=getattr(self, 'capstone_version', ''),
            lief_version=getattr(self, 'lief_version', ''),
        ).build(raw_insns, meta)

    @property
    def version(self) -> str:
        return '0.1.0'


class Enricher(ABC):
    """Añade anotaciones semánticas a un CFG inicial."""

    @abstractmethod
    def enrich(self, cfg: EnrichedCFG, granularity: str = 'selective') -> EnrichedCFG:
        ...


class RegisterMap(ABC):
    """Mapea nombres de registros a expresiones C."""

    @abstractmethod
    def to_c(self, reg: str) -> str | None:
        """Convierte un nombre de registro a la expresión C correspondiente."""
