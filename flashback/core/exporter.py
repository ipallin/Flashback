"""
Exporter: serialización y deserialización del CFG enriquecido a/desde disco.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from flashback.core.models import EnrichedCFG, CFGValidationError

logger = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parent.parent.parent / 'docs' / 'cfg_schema.json'


class ExporterError(Exception):
    pass


class Exporter:
    def __init__(self, schema_path: str | None = None):
        self._schema = None
        self._schema_path = Path(schema_path) if schema_path else _SCHEMA_PATH
        self._load_schema()

    def _load_schema(self) -> None:
        if not self._schema_path.exists():
            logger.debug(f'JSON Schema no encontrado en {self._schema_path}. Validación sintáctica desactivada.')
            return
        with open(self._schema_path, encoding='utf-8') as f:
            self._schema = json.load(f)

    def save(self, cfg: EnrichedCFG, path: str, indent: int = 2) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        cfg.save(str(output), indent=indent)
        logger.info(f'CFG guardado: {output} ({output.stat().st_size} bytes)')
        return output

    def load(self, path: str, validate: bool = True) -> EnrichedCFG:
        input_path = Path(path)
        if not input_path.exists():
            raise ExporterError(f'Fichero no encontrado: {input_path}')

        with open(input_path, encoding='utf-8') as f:
            data = json.load(f)

        if validate and self._schema:
            self._validate_schema(data, input_path)

        cfg = EnrichedCFG.from_dict(data)

        if validate:
            try:
                cfg.validate()
            except CFGValidationError as e:
                raise ExporterError(f'CFG inválido en {input_path}: {e}') from e

        logger.info(f'CFG cargado: {len(cfg.functions)} funciones, {len(cfg.basic_blocks)} bloques')
        return cfg

    def _validate_schema(self, data: dict, path: Path) -> None:
        try:
            import jsonschema
            jsonschema.validate(data, self._schema)
        except ImportError:
            logger.debug('jsonschema no disponible, saltando validación sintáctica')
        except Exception as e:
            raise ExporterError(f'{path} no cumple el JSON Schema: {e}') from e
