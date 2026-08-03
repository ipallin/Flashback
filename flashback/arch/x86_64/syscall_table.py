"""
Tabla de syscalls de Linux x86-64.
Cargada desde flashback/data/syscalls_x86_64.json.
"""

from __future__ import annotations

import json
from pathlib import Path

_DATA_FILE = Path(__file__).parent.parent.parent / 'data' / 'syscalls_x86_64.json'

_TABLE: dict[int, dict] | None = None


def _load() -> dict[int, dict]:
    global _TABLE
    if _TABLE is None:
        with open(_DATA_FILE, encoding='utf-8') as f:
            raw = json.load(f)
        _TABLE = {int(k): v for k, v in raw.items()}
    return _TABLE


def lookup(syscall_number: int) -> dict | None:
    """Devuelve {'name': str, 'args': [str], 'ret': str} o None."""
    return _load().get(syscall_number)


def name_to_number(name: str) -> int | None:
    for num, info in _load().items():
        if info.get('name') == name:
            return num
    return None
