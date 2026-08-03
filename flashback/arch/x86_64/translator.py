"""
Translator x86-64: genera código C portable desde CFG x86-64 enriquecido.

La lógica de traducción vive en core/translator.py (Translator), que implementa
la ISA x86-64 completa. Esta subclase la nombra explícitamente dentro del módulo
de arquitectura, manteniendo la simetría con X86Translator, Arm64Translator, etc.
"""

from __future__ import annotations

from flashback.core.translator import Translator


class X86_64Translator(Translator):
    """Translator para binarios x86-64 Linux (System V AMD64 ABI)."""
