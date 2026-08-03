"""
Parser de la tabla de vectores Cortex-M.

El vector table de Cortex-M está al inicio del espacio de direcciones flash (p.ej. 0x08000000):
  [0]  Valor inicial del MSP (dirección de SRAM)
  [1]  Reset_Handler (con Thumb bit)
  [2]  NMI_Handler
  [3]  HardFault_Handler
  ...
  [16+] IRQs específicas del dispositivo (con Thumb bit)
"""

from __future__ import annotations

import struct

# Vectores fijos del núcleo Cortex-M (índices 0-15)
_CORE_VECTORS = {
    0:  'InitialSP',       # No es código — es el valor de SP
    1:  'Reset_Handler',
    2:  'NMI_Handler',
    3:  'HardFault_Handler',
    4:  'MemManage_Handler',
    5:  'BusFault_Handler',
    6:  'UsageFault_Handler',
    11: 'SVC_Handler',
    12: 'DebugMon_Handler',
    14: 'PendSV_Handler',
    15: 'SysTick_Handler',
}


def parse_vector_table(data: bytes) -> tuple[int | None, dict[int, str]]:
    """
    Parsea la tabla de vectores Cortex-M.

    Devuelve:
      - initial_sp: valor inicial del MSP (word[0]), o None si no es válido
      - handlers: dict {dirección_stripped: nombre_handler}
    """
    if len(data) < 8:
        return None, {}

    initial_sp = struct.unpack_from('<I', data, 0)[0]
    handlers: dict[int, str] = {}

    n_entries = len(data) // 4
    for i in range(1, n_entries):
        if i * 4 + 4 > len(data):
            break
        word = struct.unpack_from('<I', data, i * 4)[0]
        # Entradas vacías o rellenas con 0xFFFFFFFF
        if word == 0 or word == 0xFFFFFFFF:
            continue
        # Thumb bit debe estar set en los handlers de Cortex-M
        if not (word & 1):
            continue
        addr = word & ~1  # strip Thumb bit
        if addr == 0:
            continue
        name = _CORE_VECTORS.get(i, f'IRQ{i - 16}_Handler' if i >= 16 else f'Reserved{i}_Handler')
        handlers[addr] = name

    return initial_sp, handlers


def is_vector_table_section(section, elf=None) -> bool:
    """
    Determina si una sección ELF es la tabla de vectores Cortex-M.

    Criterio primario: nombre de la sección (fiable, sin falsos positivos).
    Criterio de respaldo (solo si se pasa el elf): word[0]=SP en SRAM
    Y word[1] coincide exactamente con elf.entrypoint (Thumb bit incluido).
    """
    if section.name in ('startup', '.isr_vector', '.vectors', '.vector_table',
                        'vectors', 'isr_vector', '.intvec', 'intvec', '.interrupts'):
        return True
    if elf is None:
        return False
    # Heurística estricta: SP inicial en rango SRAM + Reset_Handler = entry point exacto
    try:
        data = bytes(section.content)
        if len(data) < 8:
            return False
        sp_val    = struct.unpack_from('<I', data, 0)[0]
        reset_val = struct.unpack_from('<I', data, 4)[0]
        if 0x20000000 <= sp_val <= 0x60000000 and reset_val == elf.entrypoint:
            return True
    except Exception:
        pass
    return False
