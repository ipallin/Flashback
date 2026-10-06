"""
Descubrimiento de código Thumb-2 por alcanzabilidad (recursive descent).

El barrido lineal del CortexMDisassembler decodifica como instrucciones todo lo
que hay entre dos símbolos de función, incluidos los datos intercalados en el
código: literal pools (constantes cargadas con 'ldr rX, [pc, #imm]') y tablas
de salto (tbb/tbh, 'ldr pc, [rB, rI, lsl #2]'). Esos datos generan bloques y
aristas falsos, y pueden desincronizar la decodificación de la instrucción real
que viene a continuación.

ThumbCodeDiscovery recorre el código desde las entradas de función siguiendo el
flujo de control (como hacen Ghidra o IDA):
  - Solo conserva instrucciones alcanzables.
  - Resuelve tablas de salto y añade sus destinos al recorrido.
  - Marca como datos los literal pools referenciados y las tablas, y no los
    decodifica como código.
  - Si un destino alcanzable no está en el barrido lineal (desincronización tras
    una tabla), redecodifica desde ese punto.

El recorrido se hace en dos pasadas: la primera recoge las referencias a datos;
la segunda recorre de nuevo respetándolas, de modo que el código basura que la
primera pasada pudo decodificar tras una llamada que no retorna (seguida de un
literal pool) no llega al resultado final.
"""

from __future__ import annotations

import bisect
import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from flashback.core.cfg_builder import Flow, RawInstruction
from flashback.arch.arm32.instruction_sem import literal_reference, split_arm_mnemonic

logger = logging.getLogger(__name__)

# Tamaño máximo razonable de una tabla de salto (entradas)
_MAX_TABLE_ENTRIES = 4096
# Instrucciones hacia atrás en las que buscar la comprobación de rango (cmp)
_BOUND_LOOKBACK = 8

_CMP_IMM_RE = re.compile(r'^(\w+),\s*#(0x[0-9a-f]+|\d+)$')


@dataclass
class JumpTable:
    targets: list[int]
    index_register: str
    data_start: int
    data_end: int


@dataclass
class DiscoveryResult:
    instructions: dict[int, RawInstruction]
    jump_tables: dict[int, list[int]] = field(default_factory=dict)
    jump_table_index_regs: dict[int, str] = field(default_factory=dict)
    tables: dict[int, JumpTable] = field(default_factory=dict)
    noreturn: set[int] = field(default_factory=set)
    data_bytes: int = 0
    unresolved_indirect: int = 0


class ThumbCodeDiscovery:
    """Recorre el código Thumb-2 desde las entradas de función conocidas."""

    def __init__(self,
                 sections: list[tuple[int, bytes]],
                 linear: dict[int, RawInstruction],
                 decode_run: Callable[[bytes, int], Iterable[RawInstruction]],
                 classify: Callable[[str, str], Optional[Flow]],
                 resolve_target: Callable[[str, str], Optional[int]],
                 func_starts: set[int]):
        self._sections = sorted(sections)
        self._bases = [b for b, _ in self._sections]
        self._linear = linear
        self._decode_run = decode_run
        self._classify = classify
        self._resolve = resolve_target
        self._func_starts = sorted(func_starts)
        self._redecoded: dict[int, RawInstruction] = {}

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def run(self, entries: set[int], noreturn_seeds: set[int] | None = None) -> DiscoveryResult:
        """
        Recorre el código desde entries. noreturn_seeds: funciones que se sabe
        que no retornan (por nombre); el resto se deduce por análisis.

        Se alternan recorrido y análisis hasta que el conjunto de funciones que
        no retornan se estabiliza: el código basura que la primera pasada
        decodifica tras una llamada que no retorna puede hacer que su llamante
        parezca retornar.
        """
        entries = {e for e in entries if self._in_code(e)}
        noreturn = set(noreturn_seeds or ())
        data: set[int] = set()
        result = self._traverse(entries, data=data, noreturn=noreturn)
        for _ in range(6):
            new_noreturn = self._noreturn_functions(result, noreturn)
            new_data = self._data_refs(result)
            if new_noreturn == noreturn and new_data == data:
                break
            noreturn, data = new_noreturn, new_data
            result = self._traverse(entries, data=data, noreturn=noreturn)
        logger.debug(
            f'Recursive descent: {len(result.instructions)} instrucciones, '
            f'{len(data)} bytes de datos en código, {len(result.jump_tables)} tablas '
            f'de salto resueltas, {len(noreturn)} funciones que no retornan'
        )
        result.noreturn = noreturn
        result.data_bytes = len(data)
        return result

    # ------------------------------------------------------------------
    # Recorrido
    # ------------------------------------------------------------------

    def _traverse(self, entries: set[int], data: set[int],
                  noreturn: set[int] = frozenset()) -> DiscoveryResult:
        reached: dict[int, RawInstruction] = {}
        result = DiscoveryResult(instructions=reached)
        tables: dict[int, JumpTable] = {}
        work = sorted(entries, reverse=True)

        while work:
            addr = work.pop()
            while addr not in reached:
                ri = self._insn_at(addr)
                if ri is None or any(b in data for b in range(addr, addr + ri.size)):
                    break
                reached[addr] = ri
                flow = self._classify(ri.mnemonic, ri.operands)
                nxt = addr + ri.size

                if flow is None or flow.kind in ('call', 'syscall'):
                    if flow is not None and flow.kind == 'call':
                        target = self._resolve(ri.mnemonic, ri.operands)
                        if target is not None and self._in_code(target):
                            work.append(target)
                        if target in noreturn and not flow.conditional:
                            break           # la función llamada no retorna
                    addr = nxt
                    continue

                if flow.kind == 'branch':
                    target = self._resolve(ri.mnemonic, ri.operands)
                    if target is not None and self._in_code(target):
                        work.append(target)
                elif flow.kind == 'indirect_jump':
                    table = self._resolve_table(ri, reached)
                    if table is not None:
                        tables[addr] = table
                        work.extend(table.targets)
                    else:
                        result.unresolved_indirect += 1

                if not flow.conditional:
                    break
                addr = nxt

        # Una tabla solo es válida si ninguna instrucción alcanzada la pisa
        for addr, table in tables.items():
            if any(a in reached for a in range(table.data_start, table.data_end)):
                result.unresolved_indirect += 1
                continue
            result.tables[addr] = table
            result.jump_tables[addr] = table.targets
            result.jump_table_index_regs[addr] = table.index_register
        return result

    # ------------------------------------------------------------------
    # Funciones que no retornan
    # ------------------------------------------------------------------

    def _noreturn_functions(self, result: DiscoveryResult, known: set[int]) -> set[int]:
        """
        Punto fijo: una función no retorna si ningún camino desde su entrada llega
        a un retorno, a un salto indirecto sin resolver o a un tail call / caída
        en una función que sí retorna. Las llamadas a funciones que no retornan
        cortan el camino.
        """
        noreturn = set(known)
        starts = set(self._func_starts)
        candidates = [f for f in self._func_starts if f in result.instructions]
        changed = True
        while changed:
            changed = False
            for f in candidates:
                if f not in noreturn and not self._may_return(f, result, noreturn, starts):
                    noreturn.add(f)
                    changed = True
        return noreturn

    def _may_return(self, entry: int, result: DiscoveryResult,
                    noreturn: set[int], starts: set[int]) -> bool:
        insns = result.instructions
        seen: set[int] = set()
        work = [entry]

        def leaves_to(target: int) -> bool:
            """¿Retorna el control al salir hacia otra función?"""
            return target not in noreturn

        while work:
            addr = work.pop()
            while addr not in seen:
                if addr != entry and addr in starts:
                    if leaves_to(addr):         # cae en la función siguiente
                        return True
                    break
                seen.add(addr)
                ri = insns.get(addr)
                if ri is None:
                    return True                 # código desconocido: conservador
                flow = self._classify(ri.mnemonic, ri.operands)
                nxt = addr + ri.size
                if flow is None or flow.kind == 'syscall':
                    addr = nxt
                    continue
                if flow.kind == 'call':
                    target = self._resolve(ri.mnemonic, ri.operands)
                    if target in noreturn and not flow.conditional:
                        break
                    addr = nxt
                    continue
                if flow.kind == 'return':
                    return True
                if flow.kind == 'indirect_jump':
                    table = result.tables.get(addr)
                    if table is None:
                        return True
                    work.extend(table.targets)
                elif flow.kind == 'branch':
                    target = self._resolve(ri.mnemonic, ri.operands)
                    if target is None:
                        return True
                    if target != entry and target in starts:
                        if leaves_to(target):   # tail call
                            return True
                    else:
                        work.append(target)
                if not flow.conditional:
                    break
                addr = nxt
        return False

    def _insn_at(self, addr: int) -> Optional[RawInstruction]:
        ri = self._linear.get(addr) or self._redecoded.get(addr)
        if ri is not None:
            return ri
        # Desincronización: redecodificar desde aquí hasta volver a coincidir
        # con el barrido lineal (o hasta la siguiente función).
        sec = self._section_of(addr)
        if sec is None:
            return None
        base, data = sec
        i = bisect.bisect_right(self._func_starts, addr)
        end = self._func_starts[i] if i < len(self._func_starts) else base + len(data)
        end = min(end, base + len(data))
        for ri in self._decode_run(data[addr - base:end - base], addr):
            if ri.address != addr and ri.address in self._linear:
                break
            self._redecoded.setdefault(ri.address, ri)
        return self._redecoded.get(addr)

    # ------------------------------------------------------------------
    # Datos en código
    # ------------------------------------------------------------------

    def _data_refs(self, result: DiscoveryResult) -> set[int]:
        """Bytes de literal pools y tablas de salto referenciados por código alcanzado."""
        data: set[int] = set()
        for ri in result.instructions.values():
            ref = literal_reference(ri.mnemonic, ri.operands, ri.address)
            if ref is not None:
                start, size = ref
                data.update(range(start, start + size))
        for t in result.tables.values():
            data.update(range(t.data_start, t.data_end))
        # Las entradas de función son código por definición
        data.difference_update(self._func_starts)
        return data

    # ------------------------------------------------------------------
    # Tablas de salto
    # ------------------------------------------------------------------

    def _resolve_table(self, ri: RawInstruction,
                       reached: dict[int, RawInstruction]) -> Optional[JumpTable]:
        base, _cond = split_arm_mnemonic(ri.mnemonic)
        ops = ri.operands.replace(' ', '').lower()
        if base in ('tbb', 'tbh'):
            # tbb [pc, rI]  /  tbh [pc, rI, lsl #1]
            m = re.match(r'^\[pc,(\w+)(?:,lsl#1)?\]$', ops)
            if not m:
                return None
            idx = m.group(1)
            n = self._table_bound(ri, idx, reached)
            if n is None:
                return None
            esize = 1 if base == 'tbb' else 2
            start = ri.address + 4
            raw = self._read(start, n * esize)
            if raw is None:
                return None
            entries = [int.from_bytes(raw[i:i + esize], 'little')
                       for i in range(0, len(raw), esize)]
            targets = [start + 2 * e for e in entries]
            end = start + n * esize
            end += end & 1          # tablas tbb impares llevan un byte de relleno
        elif base == 'ldr':
            # adr rB, #imm ; ldr pc, [rB, rI, lsl #2]  — tabla de direcciones absolutas
            m = re.match(r'^pc,\[(\w+),(\w+),lsl#2\]$', ops)
            if not m:
                return None
            breg, idx = m.groups()
            table_addr = self._adr_value(ri, breg, reached)
            if table_addr is None:
                return None
            n = self._table_bound(ri, idx, reached)
            if n is None:
                return None
            raw = self._read(table_addr, n * 4)
            if raw is None:
                return None
            words = [int.from_bytes(raw[i:i + 4], 'little') for i in range(0, len(raw), 4)]
            if any(not (w & 1) for w in words):   # destinos Thumb llevan el bit 0
                return None
            targets = [w & ~1 for w in words]
            start, end = table_addr, table_addr + n * 4
        else:
            return None

        if not targets or not all(self._same_function(ri.address, t) for t in targets):
            return None
        return JumpTable(targets=targets, index_register=idx,
                         data_start=start, data_end=end)

    def _previous(self, ri: RawInstruction,
                  reached: dict[int, RawInstruction]) -> list[RawInstruction]:
        """Instrucciones inmediatamente anteriores (más cercana primero)."""
        out: list[RawInstruction] = []
        addr = ri.address
        for _ in range(_BOUND_LOOKBACK):
            prev = None
            for size in (2, 4):
                cand = reached.get(addr - size)
                if cand is not None and cand.size == size:
                    prev = cand
                    break
            if prev is None:
                break
            out.append(prev)
            addr = prev.address
        return out

    def _table_bound(self, ri: RawInstruction, idx: str,
                     reached: dict[int, RawInstruction]) -> Optional[int]:
        """Número de entradas a partir del 'cmp rI, #K' que protege el salto."""
        for prev in self._previous(ri, reached):
            base, _ = split_arm_mnemonic(prev.mnemonic)
            if base == 'cmp':
                m = _CMP_IMM_RE.match(prev.operands.strip().lower())
                if m and m.group(1) == idx:
                    n = int(m.group(2), 0) + 1
                    return n if 0 < n <= _MAX_TABLE_ENTRIES else None
        return None

    def _adr_value(self, ri: RawInstruction, reg: str,
                   reached: dict[int, RawInstruction]) -> Optional[int]:
        for prev in self._previous(ri, reached):
            if prev.mnemonic.lower() in ('adr', 'adr.w'):
                parts = [p.strip().lower() for p in prev.operands.split(',')]
                if len(parts) == 2 and parts[0] == reg:
                    imm = int(parts[1].lstrip('#'), 0)
                    return ((prev.address + 4) & ~3) + imm
        return None

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------

    def _section_of(self, addr: int) -> Optional[tuple[int, bytes]]:
        i = bisect.bisect_right(self._bases, addr) - 1
        if i < 0:
            return None
        base, data = self._sections[i]
        return (base, data) if addr < base + len(data) else None

    def _in_code(self, addr: int) -> bool:
        return not (addr & 1) and self._section_of(addr) is not None

    def _read(self, addr: int, size: int) -> Optional[bytes]:
        sec = self._section_of(addr)
        if sec is None:
            return None
        base, data = sec
        if addr + size > base + len(data):
            return None
        return data[addr - base: addr - base + size]

    def _same_function(self, addr: int, target: int) -> bool:
        if not self._in_code(target):
            return False
        i = bisect.bisect_right(self._func_starts, addr) - 1
        lo = self._func_starts[i] if i >= 0 else 0
        hi = self._func_starts[i + 1] if i + 1 < len(self._func_starts) else float('inf')
        return lo <= target < hi
