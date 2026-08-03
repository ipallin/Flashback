#!/usr/bin/env python3
"""
evaluate.py — Script de evaluación experimental de Flashback.

Para cada binario del corpus:
  1. Captura la salida del binario original.
  2. Ejecuta Flashback para generar el código C reconstruido.
  3. Compila el código C con gcc.
  4. Ejecuta el binario reconstruido y compara la salida.
  5. Registra métricas y genera un informe en Markdown.

Uso:
    python tests/corpus/evaluate.py [--corpus DIR] [--out REPORT.md]
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
log = logging.getLogger('evaluate')

REPO_ROOT = Path(__file__).parent.parent.parent
FLASHBACK  = REPO_ROOT / 'flashback.py'
CORPUS_DIR = Path(__file__).parent
BIN_DIR    = CORPUS_DIR / 'binaries'
BUILD_DIR  = CORPUS_DIR / 'build'
GCC        = 'gcc'
TIMEOUT    = 10   # segundos por ejecución


# ---------------------------------------------------------------------------
# Descripción del corpus
# ---------------------------------------------------------------------------

CORPUS = [
    {
        'id':    '01_hello_nopie',
        'desc':  'Hello World — función auxiliar, printf, no-PIE',
        'tags':  ['basic', 'external_call'],
        'stdin': '',
    },
    {
        'id':    '02_switch',
        'desc':  'Switch con 5 casos → tabla de salto (Fase 1)',
        'tags':  ['jump_table', 'external_call'],
        'stdin': '',
    },
    {
        'id':    '03_recursive',
        'desc':  'Fibonacci recursivo y función is_even mutuamente recursiva',
        'tags':  ['recursion', 'cond_branch'],
        'stdin': '',
    },
    {
        'id':    '04_strings',
        'desc':  'Operaciones de cadena: snprintf, strlen, strcat, strcmp',
        'tags':  ['external_call', 'rodata'],
        'stdin': '',
    },
    {
        'id':    '05_loops',
        'desc':  'Bucles anidados: for/while/do-while, loop headers, Collatz',
        'tags':  ['loop', 'cond_branch'],
        'stdin': '',
    },
    {
        'id':    '06_syscalls',
        'desc':  'Syscalls directas via inline asm: write(1) y exit(0)',
        'tags':  ['syscall'],
        'stdin': '',
    },
    {
        'id':    '07_funcptr',
        'desc':  'Punteros a función en dispatch table (Fase 2)',
        'tags':  ['indirect_call', 'function_pointer'],
        'stdin': '',
    },
    {
        'id':    '08_memory',
        'desc':  'Gestión de heap: malloc, realloc, free',
        'tags':  ['heap', 'external_call'],
        'stdin': '',
    },
]


# ---------------------------------------------------------------------------
# Estructuras de resultado
# ---------------------------------------------------------------------------

@dataclass
class BinaryResult:
    id: str
    desc: str
    tags: list[str]

    # Flashback
    flashback_ok:    bool  = False
    flashback_time:  float = 0.0
    flashback_lines: int   = 0
    flashback_error: str   = ''

    # CFG metrics (from --export-cfg)
    n_functions: int = 0
    n_blocks:    int = 0
    n_insns:     int = 0
    n_edges:     int = 0
    n_jt_sites:  int = 0   # jump_table_site blocks
    n_ind_calls: int = 0   # resolved_indirect annotations

    # Compilación
    compile_ok:    bool  = False
    compile_time:  float = 0.0
    compile_error: str   = ''

    # Equivalencia funcional
    original_out:      str  = ''
    original_exit:     int  = 0
    rebuilt_out:       str  = ''
    rebuilt_exit:      int  = 0
    output_equivalent: bool = False
    equiv_note:        str  = ''

    @property
    def status(self) -> str:
        if not self.flashback_ok:
            return 'FLASHBACK_ERROR'
        if not self.compile_ok:
            return 'COMPILE_ERROR'
        if self.output_equivalent:
            return 'PASS'
        return 'OUTPUT_MISMATCH'

    @property
    def status_emoji(self) -> str:
        return {'PASS': '✓', 'FLASHBACK_ERROR': '✗', 'COMPILE_ERROR': '✗',
                'OUTPUT_MISMATCH': '~'}[self.status]


# ---------------------------------------------------------------------------
# Ejecución de subprocesos con timeout
# ---------------------------------------------------------------------------

def _run(cmd: list[str], stdin: str = '', timeout: int = TIMEOUT,
         cwd: Path | None = None) -> tuple[str, str, int, float]:
    """Ejecuta un comando y devuelve (stdout, stderr, returncode, elapsed)."""
    t0 = time.perf_counter()
    try:
        r = subprocess.run(
            cmd, input=stdin.encode(), capture_output=True,
            timeout=timeout, cwd=cwd,
        )
        elapsed = time.perf_counter() - t0
        return r.stdout.decode(errors='replace'), r.stderr.decode(errors='replace'), r.returncode, elapsed
    except subprocess.TimeoutExpired:
        return '', f'TIMEOUT after {timeout}s', -1, timeout
    except Exception as e:
        return '', str(e), -2, time.perf_counter() - t0


# ---------------------------------------------------------------------------
# Métricas del CFG desde el JSON exportado
# ---------------------------------------------------------------------------

def _extract_cfg_metrics(cfg_path: Path, result: BinaryResult) -> None:
    if not cfg_path.exists():
        return
    try:
        with open(cfg_path, encoding='utf-8') as f:
            cfg = json.load(f)
        result.n_functions = len(cfg.get('functions', {}))
        result.n_blocks    = len(cfg.get('basic_blocks', {}))
        result.n_insns     = len(cfg.get('instructions', {}))
        result.n_edges     = len(cfg.get('edges', []))
        # Contar bloques con jump_table y llamadas indirectas resueltas
        jt = 0
        for b in cfg.get('basic_blocks', {}).values():
            for ann in b.get('annotations', []):
                if ann.get('type') == 'functional_class' \
                        and ann.get('category') == 'jump_table_site':
                    jt += 1
        result.n_jt_sites = jt
        ind = sum(
            1 for i in cfg.get('instructions', {}).values()
            for ann in i.get('annotations', [])
            if ann.get('type') == 'resolved_indirect'
        )
        result.n_ind_calls = ind
    except Exception as e:
        log.warning(f'Error leyendo CFG JSON: {e}')


# ---------------------------------------------------------------------------
# Evaluación de un binario
# ---------------------------------------------------------------------------

def evaluate_one(entry: dict, python: str) -> BinaryResult:
    bid   = entry['id']
    elf   = BIN_DIR / f'{bid}.elf'
    c_out = BUILD_DIR / f'{bid}.c'
    exe   = BUILD_DIR / f'{bid}'
    cfg   = BUILD_DIR / f'{bid}.cfg.json'

    result = BinaryResult(id=bid, desc=entry['desc'], tags=entry['tags'])
    stdin  = entry.get('stdin', '')

    if not elf.exists():
        result.flashback_error = f'Binario no encontrado: {elf}'
        return result

    # 1. Capturar salida del original
    orig_out, _, orig_exit, _ = _run([str(elf)], stdin=stdin)
    result.original_out  = orig_out
    result.original_exit = orig_exit

    # 2. Ejecutar Flashback
    log.info(f'[{bid}] Ejecutando Flashback...')
    fb_cmd = [python, str(FLASHBACK), str(elf), '-o', str(c_out),
              '--export-cfg', str(cfg)]
    _, fb_err, fb_ret, fb_elapsed = _run(fb_cmd, timeout=60)
    result.flashback_time = fb_elapsed
    if fb_ret != 0 or not c_out.exists():
        result.flashback_ok    = False
        result.flashback_error = fb_err.strip().splitlines()[-1] if fb_err.strip() else 'unknown'
        return result

    result.flashback_ok    = True
    result.flashback_lines = sum(1 for _ in open(c_out))
    _extract_cfg_metrics(cfg, result)

    # 3. Compilar el C generado
    log.info(f'[{bid}] Compilando C generado ({result.flashback_lines} líneas)...')
    cc_out, cc_err, cc_ret, cc_elapsed = _run(
        [GCC, '-O0', str(c_out), '-o', str(exe), '-lm'],
    )
    result.compile_time = cc_elapsed
    if cc_ret != 0:
        result.compile_ok    = False
        result.compile_error = cc_err.strip().splitlines()[-1] if cc_err.strip() else 'unknown'
        return result
    result.compile_ok = True

    # 4. Ejecutar el binario reconstruido y comparar salida
    log.info(f'[{bid}] Ejecutando binario reconstruido...')
    reb_out, _, reb_exit, _ = _run([str(exe)], stdin=stdin)
    result.rebuilt_out  = reb_out
    result.rebuilt_exit = reb_exit

    if orig_out == reb_out and orig_exit == reb_exit:
        result.output_equivalent = True
        result.equiv_note        = 'stdout y exit code idénticos'
    elif orig_out == reb_out:
        result.output_equivalent = False
        result.equiv_note        = f'stdout idéntico pero exit code difiere ({orig_exit}≠{reb_exit})'
    else:
        result.output_equivalent = False
        # Número de líneas coincidentes
        orig_lines = orig_out.splitlines()
        reb_lines  = reb_out.splitlines()
        match = sum(a == b for a, b in zip(orig_lines, reb_lines))
        result.equiv_note = (
            f'{match}/{len(orig_lines)} líneas coinciden; '
            f'exit {orig_exit}≠{reb_exit}' if orig_exit != reb_exit else
            f'{match}/{len(orig_lines)} líneas coinciden'
        )

    return result


# ---------------------------------------------------------------------------
# Informe Markdown
# ---------------------------------------------------------------------------

def _md_report(results: list[BinaryResult]) -> str:
    total    = len(results)
    passed   = sum(1 for r in results if r.status == 'PASS')
    compiled = sum(1 for r in results if r.compile_ok)
    fb_ok    = sum(1 for r in results if r.flashback_ok)

    lines: list[str] = []
    lines.append('# Evaluación experimental de Flashback\n')
    lines.append('## Resumen ejecutivo\n')
    lines.append(f'| Métrica | Resultado |')
    lines.append(f'|---|---|')
    lines.append(f'| Binarios del corpus | {total} |')
    lines.append(f'| Traducción exitosa (Flashback) | {fb_ok}/{total} ({100*fb_ok//total}%) |')
    lines.append(f'| Compilación del C generado | {compiled}/{total} ({100*compiled//total}%) |')
    lines.append(f'| Equivalencia funcional (PASS) | {passed}/{total} ({100*passed//total}%) |')
    lines.append('')

    lines.append('## Resultados por binario\n')
    lines.append('| ID | Descripción | Tags | Flashback | Compila | Equiv. | Tiempo FB | Líneas C | Bloques | Instrucciones |')
    lines.append('|---|---|---|---|---|---|---|---|---|---|')
    for r in results:
        tags   = ', '.join(r.tags)
        fb     = '✓' if r.flashback_ok else '✗'
        cc     = '✓' if r.compile_ok   else ('—' if not r.flashback_ok else '✗')
        equiv  = r.status_emoji
        t      = f'{r.flashback_time:.1f}s'
        lns    = str(r.flashback_lines) if r.flashback_ok else '—'
        blks   = str(r.n_blocks)        if r.flashback_ok else '—'
        insns  = str(r.n_insns)         if r.flashback_ok else '—'
        lines.append(f'| `{r.id}` | {r.desc} | {tags} | {fb} | {cc} | {equiv} | {t} | {lns} | {blks} | {insns} |')

    lines.append('')
    lines.append('## Detalle por caso\n')
    for r in results:
        lines.append(f'### `{r.id}` — {r.desc}\n')
        lines.append(f'- **Estado:** `{r.status}`')
        lines.append(f'- **Tags:** {", ".join(r.tags)}')
        if r.flashback_ok:
            lines.append(f'- **Tiempo Flashback:** {r.flashback_time:.2f} s')
            lines.append(f'- **Código C generado:** {r.flashback_lines} líneas')
            lines.append(f'- **CFG:** {r.n_functions} funciones · {r.n_blocks} bloques · '
                         f'{r.n_insns} instrucciones · {r.n_edges} aristas')
            if r.n_jt_sites > 0:
                lines.append(f'- **Tablas de salto resueltas (Fase 1):** {r.n_jt_sites} sitios')
            if r.n_ind_calls > 0:
                lines.append(f'- **Llamadas indirectas resueltas (Fase 2):** {r.n_ind_calls}')
        else:
            lines.append(f'- **Error Flashback:** `{r.flashback_error}`')
        if r.flashback_ok:
            if r.compile_ok:
                lines.append(f'- **Compilación gcc:** ✓ ({r.compile_time:.2f} s)')
                lines.append(f'- **Equivalencia funcional:** {r.status_emoji} {r.equiv_note}')
                if r.output_equivalent:
                    first_line = r.original_out.splitlines()[0] if r.original_out else ''
                    lines.append(f'  - Salida original (primera línea): `{first_line}`')
            else:
                lines.append(f'- **Error compilación:** `{r.compile_error}`')
        lines.append('')

    lines.append('## Análisis por categoría de feature\n')
    feature_map = {
        'basic':           'Caso base',
        'external_call':   'Llamadas externas (PLT)',
        'jump_table':      'Tablas de salto — Fase 1',
        'indirect_call':   'Llamadas indirectas — Fase 2',
        'function_pointer': 'Punteros a función',
        'recursion':       'Recursión',
        'loop':            'Bucles (loop headers)',
        'cond_branch':     'Saltos condicionales',
        'syscall':         'Syscalls directas',
        'heap':            'Gestión de heap',
        'rodata':          'Acceso a .rodata',
    }
    for tag, label in feature_map.items():
        tagged = [r for r in results if tag in r.tags]
        if not tagged:
            continue
        ok = sum(1 for r in tagged if r.status == 'PASS')
        lines.append(f'- **{label}:** {ok}/{len(tagged)} PASS')

    lines.append('')
    lines.append('## Limitaciones observadas\n')
    failed = [r for r in results if r.status != 'PASS']
    if not failed:
        lines.append('Todos los casos del corpus superaron la evaluación.')
    else:
        for r in failed:
            lines.append(f'- `{r.id}` ({r.desc}): {r.status} — {r.equiv_note or r.compile_error or r.flashback_error}')

    lines.append('')
    lines.append('---')
    lines.append('*Generado automáticamente por `tests/corpus/evaluate.py`*')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description='Evaluación experimental de Flashback')
    ap.add_argument('--corpus', default=str(CORPUS_DIR / 'binaries'),
                    help='Directorio con los ELF del corpus')
    ap.add_argument('--out', default=str(REPO_ROOT / 'docs' / 'evaluation.md'),
                    help='Ruta del informe Markdown de salida')
    ap.add_argument('--json', default='',
                    help='Ruta del informe JSON de salida (opcional)')
    args = ap.parse_args()

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    python = sys.executable

    results: list[BinaryResult] = []
    for entry in CORPUS:
        elf = Path(args.corpus) / f'{entry["id"]}.elf'
        if not elf.exists():
            log.warning(f'Binario no encontrado, saltando: {elf}')
            continue
        r = evaluate_one(entry, python)
        results.append(r)
        icon = {'PASS': '✓', 'COMPILE_ERROR': '✗ compilación', 'FLASHBACK_ERROR': '✗ flashback',
                'OUTPUT_MISMATCH': '~ mismatch'}.get(r.status, r.status)
        log.info(f'[{r.id}] {icon} — {r.n_insns} insns, {r.flashback_lines} líneas C')

    # Informe Markdown
    report = _md_report(results)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(report)
    log.info(f'Informe Markdown: {out_path}')

    # Informe JSON opcional
    if args.json:
        import dataclasses
        json_path = Path(args.json)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump([dataclasses.asdict(r) for r in results], f, indent=2)
        log.info(f'Informe JSON: {json_path}')

    # Resumen por consola
    passed = sum(1 for r in results if r.status == 'PASS')
    print(f'\n{"=" * 50}')
    print(f'RESULTADO: {passed}/{len(results)} PASS')
    print(f'{"=" * 50}\n')

    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
