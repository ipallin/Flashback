# Changelog

Registro de cambios por versión. Formato basado en [Keep a Changelog](https://keepachangelog.com/es/).

---

## [3.0.1] — 2026-07-02

### Corregido
- **Volcado de traza robusto ante terminaciones por `exit` (M4).** El volcado de `flashback_trace.bin` estaba únicamente al final de `main()`, por lo que un programa que terminara mediante una syscall cruda de la familia `exit` (`exit`=60, `exit_group`=231) —como `06_syscalls`— finalizaba el proceso sin retornar a `main()` y perdía la traza. Ahora el runtime: (a) registra el volcado con `atexit()`, cubriendo el retorno normal y las salidas por `exit()` de la libc; (b) encamina las syscalls por una envoltura `__do_syscall()` que vuelca la traza antes de ejecutar una llamada de la familia `exit`; y (c) hace el volcado idempotente para no duplicar la escritura. Con esto, M4 pasa de 7/8 a 8/8.
- **`setup.cfg` corrupto.** El fichero contenía por error una copia de `flashback/arch/arm32/enricher.py`, lo que rompía `pip install -e .`. Se sustituye por la configuración de `flake8`/`flake8-bugbear` (RD04), que antes no tenía fichero propio.

### Añadido
- **Pruebas PI07 de traza dinámica (M4).** Tres pruebas en `tests/test_integration.py` que compilan, ejecutan y verifican la creación efectiva de `flashback_trace.bin`, incluyendo el caso de terminación por syscall `exit`. Total de la batería: 128 pruebas.

---

## [3.0.0] — 2026-06-16

### Añadido
- **Fase 1 — Resolución de tablas de salto (x86-64):** `X86_64Disassembler._find_jump_tables()` detecta tres patrones de jump table generados por GCC/Clang (indexado absoluto, RIP+movsxd PIE, base+índice). `CFGBuilder` propaga los destinos como sucesores reales del bloque y añade `JumpTableAnnotation`. El `Translator` emite un `switch()` C con un `case` por destino.
- **Fase 2 — Backward slice para llamadas indirectas (x86-64):** `X86_64Enricher._resolve_indirect_calls()` resuelve `call REG` cuando el registro fue cargado con `mov REG, IMM` dentro del mismo bloque básico. Añade `ResolvedIndirectAnnotation`; el `Translator` emite la llamada correcta en lugar de un comentario.
- **Corpus de evaluación experimental:** 8 binarios en `tests/corpus/src/` cubriendo llamadas PLT, syscalls directas, tablas de salto, recursión, bucles, punteros a función y gestión de heap. Script `tests/corpus/evaluate.py` mide traducción, compilación y equivalencia funcional. Resultados: 8/8 traducción, 8/8 compilación, 6/8 equivalencia funcional.
- **`docs/evaluation.md`:** informe de evaluación experimental con análisis de causas raíz de los casos fallidos.
- **Nuevas anotaciones:** `JumpTableAnnotation` y `ResolvedIndirectAnnotation` con registro en `ANNOTATION_REGISTRY` y round-trip JSON.
- **Nuevas categorías funcionales:** `jump_table_site` e `indirect_call_site` en `FunctionalClassAnnotation`.
- **`X86_64Translator`:** clase explícita en `flashback/arch/x86_64/translator.py` que hereda de `Translator` (simetría arquitectural con el resto de ISAs).
- **88 prototipos libc** en `libc_prototypes.json` (+18 nuevos: snprintf, sprintf, strdup, qsort, bsearch, etc.).
- **35 funciones** adicionales en `_LIBC_CALL_MAP` del translator (snprintf, strcat, memmove, qsort, strerror, etc.).
- **18 tests nuevos** en `tests/test_indirect_jumps.py` (PJ01–PJ06, PB01–PB05, PM01–PM02).
- **`make corpus` y `make eval`** para reproducir la evaluación experimental.

### Corregido
- Detección de PLT para binarios con `.plt.sec` (CET/endbr64): el método `_find_plt_symbols` ahora desensambla los stubs de `.plt.sec` en lugar de asumir offsets fijos, resolviendo el bug por el que todas las llamadas externas quedaban sin anotar en gcc moderno.
- Extracción de `.data` y `.bss`: el `BinaryInfo` ahora incluye `data_va`, `data_hex`, `bss_va`, `bss_size`; el código C generado inicializa y accede a las secciones de datos del binario original.
- Instrucciones ALU con operando de memoria como destino (`add [mem], reg`): el translator generaba código incorrecto; ahora emite `SIM_READ`/`SIM_WRITE` correctos.
- Doble emisión del salto de salida de bloque: la instrucción de salto terminal ya no se traducía dos veces (como instrucción y como salida de bloque).
- Ruta del schema JSON en `Exporter`: apuntaba a `docs/02_cfg_schema.json` (inexistente); corregido a `docs/cfg_schema.json`.
- Llamadas externas con retorno `void` (ej. `__stack_chk_fail`, `abort`): se declaran explícitamente para evitar casteo de `void` a `uintptr_t`.

### Eliminado
- `notebook_semana1.ipynb`: notebook de exploración inicial, reemplazado por los tests de integración.
- `data/binarios/`: directorio de artefactos de desarrollo eliminado del control de versiones.

---

## [2.1.0] — 2026-06-12

### Añadido
- Arquitectura ARM64 (AArch64) completa: disassembler, enricher, translator con AAPCS64.
- Tests de cobertura: `test_cfg_builder.py` (23 tests), `test_exporter.py` (22 tests).
- Binario `tests/binaries/hello_world.elf` para tests de integración.

### Corregido
- Múltiples warnings de flake8 en arm32, arm64, cortexm, x86 (importaciones no usadas, strings f vacíos).

---

## [2.0.0] — 2026-04-27

### Añadido
- Refactorización completa: arquitectura pipeline Disassembler → CFGBuilder → Enricher → Translator.
- Soporte ARM32 (ARMv7 Linux) y Cortex-M (Thumb-2 bare-metal).
- Sistema de anotaciones extensible con ANNOTATION_REGISTRY.
- Trazabilidad bidireccional: comentarios estáticos `/* 0xADDR */` y runtime `__trace()`.
- JSON Schema para EnrichedCFG (`docs/cfg_schema.json`).
- CLI completa con detección automática de arquitectura.

---

## [1.0.0] — 2026-02-15

### Añadido
- Versión funcional inicial: soporte x86-64 y x86 (i386).
- Pipeline básico: lief + capstone → CFG → C portable.
- Tablas de syscalls Linux para x86-64, x86, ARM64 y ARM32.
