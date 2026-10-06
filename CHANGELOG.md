# Changelog

Registro de cambios por versión. Formato basado en [Keep a Changelog](https://keepachangelog.com/es/).

---

## [1.1.0] - 2026-10-06

### Corregido
- **Retornos Thumb/ARM no reconocidos.** `pop {…, pc}`, `ldm sp!, {…, pc}`, `ldr pc, [sp], #4` y `mov pc, lr` no terminaban el bloque: el código siguiente se fusionaba con el retorno y se generaban fall-through falsos hacia la función siguiente. También los retornos condicionales de bloques IT (`pophi`, `bxeq lr`).
- **`bx rN` clasificado como retorno.** Solo `bx lr` es retorno; `bx rN` es un salto indirecto.
- **Saltos Thumb-2 anchos ignorados.** `b.w`, `beq.w`, `bne.w`… (≈4.400 en ArduCopter) no se reconocían como saltos.
- **Destino de `cbz`/`cbnz` nunca resuelto.** El resolver recibía `r3, #0x…` completo; ahora usa el último operando.
- **`wfi`/`wfe` tratados como halt.** La ejecución continúa tras la interrupción.
- **Traductor ARM:** las llamadas `bl`/`blx` y `bx lr` no se emitían (se trataban como saltos de salida de bloque); `cbz`/`cbnz` generaban `goto label_…` a etiquetas inexistentes; los tail calls (`b f`) generaban `goto` entre funciones C; faltaba el alias `sb` (r9). El C generado para ArduCopter compila ahora con `gcc -fsyntax-only` sin errores.
- **`docs/cfg_schema.json` desactualizado:** admite las arquitecturas ARM, las anotaciones `jump_table`/`resolved_indirect` y las categorías funcionales de Cortex-M.
- **Traducción de instrucciones ARM / Thumb-2 incompleta e incorrecta.** El C de ArduCopter tenía 75.664 `UNSUPPORTED` y 58.939 instrucciones VFP emitidas como comentario "no simulado". Además: `_strip_condition` confundía el sufijo `s` con una condición (`movs` → `mo`+`vs`, `lsls`, `muls`, `adcs`, `bics`); las instrucciones con `s` no actualizaban NZCV; `adc`/`sbc` ignoraban el carry y `rsb` se traducía como `sub`; los modos de direccionamiento con writeback, post-índice o registro desplazado se ignoraban; `movw` conservaba la mitad alta; las cargas desde literal pools leían de `r15`, que nunca se inicializaba. Ahora el C de ArduCopter tiene 0 `UNSUPPORTED`.

### Corregido (trazabilidad)
- **Puntos de traza perdidos en saltos.** El translator omitía en línea la instrucción de salto que cierra un bloque (la materializa la salida de bloque) y con ella su `trace_point`: con `--granularity instruction` se perdían 34.983 de 327.879 puntos en ArduCopter, y con `selective` los de bloques formados solo por un salto. Ahora se emite `__trace` también ahí.

### Corregido (comparación con Ghidra)
- **Funciones que no retornan.** Tras `bl abort`, `bl _exit` o `bl AP_HAL::panic` se creaba una arista fall-through y se desensamblaba el relleno siguiente como código. Ahora se reconocen por nombre (`NORETURN_NAMES`, todas las arquitecturas) y, en Cortex-M, por análisis de punto fijo (ningún camino llega a un retorno: bucles de hilos, `panic`, `reboot`...). En ArduCopter: 55 funciones. Nuevo campo `Function.is_noreturn`.
- **Aristas perdidas por deduplicación.** Se deduplicaba por (origen, destino) sin el tipo: en `bl siguiente` se perdía la arista fall_through.
- **Cortex-M excluía `main`, `_exit`, `__assert_func`, `SystemInit` y `__libc_init_array` de las funciones** (lógica heredada de binarios Linux); su código se atribuía a la función anterior y `_exit` no podía marcarse como noreturn.

### Añadido (comparación con Ghidra)
- **Tipo de arista `tail_call`:** salto directo a la entrada de otra función (Ghidra lo modela como llamada).
- Con el mismo `arducopter.elf`, frente al `SimpleBlockModel` de Ghidra 11.3.2: 79.193 bloques comunes (todos los de Flashback) y 119.541 aristas idénticas de 120.495. Las diferencias restantes son convenciones de Ghidra (bloque nuevo en cada etiqueta `switchD`), datos que Ghidra decodifica como código y fall-throughs tras funciones que Ghidra no detecta como noreturn.

### Añadido (semántica ARM)
- **`flashback/arch/arm32/semantics.py`:** semántica ARM / Thumb-2 / VFP compartida por los translators ARM32 y Cortex-M: procesamiento de datos con flags NZCV exactos (incluido el carry del desplazador e inmediatos modificados), multiplicaciones largas y de media palabra, divisiones, campos de bits, extensiones, saturación, todos los modos de direccionamiento, `ldm`/`stm`/`push`/`pop`, `ldrex`/`strex` con monitor exclusivo, y VFP de simple y doble precisión (banco `s0..s31`/`d0..d31`, FPSCR, `vcmp`+`vmrs`, conversiones con saturación y punto fijo, `vsel`, `vrint*`, `vmaxnm`, reglas de NaN de ARM). Las formas NEON (Advanced SIMD) se rechazan explícitamente.
- **Anotación `literal_load`:** los disassemblers ARM32 y Cortex-M resuelven el valor de cada carga relativa a pc; el translator la emite como constante.
- **Despachador `__call_indirect`:** `blx rN`, `bx rN` y escrituras en pc saltan a la función cuya dirección contiene el registro (punteros a función, tablas virtuales); aborta con un mensaje si la dirección no es una función.
- **Cortex-M:** `mrs`/`msr` de APSR/xPSR conectados a los flags NZCV; MSP/PSP según `CONTROL.SPSEL`; `svc` invoca `SVC_Handler` si existe.
- **`tools/arm_difftest.py`:** prueba diferencial frente a Unicorn (Cortex-M7 y ARMv8-A). Resultado: 51.908 bloques reales de ArduCopter (232 formas de instrucción), 642 casos dirigidos a las 9 formas restantes y ~60.000 instrucciones aleatorias en Thumb-2 y modo ARM, sin diferencias salvo codificaciones UNPREDICTABLE.
- **86 pruebas** en `tests/test_arm_semantics.py` (PAS01–PAS05). Total de la batería: 268 pruebas.

### Añadido
- **Descubrimiento de código Cortex-M por alcanzabilidad** (`flashback/arch/cortexm/discovery.py`): descarta literal pools y tablas decodificados como instrucciones por el barrido lineal y redecodifica tras una desincronización.
- **Tablas de salto Thumb-2:** `tbb`/`tbh` y `adr rB; ldr pc, [rB, rI, lsl #2]`, acotadas por el `cmp rI, #K` previo. El traductor las emite como `switch`.
- **Aristas explícitas:** campo `source_block`, `condition` siempre presente (`always`, `<mnemónico>`, `not <mnemónico>`, `case N`), aristas `call` hacia la función llamada y aristas hacia `"unknown"` para saltos y llamadas indirectas sin resolver.
- **`classify_arm_flow()`**: clasificación de terminadores ARM/Thumb por operando, compartida por ARM32 y Cortex-M.
- **54 pruebas** en `tests/test_arm_flow.py` (PAF01–PAF06). Total de la batería: 182 pruebas.

---

## [1.0.1] — 2026-07-02

### Corregido
- **Volcado de traza robusto ante terminaciones por `exit` (M4).** El volcado de `flashback_trace.bin` estaba únicamente al final de `main()`, por lo que un programa que terminara mediante una syscall cruda de la familia `exit` (`exit`=60, `exit_group`=231) —como `06_syscalls`— finalizaba el proceso sin retornar a `main()` y perdía la traza. Ahora el runtime: (a) registra el volcado con `atexit()`, cubriendo el retorno normal y las salidas por `exit()` de la libc; (b) encamina las syscalls por una envoltura `__do_syscall()` que vuelca la traza antes de ejecutar una llamada de la familia `exit`; y (c) hace el volcado idempotente para no duplicar la escritura. Con esto, M4 pasa de 7/8 a 8/8.
- **`setup.cfg` corrupto.** El fichero contenía por error una copia de `flashback/arch/arm32/enricher.py`, lo que rompía `pip install -e .`. Se sustituye por la configuración de `flake8`/`flake8-bugbear` (RD04), que antes no tenía fichero propio.

### Añadido
- **Pruebas PI07 de traza dinámica (M4).** Tres pruebas en `tests/test_integration.py` que compilan, ejecutan y verifican la creación efectiva de `flashback_trace.bin`, incluyendo el caso de terminación por syscall `exit`. Total de la batería: 128 pruebas.

---

## [1.0.0] — 2026-06-16

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

## [0.2.1] — 2026-06-12

### Añadido
- Arquitectura ARM64 (AArch64) completa: disassembler, enricher, translator con AAPCS64.
- Tests de cobertura: `test_cfg_builder.py` (23 tests), `test_exporter.py` (22 tests).
- Binario `tests/binaries/hello_world.elf` para tests de integración.

### Corregido
- Múltiples warnings de flake8 en arm32, arm64, cortexm, x86 (importaciones no usadas, strings f vacíos).

---

## [0.2.0] — 2026-04-27

### Añadido
- Refactorización completa: arquitectura pipeline Disassembler → CFGBuilder → Enricher → Translator.
- Soporte ARM32 (ARMv7 Linux) y Cortex-M (Thumb-2 bare-metal).
- Sistema de anotaciones extensible con ANNOTATION_REGISTRY.
- Trazabilidad bidireccional: comentarios estáticos `/* 0xADDR */` y runtime `__trace()`.
- JSON Schema para EnrichedCFG (`docs/cfg_schema.json`).
- CLI completa con detección automática de arquitectura.

---

## [0.1.0] — 2026-02-15

### Añadido
- Versión funcional inicial: soporte x86-64 y x86 (i386).
- Pipeline básico: lief + capstone → CFG → C portable.
- Tablas de syscalls Linux para x86-64, x86, ARM64 y ARM32.
