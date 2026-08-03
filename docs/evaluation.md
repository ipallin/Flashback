# Evaluación experimental de Flashback

## Resumen ejecutivo

| Métrica | Resultado |
|---|---|
| Binarios del corpus | 8 |
| Traducción exitosa (Flashback) | 8/8 (100%) |
| Compilación del C generado | 8/8 (100%) |
| Equivalencia funcional (PASS) | 7/8 (87%) |

## Resultados por binario

| ID | Descripción | Tags | Flashback | Compila | Equiv. | Tiempo FB | Líneas C | Bloques | Instrucciones |
|---|---|---|---|---|---|---|---|---|---|
| `01_hello_nopie` | Hello World — función auxiliar, printf, no-PIE | basic, external_call | ✓ | ✓ | ✓ | 0.7s | 435 | 24 | 91 |
| `02_switch` | Switch con 5 casos → tabla de salto (Fase 1) | jump_table, external_call | ✓ | ✓ | ✓ | 0.7s | 516 | 34 | 109 |
| `03_recursive` | Fibonacci recursivo y función is_even mutuamente recursiva | recursion, cond_branch | ✓ | ✓ | ✓ | 0.7s | 557 | 37 | 131 |
| `04_strings` | Operaciones de cadena: snprintf, strlen, strcat, strcmp | external_call, rodata | ✓ | ✓ | ✓ | 0.7s | 584 | 31 | 134 |
| `05_loops` | Bucles anidados: for/while/do-while, loop headers, Collatz | loop, cond_branch | ✓ | ✓ | ✓ | 0.7s | 603 | 40 | 148 |
| `06_syscalls` | Syscalls directas via inline asm: write(1) y exit(0) | syscall | ✓ | ✓ | ✓ | 0.7s | 462 | 28 | 97 |
| `07_funcptr` | Punteros a función en dispatch table (Fase 2) | indirect_call, function_pointer | ✓ | ✓ | ~ | 0.7s | 597 | 30 | 149 |
| `08_memory` | Gestión de heap: malloc, realloc, free | heap, external_call | ✓ | ✓ | ✓ | 0.6s | 703 | 43 | 178 |

## Detalle por caso

### `01_hello_nopie` — Hello World — función auxiliar, printf, no-PIE

- **Estado:** `PASS`
- **Tags:** basic, external_call
- **Tiempo Flashback:** 0.66 s
- **Código C generado:** 435 líneas
- **CFG:** 5 funciones · 24 bloques · 91 instrucciones · 18 aristas
- **Compilación gcc:** ✓ (0.07 s)
- **Equivalencia funcional:** ✓ stdout y exit code idénticos
  - Salida original (primera línea): `result: 13`

### `02_switch` — Switch con 5 casos → tabla de salto (Fase 1)

- **Estado:** `PASS`
- **Tags:** jump_table, external_call
- **Tiempo Flashback:** 0.67 s
- **Código C generado:** 516 líneas
- **CFG:** 5 funciones · 34 bloques · 109 instrucciones · 35 aristas
- **Tablas de salto resueltas (Fase 1):** 1 sitios
- **Compilación gcc:** ✓ (0.07 s)
- **Equivalencia funcional:** ✓ stdout y exit code idénticos
  - Salida original (primera línea): `0: lunes`

### `03_recursive` — Fibonacci recursivo y función is_even mutuamente recursiva

- **Estado:** `PASS`
- **Tags:** recursion, cond_branch
- **Tiempo Flashback:** 0.68 s
- **Código C generado:** 557 líneas
- **CFG:** 6 funciones · 37 bloques · 131 instrucciones · 34 aristas
- **Compilación gcc:** ✓ (0.08 s)
- **Equivalencia funcional:** ✓ stdout y exit code idénticos
  - Salida original (primera línea): `fib(0)=0 even=1`

### `04_strings` — Operaciones de cadena: snprintf, strlen, strcat, strcmp

- **Estado:** `PASS`
- **Tags:** external_call, rodata
- **Tiempo Flashback:** 0.70 s
- **Código C generado:** 584 líneas
- **CFG:** 9 funciones · 31 bloques · 134 instrucciones · 27 aristas
- **Compilación gcc:** ✓ (0.08 s)
- **Equivalencia funcional:** ✓ stdout y exit code idénticos
  - Salida original (primera línea): `Hola, Alice! (len=12)`

### `05_loops` — Bucles anidados: for/while/do-while, loop headers, Collatz

- **Estado:** `PASS`
- **Tags:** loop, cond_branch
- **Tiempo Flashback:** 0.71 s
- **Código C generado:** 603 líneas
- **CFG:** 6 funciones · 40 bloques · 148 instrucciones · 39 aristas
- **Compilación gcc:** ✓ (0.09 s)
- **Equivalencia funcional:** ✓ stdout y exit code idénticos
  - Salida original (primera línea): `matrix_sum(4,4)=120`

### `06_syscalls` — Syscalls directas via inline asm: write(1) y exit(0)

- **Estado:** `PASS`
- **Tags:** syscall
- **Tiempo Flashback:** 0.71 s
- **Código C generado:** 462 líneas
- **CFG:** 4 funciones · 28 bloques · 97 instrucciones · 24 aristas
- **Compilación gcc:** ✓ (0.07 s)
- **Equivalencia funcional:** ✓ stdout y exit code idénticos
  - Salida original (primera línea): `syscall: write directo`

### `07_funcptr` — Punteros a función en dispatch table (Fase 2)

- **Estado:** `OUTPUT_MISMATCH`
- **Tags:** indirect_call, function_pointer
- **Tiempo Flashback:** 0.67 s
- **Código C generado:** 597 líneas
- **CFG:** 8 funciones · 30 bloques · 149 instrucciones · 23 aristas
- **Compilación gcc:** ✓ (0.08 s)
- **Equivalencia funcional:** ~ 0/3 líneas coinciden

### `08_memory` — Gestión de heap: malloc, realloc, free

- **Estado:** `PASS`
- **Tags:** heap, external_call
- **Tiempo Flashback:** 0.64 s
- **Código C generado:** 703 líneas
- **CFG:** 9 funciones · 43 bloques · 178 instrucciones · 43 aristas
- **Compilación gcc:** ✓ (0.08 s)
- **Equivalencia funcional:** ✓ stdout y exit code idénticos
  - Salida original (primera línea): `sum_of_squares(8)=140`

## Análisis por categoría de feature

- **Caso base:** 1/1 PASS
- **Llamadas externas (PLT):** 4/4 PASS
- **Tablas de salto — Fase 1:** 1/1 PASS
- **Llamadas indirectas — Fase 2:** 0/1 PASS
- **Punteros a función:** 0/1 PASS
- **Recursión:** 1/1 PASS
- **Bucles (loop headers):** 1/1 PASS
- **Saltos condicionales:** 2/2 PASS
- **Syscalls directas:** 1/1 PASS
- **Gestión de heap:** 1/1 PASS
- **Acceso a .rodata:** 1/1 PASS

## Limitaciones observadas

- `07_funcptr` (Punteros a función en dispatch table (Fase 2)): OUTPUT_MISMATCH — 0/3 líneas coinciden

---
*Generado automáticamente por `tests/corpus/evaluate.py`*