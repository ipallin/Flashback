# Flashback

Flashback convierte binarios ELF en código C compilable, ejecutable y trazable. No es un decompilador de legibilidad: genera C que simula el comportamiento del binario instrucción a instrucción, con correspondencia directa entre cada línea de C y la instrucción ensambladora original.

**Trabajo Fin de Estudios — Grado en Ciberseguridad, UNIR 2025-2026**

---

## Instalación

```bash
git clone <repositorio>
cd Flashback-dbg
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

**Requisitos:** Python 3.10+, `capstone >= 5.0`, `lief >= 0.14`

Verificar:

```bash
python flashback.py tests/binaries/hello_world.elf -o /tmp/test.c && echo "OK"
```

---

## Uso rápido

```bash
# Conversión básica (arquitectura auto-detectada)
python flashback.py binario.elf -o salida.c

# Con arquitectura explícita
python flashback.py firmware.elf --arch cortexm -o firmware.c

# Exportar el CFG enriquecido a JSON además del C
python flashback.py binario.elf -o salida.c --export-cfg cfg.json

# Solo traducir ciertas funciones
python flashback.py binario.elf -o salida.c --functions main,foo,bar

# Verbose (progreso del pipeline)
python flashback.py binario.elf -v -o salida.c
```

---

## Arquitecturas soportadas

| `--arch` | ISA | Modo | ABI | Syscall | Auto-detección |
|---|---|---|---|---|---|
| `x86_64` | x86-64 | 64-bit | System V AMD64 | `syscall` (num en rax) | `e_machine == EM_X86_64` |
| `x86` | i386 | 32-bit | cdecl | `int 0x80` (num en eax) | `e_machine == EM_386` |
| `arm64` | AArch64 | 64-bit | AAPCS64 | `svc #0` (num en x8) | `e_machine == EM_AARCH64` |
| `arm32` | ARMv7 Linux | 32-bit | AAPCS | `svc #0` (num en r7) | `EM_ARM` + sin Thumb en entry |
| `cortexm` | Cortex-M (Thumb-2) | bare-metal | — | sin syscalls | `EM_ARM` + Thumb bit en entry + sin `.dynamic` |

La opción `--arch auto` (por defecto) lee la cabecera ELF con lief. Puede especificarse manualmente con `--arch <isa>`.

---

## Referencia CLI

```
python flashback.py <binario.elf> [opciones]

Opciones:
  -o, --output <file>          Fichero C de salida (default: <binario>.c)
  --arch <isa>                 Arquitectura: auto|x86_64|x86|arm64|arm32|cortexm (default: auto)
  --granularity <g>            Densidad de trazas: none|block|instruction|selective (default: selective)
  --functions <f1,f2,...>      Traducir solo estas funciones
  --export-cfg <file>          Exportar CFG enriquecido a JSON
  -v, --verbose                Logging detallado del pipeline
  --version                    Mostrar versión
```

### Granularidad de trazabilidad

| `--granularity` | Puntos de traza `__trace()` insertados |
|---|---|
| `none` | Ninguno |
| `block` | Entrada de cada bloque básico |
| `instruction` | Cada instrucción |
| `selective` | Entradas de bloque + llamadas externas + syscalls + loop headers |

---

## Pipeline

```
ELF
 │
 ▼  Disassembler   ← lief (ELF headers, símbolos, PLT, secciones)
 │                 ← capstone (instrucciones)
 │  dict[int, RawInstruction] + BinaryMeta
 │
 ▼  CFGBuilder     ← identifica bloques básicos, aristas, funciones
 │                 ← ArchMnemonics parametriza la lógica de control flow
 │  EnrichedCFG (stage='initial')
 │
 ▼  Enricher       ← anota external_call, syscall, functional_class
 │                 ← decide granularidad de trazabilidad por bloque
 │  EnrichedCFG (stage='enriched')
 │
 ▼  Translator     ← mapea instrucciones a expresiones C
 │                 ← inserta __trace(), SIM_READ/WRITE, main() de entrada
 │  str (código C)
 │
 ▼  .c
```

---

## Código C generado

### Estructura del fichero

```c
/*
 * Generado por Flashback v0.1.0 — 2026-06-16T09:00:00Z
 *
 * Binario: hello_world.elf (amd64)
 * SHA256 : a1b2c3...
 * Entry  : 0x401060
 */

#include <stdint.h>
#include <stdio.h>
/* ... */

/* Macros de acceso a memoria simulada */
#define SIM_READ64(addr)       (*(uint64_t *)__sim_addr((uint64_t)(addr)))
#define SIM_WRITE32(addr, val) (*(uint32_t *)__sim_addr((uint64_t)(addr)) = (uint32_t)(val))
/* ... */

/* Registros simulados como variables globales */
static uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
static uint64_t rsi = 0, rdi = 0, rsp = 0, rbp = 0;
/* ... */

/* Declaraciones forward */
static void func_401060(void);  /* main */
/* ... */

/* Implementación de funciones */
static void func_401060(void) {
  block_401060:
    __trace(0x401060ULL);
    /* 0x401060: push rbp */
    rsp -= 8; SIM_WRITE64(rsp, rbp);
    /* 0x401061: mov rbp, rsp */
    rbp = rsp;
    /* 0x401064: lea rdi, [rip+0xeb5] */
    rdi = (uint64_t)0x402000ULL;
    /* 0x40106b: call puts */
    __trace(0x40106bULL);
    rax = (uint64_t)(uintptr_t)puts((const char*)(uintptr_t)rdi);
  block_401070:
    /* 0x401070: xor eax, eax */
    rax = (uint32_t)((uint32_t)rax ^ (uint32_t)rax);
    ZF = ((uint32_t)rax == 0);
    /* 0x401072: pop rbp */
    rbp = SIM_READ64(rsp); rsp += 8;
    /* 0x401073: ret */
    return;
}

/* Punto de entrada */
int main(int argc, char **argv) {
    rsp = (uint64_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 8);
    rsp &= ~(uint64_t)0xFU;
    rdi = (uint64_t)argc;
    rsi = (uint64_t)(uintptr_t)argv;
    func_401060();
    __trace_dump("flashback_trace.bin");
    return (int)(uint32_t)rax;
}
```

Para **Cortex-M** el entry point es diferente — no hay argc/argv, se llama directamente al Reset_Handler:

```c
int main(void) {
    r13 = (uint32_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 4);
    r13 &= ~(uint32_t)0x7U;
    msp = r13;
    func_8020d8c();  /* Reset_Handler @ 0x8020d8c */
    for (;;);        /* el firmware no retorna */
    return 0;
}
```

### Compilar el C generado

El C generado compila en cualquier plataforma de 64 bits:

```bash
# El original era x86_64 Linux
gcc -O0 -g salida.c -o simulado

# El original era arm32 Linux (cross-compile)
arm-linux-gnueabihf-gcc -O0 salida.c -o simulado_arm

# El original era firmware Cortex-M (simular en x86_64)
gcc -O0 firmware.c -o simulado_fw
```

---

## Trazabilidad bidireccional

### Estática (C ↔ ASM)

Cada instrucción genera un comentario con su dirección original:

```c
/* 0x401064: lea rdi, [rip+0xeb5] */
rdi = (uint64_t)0x402000ULL;
/* 0x40106b: call puts */
rax = (uint64_t)(uintptr_t)puts((const char*)(uintptr_t)rdi);
```

Dada cualquier línea del C generado, puedes encontrar la instrucción ASM exacta buscando la dirección en objdump, Ghidra o gdb.

### Dinámica (runtime)

Los puntos de traza emiten la dirección en ejecución al buffer `__trace_buffer`. Al terminar, `__trace_dump("flashback_trace.bin")` vuelca el buffer a disco:

```c
__trace(0x401060ULL);  /* block entry */
```

Esto permite reconstruir el camino de ejecución exacto y compararlo con el binario original.

---

## Estructura del repositorio

```
Flashback-dbg/
├── flashback.py              ← Punto de entrada
├── flashback/
│   ├── core/
│   │   ├── models.py         ← EnrichedCFG, BasicBlock, Instruction, Edge, anotaciones
│   │   ├── cfg_builder.py    ← Construcción del CFG (agnóstico de arquitectura)
│   │   ├── translator.py     ← Generación de C (clase base; x86_64 la usa directamente)
│   │   └── exporter.py       ← Serialización JSON del CFG
│   │
│   ├── arch/
│   │   ├── base.py           ← Interfaces abstractas: Disassembler, Enricher
│   │   ├── x86_64/           ← x86-64 Linux (completo)
│   │   ├── x86/              ← i386 Linux (completo)
│   │   ├── arm64/            ← AArch64 Linux (completo)
│   │   ├── arm32/            ← ARMv7 Linux userspace (completo)
│   │   └── cortexm/          ← ARM Cortex-M bare-metal, hereda de arm32 (completo)
│   │
│   ├── ui/
│   │   └── cli.py            ← CLI: _detect_arch(), _build_pipeline(), run()
│   │
│   └── data/
│       ├── libc_prototypes.json
│       ├── syscalls_x86_64.json
│       ├── syscalls_x86.json
│       ├── syscalls_arm64.json
│       └── syscalls_arm32.json
│
├── tests/
│   ├── test_functional.py
│   ├── test_integration.py
│   └── test_traceability.py
│
└── docs/
    ├── README.md             ← Referencia rápida: CLI, opciones, pipeline
    ├── architecture.md       ← Arquitectura del sistema, módulos, cómo añadir una ISA
    ├── architectures.md      ← Referencia detallada por ISA
    ├── cfg_schema.json       ← JSON Schema del EnrichedCFG (draft-07)
    └── cfg_example.json      ← CFG de ejemplo (hello_world)
```

Cada arquitectura en `arch/<isa>/` implementa los mismos siete módulos: `disassembler.py`, `enricher.py`, `translator.py`, `register_map.py`, `calling_convention.py`, `instruction_sem.py`, `syscall_table.py`.

---

## Diseño

La decisión central es la separación entre lógica **agnóstica de arquitectura** (`core/`) y lógica **específica de ISA** (`arch/<isa>/`). Añadir una nueva arquitectura no requiere modificar el CFGBuilder ni el Translator base.

El CFGBuilder se parametriza con un `ArchMnemonics` que describe el conjunto de mnemonicos de cada categoría (saltos condicionales, incondicionales, llamadas, retornos, syscalls, halts) y una función de resolución de targets. Todo lo demás — identificación de bloques básicos, construcción de aristas, asignación de bloques a funciones — es código compartido.

Frente a los lifters basados en LLVM IR (McSema, Rev.ng), Flashback traduce directamente desde el CFG enriquecido al C final, preservando la trazabilidad instrucción a instrucción sin pasar por una representación intermedia que la pierde.

---

## Tests

```bash
pytest tests/                     # todos los tests
pytest tests/test_functional.py   # corrección funcional del traductor
pytest tests/test_integration.py  # pipeline end-to-end
pytest tests/test_traceability.py # trazabilidad bidireccional
```

---

## Documentación

- [`docs/README.md`](docs/README.md) — referencia rápida de opciones CLI
- [`docs/architecture.md`](docs/architecture.md) — arquitectura del sistema, módulos, cómo añadir una ISA
- [`docs/architectures.md`](docs/architectures.md) — referencia detallada por arquitectura: registros, ABI, PLT, instrucciones
- [`docs/cfg_schema.json`](docs/cfg_schema.json) — JSON Schema del EnrichedCFG
- [`docs/cfg_example.json`](docs/cfg_example.json) — CFG de ejemplo para referencia
- [`docs/evaluation.md`](docs/evaluation.md) — evaluación experimental sobre corpus de 8 binarios

---

## Evaluación experimental

Flashback incluye un corpus de 8 binarios de prueba y un script de evaluación automática que mide tres métricas: traducción exitosa, compilación del C generado y equivalencia funcional (mismo stdout y exit code).

```bash
# Compilar el corpus (requiere gcc)
cd tests/corpus && bash build.sh

# Ejecutar la evaluación completa
python tests/corpus/evaluate.py
```

**Resultados sobre el corpus v1 (8 binarios x86-64, gcc -O0 -no-pie):**

| Métrica | Resultado |
|---|---|
| Traducción exitosa (Flashback) | **8/8 (100%)** |
| Compilación del C generado | **8/8 (100%)** |
| Equivalencia funcional | **6/8 (75%)** |

Los 2 casos fallidos corresponden exactamente a limitaciones documentadas: tablas de salto con entradas de 4 bytes en binarios no-PIE (formato no detectado por la heurística actual) y dispatch via array de punteros a función (requiere VSA inter-bloque). Ver [`docs/evaluation.md`](docs/evaluation.md) para el análisis completo de causas raíz.

---

## Limitaciones conocidas

| Limitación | Aplica a |
|---|---|
| Tablas de salto con entradas de 4 bytes en no-PIE (GCC patrón movsxd) | x86_64 Fase 1 |
| Dispatch via array de punteros a función (requiere VSA) | x86_64 Fase 2 |
| Sin resolución de saltos indirectos en ARM32/ARM64 | arm32, arm64 |
| Sin recuperación de tipos de alto nivel (structs, clases) | Todas |
| Sin soporte SIMD/AVX/NEON — instrucciones comentadas | x86_64, arm64 |
| VFP/FPU Cortex-M comentado como `[VFP/FPU — no simulado]` | cortexm |
| Solo formato ELF (no PE, Mach-O) | Todas |
| Binarios stripped: function discovery parcial | Todas |
| Sin análisis de dataflow inter-bloque (VSA) | Todas |
