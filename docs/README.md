# Flashback

Flashback convierte binarios ELF en código C compilable y ejecutable, manteniendo trazabilidad bidireccional con el ensamblador original. No es un decompilador de legibilidad (como Ghidra o Hex-Rays): genera C funcional que simula el comportamiento del binario instrucción a instrucción.

## Instalación

```bash
pip install -e .
```

Dependencias: `capstone >= 5.0`, `lief >= 0.14`.

## Uso básico

```bash
# Conversión simple
flashback binario.elf -o salida.c

# Con arquitectura explícita (por defecto: auto-detección)
flashback firmware.elf --arch cortexm -o firmware.c

# Exportar el CFG enriquecido a JSON
flashback binario.elf -o salida.c --export-cfg cfg.json

# Solo traducir ciertas funciones
flashback binario.elf -o salida.c --functions main,foo,bar

# Control de granularidad de trazabilidad
flashback binario.elf -o salida.c --granularity block

# Verbose (muestra progreso del pipeline)
flashback binario.elf -v -o salida.c
```

## Opciones

| Opción | Valores | Por defecto | Descripción |
|---|---|---|---|
| `--arch` | `auto`, `x86_64`, `x86`, `arm64`, `arm32`, `cortexm` | `auto` | Arquitectura del binario |
| `--granularity` | `none`, `block`, `instruction`, `selective` | `selective` | Densidad de puntos de traza |
| `--functions` | `func1,func2,...` | — | Traducir solo estas funciones |
| `--export-cfg` | `<fichero.json>` | — | Exportar CFG enriquecido a JSON |
| `-o` / `--output` | `<fichero.c>` | `<binario>.c` | Fichero de salida |
| `-v` / `--verbose` | — | — | Logging detallado del pipeline |

## Arquitecturas soportadas

| `--arch` | ISA | Modo | ABI | Syscall |
|---|---|---|---|---|
| `x86_64` | x86-64 | 64-bit | System V AMD64 | `syscall` (num en rax) |
| `x86` | i386 | 32-bit | cdecl | `int 0x80` (num en eax) |
| `arm64` | AArch64 | 64-bit | AAPCS64 | `svc #0` (num en x8) |
| `arm32` | ARMv7 Linux | 32-bit | AAPCS | `svc #0` (num en r7) |
| `cortexm` | Cortex-M (Thumb-2) | bare-metal | — | sin syscalls |

La auto-detección (`--arch auto`) lee la cabecera ELF con lief. Para Cortex-M, el criterio adicional es: `e_machine == ARM` + Thumb bit en entry point + sin sección `.dynamic`.

## Compilar el código generado

El C generado es portable a cualquier plataforma de 64 bits:

```bash
# El binario original era x86_64 Linux
gcc -O0 -g salida.c -o simulado

# El binario original era ARM32 Linux (cross-compile)
arm-linux-gnueabihf-gcc -O0 salida.c -o simulado

# Firmware Cortex-M (simulación en x86_64)
gcc -O0 salida.c -o simulado_fw
```

## Trazabilidad

### Estática (C ↔ ASM)

Cada instrucción genera un comentario con su dirección original:

```c
/* 0x401060: mov rax, 0x1 */
rax = (uint64_t)0x1ULL;
/* 0x40106e: syscall */
rax = (uint64_t)write((int)rdi, (void*)(uintptr_t)rsi, (size_t)rdx);
```

### Dinámica (runtime)

Los puntos de traza emiten la dirección en ejecución al buffer `__trace_buffer`. Al terminar, `__trace_dump("flashback_trace.bin")` vuelca el buffer a disco:

```c
__trace(0x401060ULL);  /* block entry */
```

### Políticas de granularidad

| `--granularity` | Puntos de traza insertados |
|---|---|
| `none` | Ninguno |
| `block` | Entrada de cada bloque básico |
| `instruction` | Cada instrucción |
| `selective` | Entradas de bloque + llamadas externas + syscalls + loop headers |

## Formato de salida

El CFG enriquecido que genera el pipeline puede exportarse con `--export-cfg`. El formato está definido en `cfg_schema.json` y hay un ejemplo en `cfg_example.json`.

## Pipeline

```
ELF binario
    │
    ▼
Disassembler          ← lief (símbolos, PLT, secciones) + capstone (instrucciones)
    │ dict[int, RawInstruction] + BinaryMeta
    ▼
CFGBuilder            ← identifica bloques básicos, aristas, funciones
    │ EnrichedCFG (pipeline_stage='initial')
    ▼
Enricher              ← anota: external_call, syscall, functional_class, trace_recommendation
    │ EnrichedCFG (pipeline_stage='enriched')
    ▼
Translator            ← genera código C con trazabilidad
    │ str (código C)
    ▼
Fichero .c
```
