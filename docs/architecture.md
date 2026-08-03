# Arquitectura de Flashback

## Estructura del repositorio

```
flashback/
├── core/                        ← Lógica independiente de la ISA
│   ├── models.py                ← Todas las estructuras de datos (EnrichedCFG, etc.)
│   ├── cfg_builder.py           ← Construcción del CFG desde instrucciones crudas
│   ├── translator.py            ← Generación de C (clase base Translator)
│   └── exporter.py              ← Serialización/deserialización JSON del CFG
│
├── arch/                        ← Implementaciones por arquitectura
│   ├── base.py                  ← Interfaces abstractas (Disassembler, Enricher)
│   ├── x86_64/                  ← x86-64 Linux
│   ├── x86/                     ← i386 Linux
│   ├── arm64/                   ← AArch64 Linux
│   ├── arm32/                   ← ARMv7 Linux userspace
│   └── cortexm/                 ← ARM Cortex-M bare-metal (Thumb-2)
│
├── ui/
│   └── cli.py                   ← CLI (argparse): _detect_arch() + _build_pipeline() + run()
│
└── data/
    ├── libc_prototypes.json     ← Prototipos de funciones libc (args, tipos de retorno)
    ├── syscalls_x86_64.json     ← Tabla de syscalls Linux x86-64
    ├── syscalls_x86.json        ← Tabla de syscalls Linux i386 (int 0x80)
    ├── syscalls_arm64.json      ← Tabla de syscalls Linux AArch64
    └── syscalls_arm32.json      ← Tabla de syscalls Linux ARM32 EABI
```

## Módulo `core/`

### `models.py` — Estructuras de datos

Todas las estructuras son dataclasses Python. La estructura central es `EnrichedCFG`:

```
EnrichedCFG
├── metadata: Metadata          ← versión de herramienta, etapa del pipeline
├── binary_info: BinaryInfo     ← nombre, sha256, entry point, arquitectura
├── functions: dict[HexAddr, Function]
├── basic_blocks: dict[HexAddr, BasicBlock]
├── instructions: dict[HexAddr, Instruction]
└── edges: list[Edge]
```

La misma estructura recorre todo el pipeline; lo que cambia entre etapas es `pipeline_stage` y la presencia/ausencia de anotaciones.

**Anotaciones** (listas en `BasicBlock.annotations` / `Instruction.annotations`):

| Tipo | Dónde | Qué indica |
|---|---|---|
| `FunctionalClassAnnotation` | Bloque | Categoría funcional del bloque |
| `ExternalCallAnnotation` | Instrucción | Llamada a función de librería dinámica |
| `SyscallAnnotation` | Instrucción | Syscall del sistema operativo |
| `TraceRecommendationAnnotation` | Bloque | Granularidad de traza recomendada |
| `TracePointAnnotation` | Instrucción | Punto de traza concreto a insertar |
| `JumpTableAnnotation` | Instrucción | Tabla de salto switch-case resuelta (Fase 1) |
| `ResolvedIndirectAnnotation` | Instrucción | Llamada indirecta resuelta por backward slice (Fase 2) |

**Categorías funcionales de bloque** (`FunctionalClassAnnotation.category`):

| Valor | Cuándo se asigna |
|---|---|
| `function_prologue` | Bloque de prólogo detectado por heurística |
| `function_epilogue` | Bloque de epílogo (termina en `ret`) |
| `function_body` | Código genérico de función |
| `external_call_site` | Contiene `call` a PLT anotado |
| `syscall_site` | Contiene instrucción `syscall`/`svc`/`int 0x80` |
| `indirect_call_site` | `call REG` resuelto por backward slice (Fase 2) |
| `jump_table_site` | Terminador `jmp` con tabla de salto resuelta (Fase 1) |
| `loop_header` | Back-edge detectado |
| `return_block` | Termina en `ret` sin patrón de epílogo |
| `unreachable` | Sin predecesores ni es entrada de función |

### `cfg_builder.py` — Construcción del CFG

Recibe `dict[int, RawInstruction]` + `BinaryMeta` y produce `EnrichedCFG`. Proceso:

1. `_identify_block_starts()` — identifica inicios de bloque básico: entradas de función, targets de saltos, post-calls, post-returns
2. `_build_raw_blocks()` — agrupa instrucciones en bloques, cortando en terminadores o en el inicio del siguiente bloque
3. `_assign_blocks_to_functions()` — asigna cada bloque a la función más cercana por debajo (bisect, O(n log m))
4. Construye objetos `Instruction` y `BasicBlock` en `EnrichedCFG`
5. Rellena `predecessors` de cada bloque
6. `_build_edges()` — construye `Edge` tipadas (fall_through, conditional_jump, etc.)
7. `_fill_call_relations()` — rellena `calls_to` / `called_from` entre funciones

**`ArchMnemonics`** es el único parámetro que hace al CFGBuilder agnóstico de arquitectura:

```python
@dataclass
class ArchMnemonics:
    cond_branches: frozenset[str]   # 'beq', 'jne', 'cbz', ...
    uncond_jumps:  frozenset[str]   # 'b', 'jmp', 'bx', ...
    calls:         frozenset[str]   # 'bl', 'call', ...
    returns:       frozenset[str]   # 'bx', 'ret', ...
    syscalls:      frozenset[str]   # 'svc', 'syscall', 'int', ...
    halts:         frozenset[str]   # 'hlt', 'udf', 'wfi', ...
    target_resolver: Callable       # operands → int | None
```

### `translator.py` — Generación de C

La clase base `Translator` genera el fichero C completo. Los traductores por arquitectura heredan de ella y sobreescriben los métodos que difieren:

| Método sobreescribible | Qué controla |
|---|---|
| `_emit_registers()` | Declaración de registros simulados |
| `_emit_flags()` | Variables de flags (ZF, NF, CF, ...) |
| `_emit_entry_point()` | Función `main()` de entrada |
| `_translate_instruction()` | Mapeo de cada mnemónico a C |
| `_emit_external_call()` | Código para llamadas a librería |
| `_emit_syscall()` | Código para syscalls |
| `_is_branch_terminator()` | Si un mnemónico termina bloque |
| `_jcc_condition()` | Condición C para saltos condicionales |

### `exporter.py` — Serialización JSON

Serializa/deserializa `EnrichedCFG` a JSON. El esquema completo está en `cfg_schema.json`.

## Módulo `arch/`

### Estructura por arquitectura

Cada arquitectura implementa los mismos siete módulos:

```
arch/<isa>/
├── __init__.py            ← Exporta Disassembler, Enricher, Translator, RegisterMap
├── disassembler.py        ← carga ELF con lief + desensambla con capstone → RawInstruction
├── enricher.py            ← anota el CFG con semántica de la arquitectura
├── translator.py          ← mapea instrucciones a expresiones C
├── register_map.py        ← registros → tipos C + expresiones de cast
├── calling_convention.py  ← ABI: registros de args, retorno, syscall
├── instruction_sem.py     ← clasificación de mnemonicos + detección de prólogos/epílogos
└── syscall_table.py       ← carga el JSON de syscalls correspondiente
```

`arch/cortexm/` no tiene `register_map.py`, `calling_convention.py`, `instruction_sem.py` ni `syscall_table.py` porque hereda de `arm32` y solo sobreescribe lo que cambia (bare-metal, Thumb-2, vector table).

### Cómo se selecciona la arquitectura

`flashback/ui/cli.py`:

```python
def _detect_arch(binary_path) -> str:
    elf = lief.parse(binary_path)
    arch = elf.header.machine_type
    if arch == lief.ELF.ARCH.X86_64:  return 'x86_64'
    if arch == lief.ELF.ARCH.AARCH64: return 'arm64'
    if arch == lief.ELF.ARCH.I386:    return 'x86'
    if arch == lief.ELF.ARCH.ARM:
        # Cortex-M: Thumb bit en entry + sin .dynamic (firmware bare-metal)
        if elf.entrypoint & 1 and not elf.get_section('.dynamic'):
            return 'cortexm'
        return 'arm32'
```

### Detalles por módulo

#### `disassembler.py`

Responsable de:
- Parsear el ELF con lief: símbolos de función, entradas PLT, contenido de secciones
- Desensamblar las secciones ejecutables con capstone
- Devolver `(dict[int, RawInstruction], BinaryMeta)`

Cada arquitectura implementa su propia estrategia de descubrimiento de PLT:

| Arquitectura | Estrategia PLT |
|---|---|
| x86_64 | `jmp QWORD PTR [rip+offset]` → reloc GOT |
| x86 | `jmp DWORD PTR [abs_got_addr]` → reloc GOT |
| arm64 | `adrp + ldr + br` → reloc GOT |
| arm32 | Stride 20+12n bytes → pltgot_relocations ordenadas |
| cortexm | Sin PLT (sin dynamic linker) |

**Cortex-M específico:** usa `CS_MODE_THUMB | CS_MODE_MCLASS` (obligatorio para MRS/MSR a registros especiales como xPSR, MSP, PSP). Desensambla función a función para saltar los literal pools incrustados entre funciones en `.text`.

#### `enricher.py`

Añade anotaciones al CFG. El flujo base es:

1. `_annotate_external_calls()` — detecta `call`/`bl`/`blx` a PLT → `ExternalCallAnnotation`
2. `_annotate_syscalls()` — detecta `syscall`/`svc`/`int 0x80` → `SyscallAnnotation`
3. `_resolve_indirect_calls()` *(x86_64 únicamente, Fase 2)* — backward slice local para `call REG` → `ResolvedIndirectAnnotation`
4. `_classify_blocks()` — categoriza cada bloque
5. `_annotate_trace_recommendations()` — decide granularidad por bloque según política
6. `_annotate_trace_points()` — materializa las recomendaciones en `TracePointAnnotation`

`CortexMEnricher` hereda de `Arm32Enricher` y hace no-op en los pasos 1 y 2 (no hay PLT ni syscalls Linux en bare-metal). Añade categoría `irq_handler` para funciones del vector table.

#### `translator.py`

Genera el código C completo. La estructura del fichero generado:

```
1. Cabecera (comentario con sha256, entry point, arquitectura)
2. #includes
3. Macros de portabilidad (SIM_READ32, SIM_WRITE64, etc.)
4. Declaraciones forward de todas las funciones
5. Registros simulados (uint64_t rax, uint32_t r0, etc.)
6. Flags simulados (uint8_t ZF, N, C, V, etc.)
7. Sección .rodata embebida (si existe)
8. Sección .data embebida (si existe)
9. Sección .bss simulada (array estático o malloc)
10. Runtime de trazabilidad (__trace, __trace_dump)
11. Stack y heap simulados
12. __sim_addr() — mapeador de direcciones virtuales a memoria del proceso
13. Implementación de cada función
14. main() de entrada
```

## Jerarquía de herencia

```
Disassembler (ABC)
├── X86_64Disassembler
├── X86Disassembler
├── Arm64Disassembler
├── Arm32Disassembler
│   └── CortexMDisassembler   ← sobreescribe _disassemble() y _find_plt_symbols()

Enricher (ABC)
├── X86_64Enricher
├── X86Enricher
├── Arm64Enricher
├── Arm32Enricher
│   └── CortexMEnricher       ← sobreescribe _annotate_external_calls/syscalls()

Translator (clase base, no ABC — tiene implementación x86_64 por defecto)
├── X86Translator             ← registros 32-bit, cdecl
├── Arm64Translator           ← registros x0-x30, AAPCS64
├── Arm32Translator           ← registros r0-r15, AAPCS
│   └── CortexMTranslator     ← entry point bare-metal, registros especiales Cortex-M
```

`Translator` es heredado directamente por `X86_64Disassembler` (el pipeline x86_64 usa `Translator` base, que implementa la ISA x86-64 completa).

## Añadir una nueva arquitectura

1. Crear `flashback/arch/<nueva>/` con los 7 módulos
2. Implementar `<Nueva>Disassembler(Disassembler)`, `<Nueva>Enricher(Enricher)`, `<Nueva>Translator(Translator)`
3. Definir `_<nueva>_MNEMONICS = ArchMnemonics(...)` en el disassembler
4. Añadir la arquitectura a `_detect_arch()` y `_build_pipeline()` en `cli.py`
5. Añadir `'<nueva>'` al `Literal` de `BinaryInfo.architecture` en `models.py`
6. Si hay syscalls, añadir `flashback/data/syscalls_<nueva>.json`

La interfaz mínima que debe implementar el disassembler es:

```python
def disassemble(self, binary_path: str) -> EnrichedCFG:
    raw_insns, meta = self.load(binary_path)
    return CFGBuilder(arch_mnemonics=_ARCH_MNEMONICS).build(raw_insns, meta)

def load(self, binary_path: str) -> tuple[dict[int, RawInstruction], BinaryMeta]:
    ...
```

## Notas de rendimiento

Para binarios grandes (>100K instrucciones):

- `deepcopy(cfg)` en los enrichers es el principal cuello de botella. `CortexMEnricher` anota in-place para evitarlo.
- `CFGBuilder._assign_blocks_to_functions()` usa `bisect` — O(n log m) en lugar de O(n×m).
- `CFGBuilder._fill_call_relations()` y `_build_edges()` usan lookup O(1) por clave entera en `raw_insns`.

Tiempos de referencia para `arducopter.elf` (STM32 Cortex-M7, 1.38 MB de código Thumb-2):

| Etapa | Tiempo |
|---|---|
| Disassembly (391K instrucciones) | ~3 s |
| CFGBuilder (81K bloques) | ~6 s |
| Enricher | ~1 s |
| Translator (1.2M líneas de C) | ~2 s |
| **Total** | **~12 s** |

## Resolución de saltos indirectos (x86-64)

Flashback implementa dos fases de resolución estática para saltos/llamadas indirectas en x86-64. Ambas son **heurísticas de mejor esfuerzo**: no reemplazan un análisis formal, pero recuperan la mayoría de los casos generados por GCC y Clang a nivel de compilación.

### Fase 1 — Tablas de salto switch-case

**Cuándo se activa:** instrucciones `jmp` con operando de memoria indexada.

**Patrones detectados:**

| Patrón | Ejemplo | Descripción |
|---|---|---|
| P1 – Indexado absoluto (no-PIE) | `jmp qword ptr [rax*8 + 0x402000]` | `rax` es el índice; `0x402000` apunta a la tabla en `.rodata` |
| P2 – RIP+movsxd (PIE, GCC) | `lea rdx,[rip+off]; movsxd rax,[rdx+rcx*4]; add rdx,rax; jmp rdx` | Backward scan busca el `lea` para extraer la dirección base de la tabla |
| P3 – Base+índice (GCC O2) | `jmp qword ptr [rdx + rax*8]` | Backward scan busca `lea rdx,[rip+off]` en instrucciones anteriores |

**Formato de tabla:**
- No-PIE: punteros de 64 bits absolutos en `.rodata`/`.data`
- PIE: offsets de 32 bits con signo relativos a la dirección base de la tabla

**Salida:** `JumpTableAnnotation` en la instrucción `jmp`, con `index_register`, `base_address` y `targets[]`. El `CFGBuilder` usa `meta.jump_tables` para identificar los inicios de bloque de cada destino y calcular los sucesores correctamente. El `Translator` genera un `switch()` C con un `case i: goto block_ADDR` por destino.

**Limitación PIE:** los binarios con PIE (Position Independent Executable) que usen offsets relativos a un punto de referencia distinto a la base de la tabla no se resuelven correctamente. Los ejecutables compilados con `-no-pie` están completamente cubiertos.

### Fase 2 — Backward slice local para llamadas indirectas

**Cuándo se activa:** instrucciones `call REG` donde `REG` es un registro de propósito general.

**Algoritmo:** para cada `call REG` en un bloque, el enricher (`X86_64Enricher._resolve_indirect_calls`) recorre hacia atrás las instrucciones del mismo bloque hasta encontrar la última escritura de `REG`. Si esa escritura es `mov REG, IMM` o `movabs REG, IMM` y el valor `IMM` corresponde a una función conocida en el CFG, anota con `ResolvedIndirectAnnotation`.

**Salida:** `ResolvedIndirectAnnotation` en la instrucción `call`, con `resolved_target` (dirección hex de la función) y `method='backslice_local'`. El `Translator` usa esta anotación para emitir `func_ADDR()` en lugar del comentario `/* INDIRECT CALL */`.

### Limitación: Value Set Analysis (VSA) fuera de alcance

Las dos fases anteriores cubren los patrones generados por compiladores a nivel de instrucción única o dentro de un bloque básico. La resolución de casos más complejos requiere **Value Set Analysis (VSA)**, una forma de interpretación abstracta que propaga rangos de valores a través de todos los bloques del CFG y entre funciones.

VSA está deliberadamente fuera del alcance de Flashback por las siguientes razones:

1. **Complejidad algorítmica:** un análisis de punto fijo correcto sobre grafos de llamadas completos tiene coste prohibitivo para binarios grandes (>100K instrucciones).
2. **Dependencia de alias analysis:** resolver `call [rsp+8]` o `jmp [rbx+rcx*8]` requiere razonar sobre el alias de punteros en memoria, que a su vez depende del estado del heap y la pila en cada punto del programa.
3. **Scope de la herramienta:** Flashback prioriza la reconstrucción de código ejecutable sobre el análisis semántico profundo. Los saltos indirectos no resueltos se emiten como `/* INDIRECT CALL: ops — sin resolver */` o `/* UNSUPPORTED: salto indirecto */` para preservar la trazabilidad.

Herramientas como BAP (Binary Analysis Platform), angr o Ghidra implementan formas de VSA y pueden complementar el análisis de Flashback cuando se necesita resolución exhaustiva.

## Limitaciones conocidas

| Limitación | Aplica a |
|---|---|
| Saltos indirectos multi-bloque (VSA) sin resolver — ver sección anterior | Todas |
| Tablas de salto PIE con punto de referencia distinto a la base de la tabla | x86_64 (PIE) |
| Backward slice solo dentro del mismo bloque básico (no inter-bloque) | x86_64 Fase 2 |
| Sin recuperación de tipos (structs, clases, arrays) | Todas |
| Sin análisis de dataflow inter-bloque | Todas |
| Sin soporte SIMD/AVX/NEON/VFP (instrucciones comentadas) | x86_64, arm64, cortexm |
| Solo formato ELF (no PE, Mach-O) | Todas |
| Heurísticas de function discovery basadas en símbolos | Todas (binarios stripped son parciales) |
| Cortex-M: VFP/FPU comentado como `[VFP/FPU — no simulado]` | cortexm |
| arm32: código Thumb en binarios Linux userspace puede requerir `--arch arm32` explícito | arm32 |
