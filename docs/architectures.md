# Referencia por arquitectura

## x86-64

**`--arch x86_64`** · Auto-detectado: `e_machine == EM_X86_64`

| Elemento | Detalle |
|---|---|
| Capstone | `CS_ARCH_X86 / CS_MODE_64` |
| Registros | `uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15` |
| Aliases 32-bit | `eax = (uint32_t)rax` (macro) |
| Flags | `uint8_t ZF, SF, CF, OF, PF` |
| ABI | System V AMD64: args rdi, rsi, rdx, rcx, r8, r9 |
| Retorno | `rax` |
| Syscall | `syscall` — número en `rax`, args en rdi/rsi/rdx/r10/r8/r9 |
| PLT | `jmp QWORD PTR [rip+offset]` — reloc GOT RIP-relativa |
| Entry point en C | `int main(int argc, char **argv)` — rsp alineado 16 bytes |
| Datos syscalls | `data/syscalls_x86_64.json` |

Instrucciones traducidas: mov/movsx/movzx, add/sub/and/or/xor/not/neg, imul/mul/div/idiv, lea, push/pop, cmp/test, jcc, call/ret, syscall, leave, cdq/cqo, cmovcc, rep movs/stos, nop.

---

## x86 (i386)

**`--arch x86`** · Auto-detectado: `e_machine == EM_386`

| Elemento | Detalle |
|---|---|
| Capstone | `CS_ARCH_X86 / CS_MODE_32` |
| Registros | `uint32_t eax, ebx, ecx, edx, esi, edi, esp, ebp` |
| Flags | `uint8_t ZF, SF, CF, OF, PF` |
| ABI | cdecl: args en pila (esp+4, esp+8, ...) |
| Retorno | `eax` |
| Syscall | `int 0x80` — número en `eax`, args en ebx/ecx/edx/esi/edi/ebp |
| PLT | `jmp DWORD PTR [abs_addr]` — reloc GOT absoluta |
| Entry point en C | `int main(int argc, char **argv)` — args en pila |
| Datos syscalls | `data/syscalls_x86.json` |

Las instrucciones son un subconjunto de x86-64 sin registros extendidos (r8-r15, REX prefix). Las operaciones de 16 y 8 bits se emulan con casts.

---

## AArch64 (ARM64)

**`--arch arm64`** · Auto-detectado: `e_machine == EM_AARCH64`

| Elemento | Detalle |
|---|---|
| Capstone | `CS_ARCH_ARM64 / CS_MODE_ARM` |
| Registros | `uint64_t x0-x30, sp, pc` |
| Aliases 32-bit | `uint32_t w0 = (uint32_t)x0` (macro) |
| Registros especiales | `xzr = 0` (zero register, siempre cero) |
| Flags | `uint8_t N, Z, C, V` (NZCV) |
| ABI | AAPCS64: args x0-x7, retorno x0, frame x29/x30 |
| Syscall | `svc #0` — número en `x8`, args en x0-x5 |
| PLT | `adrp xN, page + ldr xN, [xN, #offset] + br xN` |
| Entry point en C | `int main(int argc, char **argv)` — x0=argc, x1=argv |
| Datos syscalls | `data/syscalls_arm64.json` |

Instrucciones: mov/movz/movk/movn, add/sub/and/orr/eor/bic, ldr/str (escalares + pares ldp/stp), b/bl/blr/ret, cbz/cbnz, tbnz/tbz, csel/cset, sxtw/uxtw, adrp+ldr (para acceso a GOT), lsl/lsr/asr/ror.

---

## ARM32 (ARMv7 Linux userspace)

**`--arch arm32`** · Auto-detectado: `e_machine == EM_ARM` + sin Thumb bit en entry, o con `.dynamic`

| Elemento | Detalle |
|---|---|
| Capstone | `CS_ARCH_ARM / CS_MODE_ARM` o `CS_MODE_THUMB` (heurística por sección) |
| Registros | `uint32_t r0-r15` |
| Aliases | `sp=r13`, `lr=r14`, `pc=r15`, `ip=r12`, `fp=r11`, `sl=r10` (macros) |
| Flags | `uint8_t N, Z, C, V` |
| ABI | AAPCS: args r0-r3, retorno r0, extra en pila |
| Syscall | `svc #0` (EABI) — número en `r7`, args en r0-r5 |
| PLT | Stride 20 bytes (header) + 12 bytes por stub → pltgot_relocations |
| Entry point en C | `int main(int argc, char **argv)` — r0=argc, r1=argv |
| Thumb bit | Strips del valor de símbolo: `addr = sym.value & ~1` |
| Datos syscalls | `data/syscalls_arm32.json` |

Los mnemónicos ARM32 llevan sufijo de condición (`beq`, `bne`, `addlt`, etc.). El traductor detecta el sufijo con `_strip_condition()` y envuelve la instrucción en `if (cond) { ... }`. Los bloques `ldm`/`stm` (y `push`/`pop`) se expanden a secuencias de `SIM_READ32`/`SIM_WRITE32`.

---

## Cortex-M (ARM bare-metal)

**`--arch cortexm`** · Auto-detectado: `e_machine == EM_ARM` + Thumb bit en entry + sin `.dynamic`

| Elemento | Detalle |
|---|---|
| Capstone | `CS_ARCH_ARM / CS_MODE_THUMB | CS_MODE_MCLASS` |
| Registros | `uint32_t r0-r15` (igual que arm32) |
| Registros especiales | `uint32_t msp, psp, xpsr, control, primask, basepri, faultmask` |
| Flags | `uint8_t N, Z, C, V` |
| ABI | Sin OS — bare-metal |
| Syscall | Sin syscalls de SO |
| PLT | Sin PLT (sin dynamic linker) |
| Entry point en C | `int main(void)` → llama a `Reset_Handler` con MSP del vector table |
| Vector table | Sección `startup`/`.isr_vector`: word[0]=SP inicial, word[1+]=IRQ handlers |
| Datos syscalls | — |

### Por qué `CS_MODE_MCLASS` es obligatorio

Sin este flag, capstone no puede decodificar instrucciones que acceden a registros especiales Cortex-M (`MRS r3, xPSR`, `MSR basepri, r0`, etc.). El primer byte no decodificable detiene la disassembly lineal.

### Literal pools y disassembly por función

El código Thumb incrusta tablas de constantes (literal pools) entre funciones dentro de `.text`. La disassembly lineal se detiene al encontrar estos datos. La solución: desensamblar tramo a tramo usando las direcciones de los símbolos ELF como puntos de reinicio.

```
función A → literal pool A → función B → literal pool B → ...
            ^-- capstone para aquí
                             ^-- reiniciar aquí desde símbolo B
```

### Traducción de instrucciones específicas

| Instrucción Cortex-M | Traducción C |
|---|---|
| `mrs r0, xpsr` | `r0 = xpsr;` |
| `msr basepri, r3` | `basepri = r3;` |
| `cpsid i` | `primask = 1; /* CPSID i — disable IRQ */` |
| `cpsie i` | `primask = 0; /* CPSIE i — enable IRQ */` |
| `dmb` / `dsb` / `isb` | `/* dmb — memory barrier (nop en simulación) */` |
| `wfi` / `wfe` | `/* wfi — wait for interrupt (nop en simulación) */` |
| `cbz r0, #target` | `if (!r0) goto label_target;` |
| `cbnz r0, #target` | `if (r0) goto label_target;` |
| `vldr s0, [r0]` | `/* vldr s0, [r0]  [VFP/FPU — no simulado] */` |
| `bkpt #0` | `/* bkpt 0 — breakpoint */` |

Las instrucciones VFP/FPU (`vldr`, `vstr`, `vadd`, `vmul`, `vmrs`, etc.) se comentan porque requieren un coprocesador flotante que la simulación en C no modela. En ArduPilot (~62 000 instrucciones VFP en arducopter.elf), esto afecta principalmente a cálculos de navegación y PID.

### Entry point generado

```c
/* Punto de entrada Cortex-M — firmware bare-metal */
/* El hardware inicializa MSP y llama a Reset_Handler */
int main(void) {
    /* MSP inicial del vector table: 0x30000600 */
    r13 = (uint32_t)(uintptr_t)(__sim_stack + SIM_STACK_SIZE - 4);
    r13 &= ~(uint32_t)0x7U;
    msp = r13;
    func_8020d8c();  /* Reset_Handler @ 0x8020d8c */
    for (;;);  /* el firmware no retorna */
    return 0;
}
```

---

## Comparativa de tablas de syscalls

Los ficheros JSON tienen la estructura:

```json
{
  "1": { "name": "exit",  "args": ["r0"], "description": "Termina el proceso" },
  "3": { "name": "read",  "args": ["r0", "r1", "r2"] },
  ...
}
```

La clave es el número de syscall como string. Los registros de args coinciden con la convención de cada arquitectura.

| Archivo | Arquitectura | Interfaz | Nº syscalls documentados |
|---|---|---|---|
| `syscalls_x86_64.json` | x86-64 | `syscall` | 40+ |
| `syscalls_x86.json` | i386 | `int 0x80` | 35+ |
| `syscalls_arm64.json` | AArch64 | `svc #0` | 40+ |
| `syscalls_arm32.json` | ARMv7 | `svc #0` (EABI) | 55+ |
