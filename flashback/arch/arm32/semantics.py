"""
Semántica de instrucciones ARM / Thumb-2 (incluida VFP) → sentencias C.

Traduce una instrucción ARM ya desensamblada (mnemónico + operandos en sintaxis
UAL de capstone) a C que opera sobre el estado simulado:

  r0..r15         registros enteros (uint32_t)
  N, Z, C, V      flags de APSR
  __s[0..63]      banco VFP: s<n> = __s[n]; d<n> = __s[2n] (bajo) y __s[2n+1]
                  (alto), igual que en el hardware (d16..d31 solo en VFPv3-D32)
  __fpscr         FPSCR (los flags NZCV de las comparaciones VFP en bits 31..28)
  __ge            flags GE de las instrucciones SIMD (uadd8 / sel)

El runtime C que necesitan estas sentencias (helpers de flags, desplazamientos,
conversiones VFP) está en C_RUNTIME. Los accesos a memoria usan las macros
SIM_READ*/SIM_WRITE* del translator; los saltos y llamadas a registro usan
__call_indirect(target, site), que el translator define como despachador.

Detalles de semántica relevantes:
  - Sufijo 's' (flag-setting) frente a condición: 'movs' es mov+S, no mo+vs.
  - Los flags de suma/resta (incluido el carry de adc/sbc/rsb) y el carry de
    salida del desplazador en las operaciones lógicas siguen el ARM ARM.
  - Lecturas de pc: Thumb → dirección + 4 (alineada a 4 en adr, add pc/imm y
    literales); ARM → dirección + 8.
  - Las cargas desde literal pools se resuelven a su valor constante cuando la
    instrucción lleva la anotación literal_load.
  - Ignorado a propósito: flag Q (saturación), excepciones de coma flotante y
    los modos flush-to-zero / default-NaN de FPSCR.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from flashback.arch.arm32.instruction_sem import ARM32_COND_TO_C

# ---------------------------------------------------------------------------
# Runtime C
# ---------------------------------------------------------------------------

C_RUNTIME = r'''/* ---- Runtime de semántica ARM / Thumb-2 / VFP ---- */
static uint8_t  __shc = 0;      /* carry de salida del desplazador */
static uint8_t  __ge  = 0;      /* flags GE (SIMD) */
static uint32_t __s[64];        /* banco VFP: s0..s31 / d0..d31 (d<n> = s<2n>:s<2n+1>) */
static uint32_t __fpscr = 0;    /* FPSCR */
static uint8_t  __excl  = 0;    /* monitor exclusivo local (ldrex/strex) */

/* Suma con carry; actualiza NZCV (adds, adcs, subs, sbcs, rsbs, cmp, cmn) */
static inline uint32_t __addc(uint32_t a_, uint32_t b_, uint32_t c_) {
    uint64_t r_ = (uint64_t)a_ + b_ + c_;
    uint32_t r32_ = (uint32_t)r_;
    N = (uint8_t)(r32_ >> 31); Z = (uint8_t)(r32_ == 0);
    C = (uint8_t)(r_ >> 32);
    V = (uint8_t)(((~(a_ ^ b_)) & (a_ ^ r32_)) >> 31);
    return r32_;
}
static inline uint32_t __nz(uint32_t r_) { N = (uint8_t)(r_ >> 31); Z = (uint8_t)(r_ == 0); return r_; }
static inline uint32_t __nzc(uint32_t r_) { __nz(r_); C = __shc; return r_; }

/* Desplazamientos con carry de salida (__shc); n = byte bajo del desplazamiento */
static inline uint32_t __lsl(uint32_t x_, uint32_t n_) {
    n_ &= 0xffu;
    if (n_ == 0) { __shc = C; return x_; }
    if (n_ < 32) { __shc = (uint8_t)((x_ >> (32 - n_)) & 1u); return x_ << n_; }
    __shc = (uint8_t)(n_ == 32 ? (x_ & 1u) : 0); return 0;
}
static inline uint32_t __lsr(uint32_t x_, uint32_t n_) {
    n_ &= 0xffu;
    if (n_ == 0) { __shc = C; return x_; }
    if (n_ < 32) { __shc = (uint8_t)((x_ >> (n_ - 1)) & 1u); return x_ >> n_; }
    __shc = (uint8_t)(n_ == 32 ? (x_ >> 31) : 0); return 0;
}
static inline uint32_t __asr(uint32_t x_, uint32_t n_) {
    n_ &= 0xffu;
    if (n_ == 0) { __shc = C; return x_; }
    if (n_ < 32) { __shc = (uint8_t)((x_ >> (n_ - 1)) & 1u); return (uint32_t)((int32_t)x_ >> n_); }
    __shc = (uint8_t)(x_ >> 31); return (x_ >> 31) ? 0xffffffffu : 0u;
}
static inline uint32_t __ror(uint32_t x_, uint32_t n_) {
    if ((n_ & 0xffu) == 0) { __shc = C; return x_; }
    n_ &= 31u;
    uint32_t r_ = n_ ? ((x_ >> n_) | (x_ << (32 - n_))) : x_;
    __shc = (uint8_t)(r_ >> 31); return r_;
}
static inline uint32_t __rrx(uint32_t x_) {
    __shc = (uint8_t)(x_ & 1u); return (x_ >> 1) | ((uint32_t)C << 31);
}
static inline uint32_t __rot(uint32_t x_, uint32_t n_) {   /* rotación sin flags */
    n_ &= 31u; return n_ ? ((x_ >> n_) | (x_ << (32 - n_))) : x_;
}
static inline uint32_t __rbit(uint32_t x_) {
    uint32_t r_ = 0; for (int i_ = 0; i_ < 32; i_++) { r_ = (r_ << 1) | (x_ & 1u); x_ >>= 1; }
    return r_;
}
static inline uint32_t __clz(uint32_t x_) { return x_ ? (uint32_t)__builtin_clz(x_) : 32u; }
static inline uint32_t __usat(int64_t v_, unsigned n_) {
    int64_t hi_ = (n_ >= 32) ? 0xffffffffLL : (int64_t)((1ULL << n_) - 1);
    return (uint32_t)(v_ < 0 ? 0 : (v_ > hi_ ? hi_ : v_));
}
static inline uint32_t __ssat(int64_t v_, unsigned n_) {
    int64_t hi_ = (int64_t)((1ULL << (n_ - 1)) - 1), lo_ = -hi_ - 1;
    return (uint32_t)(int32_t)(v_ < lo_ ? lo_ : (v_ > hi_ ? hi_ : v_));
}
static inline uint32_t __sdiv(uint32_t a_, uint32_t b_) {
    if (b_ == 0) return 0;                      /* Cortex-M con DIV_0_TRP = 0 */
    if (a_ == 0x80000000u && b_ == 0xffffffffu) return a_;
    return (uint32_t)((int32_t)a_ / (int32_t)b_);
}
static inline uint32_t __udiv(uint32_t a_, uint32_t b_) { return b_ ? a_ / b_ : 0; }
static inline uint32_t __uadd8(uint32_t a_, uint32_t b_) {
    uint32_t r_ = 0; __ge = 0;
    for (int i_ = 0; i_ < 4; i_++) {
        uint32_t s_ = ((a_ >> (8 * i_)) & 0xffu) + ((b_ >> (8 * i_)) & 0xffu);
        r_ |= (s_ & 0xffu) << (8 * i_);
        if (s_ >= 0x100u) __ge |= (uint8_t)(1u << i_);
    }
    return r_;
}
static inline uint32_t __sel(uint32_t a_, uint32_t b_) {
    uint32_t r_ = 0;
    for (int i_ = 0; i_ < 4; i_++)
        r_ |= (((__ge >> i_) & 1u) ? a_ : b_) & (0xffu << (8 * i_));
    return r_;
}

/* Banco VFP */
static inline float  __getf(int n_) { float f_; memcpy(&f_, &__s[n_], 4); return f_; }
static inline void   __setf(int n_, float f_) { memcpy(&__s[n_], &f_, 4); }
static inline double __getd(int n_) { double d_; memcpy(&d_, &__s[2 * n_], 8); return d_; }
static inline void   __setd(int n_, double d_) { memcpy(&__s[2 * n_], &d_, 8); }
/* Aritmética VFP con las reglas de NaN de ARM (FPSCR.DN = 0):
   - un NaN de entrada se propaga (sNaN antes que qNaN, en orden de operandos),
     silenciado (bit 22 / bit 51 a 1);
   - una operación inválida sin NaN de entrada produce el NaN por defecto
     0x7fc00000 / 0x7ff8000000000000 (x86 produciría uno negativo). */
static inline uint32_t __fbits(float f_) { uint32_t u_; memcpy(&u_, &f_, 4); return u_; }
static inline float __fbitsf(uint32_t u_) { float f_; memcpy(&f_, &u_, 4); return f_; }
static inline uint64_t __dbits(double d_) { uint64_t u_; memcpy(&u_, &d_, 8); return u_; }
static inline double __dbitsd(uint64_t u_) { double d_; memcpy(&d_, &u_, 8); return d_; }
static inline int __fsnan(float f_) { uint32_t u_ = __fbits(f_); return f_ != f_ && !(u_ & 0x400000u); }
static inline int __dsnan(double d_) { uint64_t u_ = __dbits(d_); return d_ != d_ && !(u_ & 0x8000000000000ULL); }
static inline float  __fquiet(float f_)  { return __fbitsf(__fbits(f_) | 0x400000u); }
static inline double __dquiet(double d_) { return __dbitsd(__dbits(d_) | 0x8000000000000ULL); }
static inline float  __fdef(float r_)  { return r_ != r_ ? __fbitsf(0x7fc00000u) : r_; }
static inline double __ddef(double r_) { return r_ != r_ ? __dbitsd(0x7ff8000000000000ULL) : r_; }
static inline int __fnan3(float a_, float b_, float c_, int n_, float *r_) {
    float v_[3] = {a_, b_, c_};
    for (int i_ = 0; i_ < n_; i_++) if (__fsnan(v_[i_])) { *r_ = __fquiet(v_[i_]); return 1; }
    for (int i_ = 0; i_ < n_; i_++) if (v_[i_] != v_[i_]) { *r_ = v_[i_]; return 1; }
    return 0;
}
static inline int __dnan3(double a_, double b_, double c_, int n_, double *r_) {
    double v_[3] = {a_, b_, c_};
    for (int i_ = 0; i_ < n_; i_++) if (__dsnan(v_[i_])) { *r_ = __dquiet(v_[i_]); return 1; }
    for (int i_ = 0; i_ < n_; i_++) if (v_[i_] != v_[i_]) { *r_ = v_[i_]; return 1; }
    return 0;
}
#define __VFP_BIN(name_, T_, sfx_, op_) \
    static inline T_ name_##sfx_(T_ a_, T_ b_) { T_ r_; \
        if (__##sfx_##nan3(a_, b_, 0, 2, &r_)) return r_; return __##sfx_##def(op_); }
__VFP_BIN(__vadd, float, f, a_ + b_)  __VFP_BIN(__vadd, double, d, a_ + b_)
__VFP_BIN(__vsub, float, f, a_ - b_)  __VFP_BIN(__vsub, double, d, a_ - b_)
__VFP_BIN(__vmul, float, f, a_ * b_)  __VFP_BIN(__vmul, double, d, a_ * b_)
__VFP_BIN(__vdiv, float, f, a_ / b_)  __VFP_BIN(__vdiv, double, d, a_ / b_)
/* fma ARM: FPMulAdd(addend, op1, op2) procesa los NaN en ese orden */
static inline float __vfmaf(float acc_, float a_, float b_) {
    float r_; if (__fnan3(acc_, a_, b_, 3, &r_)) return r_; return __fdef(fmaf(a_, b_, acc_));
}
static inline double __vfmad(double acc_, double a_, double b_) {
    double r_; if (__dnan3(acc_, a_, b_, 3, &r_)) return r_; return __ddef(fma(a_, b_, acc_));
}
static inline float  __vsqrtf(float a_)  { return a_ != a_ ? (__fsnan(a_) ? __fquiet(a_) : a_) : __fdef(sqrtf(a_)); }
static inline double __vsqrtd(double a_) { return a_ != a_ ? (__dsnan(a_) ? __dquiet(a_) : a_) : __ddef(sqrt(a_)); }
/* vmaxnm / vminnm (maxNum/minNum IEEE 754-2008; +0 > -0) */
static inline float __vmaxnmf(float a_, float b_) {
    float r_; if (__fsnan(a_) || __fsnan(b_)) { __fnan3(a_, b_, 0, 2, &r_); return r_; }
    if (a_ != a_) return b_; if (b_ != b_) return a_;
    if (a_ == b_) return __fbitsf(__fbits(a_) & __fbits(b_)); return a_ > b_ ? a_ : b_;
}
static inline float __vminnmf(float a_, float b_) {
    float r_; if (__fsnan(a_) || __fsnan(b_)) { __fnan3(a_, b_, 0, 2, &r_); return r_; }
    if (a_ != a_) return b_; if (b_ != b_) return a_;
    if (a_ == b_) return __fbitsf(__fbits(a_) | __fbits(b_)); return a_ < b_ ? a_ : b_;
}
static inline double __vmaxnmd(double a_, double b_) {
    double r_; if (__dsnan(a_) || __dsnan(b_)) { __dnan3(a_, b_, 0, 2, &r_); return r_; }
    if (a_ != a_) return b_; if (b_ != b_) return a_;
    if (a_ == b_) return __dbitsd(__dbits(a_) & __dbits(b_)); return a_ > b_ ? a_ : b_;
}
static inline double __vminnmd(double a_, double b_) {
    double r_; if (__dsnan(a_) || __dsnan(b_)) { __dnan3(a_, b_, 0, 2, &r_); return r_; }
    if (a_ != a_) return b_; if (b_ != b_) return a_;
    if (a_ == b_) return __dbitsd(__dbits(a_) | __dbits(b_)); return a_ < b_ ? a_ : b_;
}
/* vcmp / vcmpe: NZCV de FPSCR */
static inline void __vcmp(double a_, double b_) {
    uint32_t f_;
    if (a_ != a_ || b_ != b_) f_ = 0x3u;        /* no ordenados: C=1 V=1 */
    else if (a_ == b_)        f_ = 0x6u;        /* Z=1 C=1 */
    else if (a_ < b_)         f_ = 0x8u;        /* N=1 */
    else                      f_ = 0x2u;        /* C=1 */
    __fpscr = (__fpscr & 0x0fffffffu) | (f_ << 28);
}
/* vcvt a entero: trunca (o redondea según el modo ya aplicado), satura, NaN → 0 */
static inline uint32_t __f2s32(double x_) {
    if (x_ != x_) return 0;
    if (x_ >= 2147483647.0) return 0x7fffffffu;
    if (x_ <= -2147483648.0) return 0x80000000u;
    return (uint32_t)(int32_t)x_;
}
static inline uint32_t __f2u32(double x_) {
    if (x_ != x_ || x_ <= 0.0) return 0;
    if (x_ >= 4294967295.0) return 0xffffffffu;
    return (uint32_t)x_;
}
/* ---- fin del runtime ARM ---- */'''


# Flags NZCV ↔ palabra APSR (bits 31..28)
APSR_PACK = ('((uint32_t)N << 31) | ((uint32_t)Z << 30) | '
             '((uint32_t)C << 29) | ((uint32_t)V << 28)')


def apsr_unpack(expr: str) -> str:
    return (f'{{ uint32_t __f = {expr}; N = (uint8_t)(__f >> 31); '
            f'Z = (uint8_t)((__f >> 30) & 1u); C = (uint8_t)((__f >> 29) & 1u); '
            f'V = (uint8_t)((__f >> 28) & 1u); }}')


# ---------------------------------------------------------------------------
# Mnemónicos
# ---------------------------------------------------------------------------

_CONDS = frozenset(c for c in ARM32_COND_TO_C if c != 'al')

# Instrucciones enteras soportadas (base, sin sufijos)
_DP_LOGIC = {'and': '&', 'orr': '|', 'eor': '^', 'bic': '&~', 'orn': '|~'}
_DP_ARITH = frozenset({'add', 'adc', 'sub', 'sbc', 'rsb', 'rsc'})
_SHIFTS = frozenset({'lsl', 'lsr', 'asr', 'ror', 'rrx'})
_LOADS = {
    'ldr': (4, False), 'ldrb': (1, False), 'ldrh': (2, False),
    'ldrsb': (1, True), 'ldrsh': (2, True),
    'ldrt': (4, False), 'ldrbt': (1, False), 'ldrht': (2, False),
    'ldrsbt': (1, True), 'ldrsht': (2, True),
    'ldrex': (4, False), 'ldrexb': (1, False), 'ldrexh': (2, False),
}
_STORES = {
    'str': 4, 'strb': 1, 'strh': 2, 'strt': 4, 'strbt': 1, 'strht': 2,
}
_STORE_EX = {'strex': 4, 'strexb': 1, 'strexh': 2}
_LDM = {'ldm': 'ia', 'ldmia': 'ia', 'ldmfd': 'ia', 'ldmdb': 'db', 'ldmea': 'db',
        'ldmib': 'ib', 'ldmed': 'ib', 'ldmda': 'da', 'ldmfa': 'da'}
_STM = {'stm': 'ia', 'stmia': 'ia', 'stmea': 'ia', 'stmdb': 'db', 'stmfd': 'db',
        'stmib': 'ib', 'stmfa': 'ib', 'stmda': 'da', 'stmed': 'da'}
_EXTEND = {'uxtb': ('uint8_t', False), 'uxth': ('uint16_t', False),
           'sxtb': ('int8_t', False), 'sxth': ('int16_t', False),
           'uxtab': ('uint8_t', True), 'uxtah': ('uint16_t', True),
           'sxtab': ('int8_t', True), 'sxtah': ('int16_t', True)}
_NOPS = frozenset({'nop', 'yield', 'sev', 'sevl', 'wfi', 'wfe', 'dmb', 'dsb', 'isb',
                   'pld', 'pldw', 'pli', 'csdb', 'ssbb', 'pssbb'})
_HALF_MUL = frozenset({'smulbb', 'smulbt', 'smultb', 'smultt',
                       'smlabb', 'smlabt', 'smlatb', 'smlatt',
                       'smulwb', 'smulwt', 'smlawb', 'smlawt'})

_INT_BASES = (
    set(_DP_LOGIC) | _DP_ARITH | _SHIFTS | set(_LOADS) | set(_STORES) | set(_STORE_EX)
    | set(_LDM) | set(_STM) | set(_EXTEND) | _NOPS | _HALF_MUL
    | {'mov', 'mvn', 'movw', 'movt', 'neg', 'cmp', 'cmn', 'tst', 'teq', 'adr', 'addw', 'subw',
       'mul', 'mla', 'mls', 'umull', 'smull', 'umlal', 'smlal', 'smmul', 'smmulr',
       'smmla', 'smmlar', 'smmls', 'smmlsr', 'udiv', 'sdiv',
       'clz', 'rbit', 'rev', 'rev16', 'revsh', 'uxtb16', 'sxtb16',
       'ubfx', 'sbfx', 'bfi', 'bfc', 'usat', 'ssat', 'uadd8', 'sel',
       'ldrd', 'strd', 'ldrexd', 'strexd', 'push', 'pop',
       'bx', 'bxj', 'blx', 'udf', 'bkpt', 'mrs', 'msr', 'clrex'}
)
# Bases que admiten el sufijo S (actualizan flags)
_S_BASES = (set(_DP_LOGIC) | _DP_ARITH | _SHIFTS
            | {'mov', 'mvn', 'neg', 'mul', 'mla', 'umull', 'smull', 'umlal', 'smlal'})

_VFP_BASES = frozenset({
    'vldr', 'vstr', 'vmov', 'vadd', 'vsub', 'vmul', 'vdiv', 'vnmul', 'vneg', 'vabs',
    'vsqrt', 'vfma', 'vfms', 'vfnma', 'vfnms', 'vmla', 'vmls', 'vnmla', 'vnmls',
    'vcmp', 'vcmpe', 'vmrs', 'vmsr', 'vcvt', 'vcvtr', 'vcvta', 'vcvtn', 'vcvtp', 'vcvtm',
    'vpush', 'vpop', 'vldmia', 'vldmdb', 'vstmia', 'vstmdb', 'vldm', 'vstm',
    'vmaxnm', 'vminnm', 'vrinta', 'vrintm', 'vrintp', 'vrintn', 'vrintz', 'vrintx', 'vrintr',
    'vseleq', 'vselge', 'vselgt', 'vselvs',
})


@dataclass(frozen=True)
class Mnemonic:
    base: str
    setflags: bool = False
    cond: str | None = None
    types: tuple[str, ...] = ()


def parse_mnemonic(mnemonic: str) -> Mnemonic | None:
    """
    Descompone un mnemónico UAL en base, sufijo S, condición y tipos de dato.

      'movs' → mov+S        'addseq.w' → add+S, eq     'lsls' → lsl+S
      'mls'  → mls          'ldrhs'    → ldr, hs       'vmovmi.f32' → vmov, mi, (f32)
    Devuelve None si la base no es conocida.
    """
    parts = mnemonic.lower().split('.')
    name = parts[0]
    types = tuple(t for t in parts[1:] if t not in ('w', 'n'))
    if name.startswith('v'):
        if name in _VFP_BASES:
            return Mnemonic(name, types=types)
        if name[-2:] in _CONDS and name[:-2] in _VFP_BASES:
            return Mnemonic(name[:-2], cond=name[-2:], types=types)
        return None
    for cond in (None, name[-2:] if name[-2:] in _CONDS else None):
        stem = name if cond is None else name[:-2]
        if stem in _INT_BASES:
            return Mnemonic(stem, False, cond, types)
        if stem.endswith('s') and stem[:-1] in _S_BASES:
            return Mnemonic(stem[:-1], True, cond, types)
        if cond is None and name[-2:] not in _CONDS:
            break
    return None


# ---------------------------------------------------------------------------
# Operandos
# ---------------------------------------------------------------------------

_ALIASES = {'sp': 'r13', 'lr': 'r14', 'pc': 'r15', 'ip': 'r12',
            'fp': 'r11', 'sl': 'r10', 'sb': 'r9'}
_REG_RE = re.compile(r'^r(1[0-5]|[0-9])$')
_SHIFT_RE = re.compile(r'^(lsl|lsr|asr|ror)\s+(#?\S+)$')


def split_operands(ops: str) -> list[str]:
    """Divide por comas de primer nivel (respeta [] y {})."""
    out, depth, cur = [], 0, ''
    for ch in ops:
        if ch in '[{':
            depth += 1
        elif ch in ']}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def reg(tok: str) -> str | None:
    t = tok.strip().lower().rstrip('!')
    t = _ALIASES.get(t, t)
    return t if _REG_RE.match(t) else None


def imm(tok: str) -> int | None:
    t = tok.strip().lower()
    if not t.startswith('#'):
        return None
    t = t[1:]
    try:
        return int(t, 0)
    except ValueError:
        return None


def _u32(v: int) -> str:
    return f'0x{v & 0xffffffff:x}U'


def _is_shift(tok: str) -> bool:
    t = tok.strip().lower()
    return t == 'rrx' or bool(_SHIFT_RE.match(t))


def _reglist(tok: str) -> list[str]:
    """'{r4, r5, lr}' → ['r4', 'r5', 'r14'] (con rangos r4-r7)."""
    inner = tok.strip()[1:-1]
    regs: list[str] = []
    for part in inner.split(','):
        part = part.strip().lower()
        if '-' in part:
            a, b = (x.strip() for x in part.split('-', 1))
            ra, rb = reg(a), reg(b)
            if ra and rb:
                regs.extend(f'r{i}' for i in range(int(ra[1:]), int(rb[1:]) + 1))
                continue
            return []
        r = reg(part)
        if r is None:
            return []
        regs.append(r)
    return regs


def _vfp_words(tok: str) -> list[int] | None:
    """'{s16, s17}' → [16, 17]; '{d8, d9}' → [16, 17, 18, 19]."""
    inner = tok.strip()[1:-1]
    words: list[int] = []
    for part in inner.split(','):
        part = part.strip().lower()
        if '-' in part:
            a, b = (x.strip() for x in part.split('-', 1))
            names = [f'{a[0]}{i}' for i in range(int(a[1:]), int(b[1:]) + 1)]
        else:
            names = [part]
        for n in names:
            if n[0] == 's' and n[1:].isdigit():
                words.append(int(n[1:]))
            elif n[0] == 'd' and n[1:].isdigit():
                words.extend((2 * int(n[1:]), 2 * int(n[1:]) + 1))
            else:
                return None
    return words


# ---------------------------------------------------------------------------
# Traductor
# ---------------------------------------------------------------------------

@dataclass
class InsnContext:
    address: int
    size: int
    thumb: bool
    literal: bytes | None = None        # bytes del literal (anotación literal_load)
    jump_table: bool = False            # la instrucción despacha una tabla resuelta


class _Unsupported(Exception):
    pass


def translate(mnemonic: str, operands: str, ctx: InsnContext) -> str | None:
    """Sentencia C para la instrucción, o None si no está soportada."""
    m = mnemonic.lower()
    if m.startswith('it') and set(m[2:]) <= {'t', 'e'}:
        return f'/* {m} {operands} — bloque IT: condición aplicada a las instrucciones siguientes */'
    mn = parse_mnemonic(m)
    if mn is None:
        return None
    try:
        body = _ArmSemantics(mn, split_operands(operands), ctx).emit()
    except (_Unsupported, ValueError, IndexError, TypeError):
        return None
    if body is None:
        return None
    if mn.cond:
        return f'if ({ARM32_COND_TO_C[mn.cond]}) {{ {body} }}'
    return body


class _ArmSemantics:
    def __init__(self, mn: Mnemonic, ops: list[str], ctx: InsnContext):
        self.mn = mn
        self.ops = ops
        self.ctx = ctx

    # -- utilidades -------------------------------------------------------

    @property
    def pc(self) -> int:
        return self.ctx.address + (4 if self.ctx.thumb else 8)

    @property
    def pc_aligned(self) -> int:
        return (self.pc & ~3) if self.ctx.thumb else self.pc

    def r(self, tok: str) -> str:
        """Expresión C de lectura de un registro (pc → constante)."""
        name = reg(tok)
        if name is None:
            raise _Unsupported(tok)
        return _u32(self.pc) if name == 'r15' else name

    def dst(self, tok: str) -> str:
        name = reg(tok)
        if name is None or name == 'r15':
            raise _Unsupported(tok)
        return name

    def value(self, tok: str) -> str:
        v = imm(tok)
        if v is not None:
            return _u32(v)
        return self.r(tok)

    def op2(self, toks: list[str]) -> tuple[str, bool]:
        """Operando flexible → (expresión, ¿actualiza __shc?)."""
        if not toks:
            raise _Unsupported('op2')
        v = imm(toks[0])
        if v is not None and len(toks) == 1:
            return _u32(v), False
        base = self.r(toks[0])
        if len(toks) == 1:
            return base, False
        sh = toks[1].strip().lower()
        if sh == 'rrx':
            return f'__rrx({base})', True
        m = _SHIFT_RE.match(sh)
        if not m:
            raise _Unsupported(sh)
        kind, amt = m.groups()
        a = imm(amt)
        amount = str(a) if a is not None else f'({self.r(amt)} & 0xffu)'
        if a == 0 and kind == 'lsl':
            return base, False
        return f'__{kind}({base}, {amount})', True

    def imm_carry(self, v: int) -> str:
        """Carry de un inmediato modificado: C si no está rotado, bit 31 si lo está."""
        v &= 0xffffffff
        lo, hi = v & 0xff, (v >> 8) & 0xff
        unrotated = v <= 0xff or (self.ctx.thumb and v in (
            lo * 0x00010001, hi * 0x01000100, lo * 0x01010101))
        return 'C' if unrotated else str(v >> 31)

    def split_dp(self) -> tuple[str, str, list[str]]:
        """'rd, rn, op2...' o la forma de 2 operandos 'rdn, op2...'."""
        rd, rest = self.ops[0], self.ops[1:]
        if len(rest) >= 2 and not _is_shift(rest[1]):
            return rd, rest[0], rest[1:]
        return rd, rd, rest

    # -- despacho ---------------------------------------------------------

    def emit(self) -> str | None:
        b = self.mn.base
        if b in _NOPS:
            return f'/* {b} — sin efecto en la simulación */'
        if b in _DP_LOGIC:
            return self.logic()
        if b in _DP_ARITH:
            return self.arith()
        if b in ('mov', 'mvn'):
            return self.mov()
        if b in ('cmp', 'cmn', 'tst', 'teq'):
            return self.compare()
        if b in _SHIFTS:
            return self.shift()
        if b in _LOADS or b in _STORES or b in _STORE_EX or b in (
                'ldrd', 'strd', 'ldrexd', 'strexd'):
            return self.load_store()
        if b in _LDM or b in _STM or b in ('push', 'pop'):
            return self.multiple()
        if b.startswith('v'):
            return self.vfp()
        handler = getattr(self, f'op_{b}', None)
        if handler is None:
            return None
        return handler()

    # -- procesamiento de datos ---------------------------------------------

    def _assign(self, rd_tok: str, expr: str) -> str:
        name = reg(rd_tok)
        if name == 'r15':
            # escritura en pc: salto/llamada a registro
            return f'{{ __call_indirect({expr}, {_u32(self.ctx.address)}); return; }}'
        return f'{self.dst(rd_tok)} = (uint32_t)({expr});'

    def logic(self) -> str:
        rd, rn, rest = self.split_dp()
        b2, shifted = self.op2(rest)
        op = _DP_LOGIC[self.mn.base]
        expr = f'{self.r(rn)} {op}(uint32_t)(__b)' if op.endswith('~') else \
            f'{self.r(rn)} {op} __b'
        if not self.mn.setflags:
            return f'{{ uint32_t __b = {b2}; {self._assign(rd, expr)} }}'
        return f'{{ {self._carry_pre(rest, shifted)}uint32_t __b = {b2}; ' \
               f'{self._assign(rd, f"__nzc({expr})")} }}'

    def _carry_pre(self, rest: list[str], shifted: bool) -> str:
        if shifted:
            return ''
        v = imm(rest[0]) if len(rest) == 1 else None
        return f'__shc = {self.imm_carry(v) if v is not None else "C"}; '

    def arith(self) -> str:
        rd, rn, rest = self.split_dp()
        b = self.mn.base
        a_expr = self.r(rn)
        # add/sub con pc e inmediato usan Align(PC, 4) (adr equivalente)
        if reg(rn) == 'r15' and len(rest) == 1 and imm(rest[0]) is not None:
            a_expr = _u32(self.pc_aligned)
        b2, _ = self.op2(rest)
        x, y, cin = {
            'add': ('__a', '__b', '0'), 'adc': ('__a', '__b', 'C'),
            'sub': ('__a', '~__b', '1'), 'sbc': ('__a', '~__b', 'C'),
            'rsb': ('__b', '~__a', '1'), 'rsc': ('__b', '~__a', 'C'),
        }[b]
        core = f'uint32_t __a = {a_expr}, __b = {b2}; '
        if self.mn.setflags:
            if reg(rd) == 'r15':
                return 'return;  /* subs pc, lr: retorno de excepción */'
            return f'{{ {core}{self._assign(rd, f"__addc({x}, {y}, {cin})")} }}'
        return f'{{ {core}{self._assign(rd, f"{x} + (uint32_t)({y}) + {cin}")} }}'

    def op_addw(self) -> str:
        return self._addsubw('+')

    def op_subw(self) -> str:
        return self._addsubw('-')

    def _addsubw(self, sign: str) -> str:
        rd, rn, v = self.ops[0], self.ops[1], imm(self.ops[2])
        a = _u32(self.pc_aligned) if reg(rn) == 'r15' else self.r(rn)
        return self._assign(rd, f'{a} {sign} {_u32(v)}')

    def op_adr(self) -> str:
        rd, v = self.ops[0], imm(self.ops[1])
        return self._assign(rd, _u32(self.pc_aligned + v))

    def op_neg(self) -> str:
        rd, rm = self.ops[0], self.ops[1]
        if self.mn.setflags:
            return self._assign(rd, f'__addc(0u, ~{self.r(rm)}, 1)')
        return self._assign(rd, f'0u - {self.r(rm)}')

    def mov(self) -> str:
        rd, rest = self.ops[0], self.ops[1:]
        b2, shifted = self.op2(rest)
        expr = f'~(uint32_t)(__b)' if self.mn.base == 'mvn' else '__b'
        if reg(rd) == 'r15':
            if not shifted and reg(rest[0]) == 'r14':
                return 'return;'
            return self._assign(rd, b2)
        if not self.mn.setflags:
            if expr == '__b':
                return self._assign(rd, b2)
            return f'{{ uint32_t __b = {b2}; {self._assign(rd, expr)} }}'
        return f'{{ {self._carry_pre(rest, shifted)}uint32_t __b = {b2}; ' \
               f'{self._assign(rd, f"__nzc({expr})")} }}'

    def op_movw(self) -> str:
        return self._assign(self.ops[0], _u32(imm(self.ops[1]) & 0xffff))

    def op_movt(self) -> str:
        rd = self.dst(self.ops[0])
        v = imm(self.ops[1]) & 0xffff
        return f'{rd} = ({rd} & 0xffffU) | {_u32(v << 16)};'

    def compare(self) -> str:
        rn, rest = self.ops[0], self.ops[1:]
        b2, shifted = self.op2(rest)
        a = self.r(rn)
        b = self.mn.base
        if b == 'cmp':
            return f'{{ uint32_t __b = {b2}; (void)__addc({a}, ~__b, 1); }}'
        if b == 'cmn':
            return f'{{ uint32_t __b = {b2}; (void)__addc({a}, __b, 0); }}'
        op = '&' if b == 'tst' else '^'
        return f'{{ {self._carry_pre(rest, shifted)}uint32_t __b = {b2}; ' \
               f'(void)__nzc({a} {op} __b); }}'

    def shift(self) -> str:
        b = self.mn.base
        rd = self.ops[0]
        if b == 'rrx':
            expr = f'__rrx({self.r(self.ops[1])})'
        else:
            if len(self.ops) == 2:          # forma Thumb de 2 operandos: rdn, rm
                src, amt = rd, self.ops[1]
            else:
                src, amt = self.ops[1], self.ops[2]
            a = imm(amt)
            amount = str(a) if a is not None else f'({self.r(amt)} & 0xffu)'
            expr = f'__{b}({self.r(src)}, {amount})'
        if self.mn.setflags:
            return self._assign(rd, f'__nzc({expr})')
        return self._assign(rd, expr)

    # -- multiplicación / división ----------------------------------------

    def op_mul(self) -> str:
        rd = self.ops[0]
        rn, rm = (self.ops[1], self.ops[2]) if len(self.ops) == 3 else (rd, self.ops[1])
        expr = f'(uint32_t)({self.r(rn)} * {self.r(rm)})'
        return self._assign(rd, f'__nz({expr})' if self.mn.setflags else expr)

    def op_mla(self) -> str:
        rd, rn, rm, ra = self.ops
        expr = f'(uint32_t)({self.r(rn)} * {self.r(rm)} + {self.r(ra)})'
        return self._assign(rd, f'__nz({expr})' if self.mn.setflags else expr)

    def op_mls(self) -> str:
        rd, rn, rm, ra = self.ops
        return self._assign(rd, f'(uint32_t)({self.r(ra)} - {self.r(rn)} * {self.r(rm)})')

    def _long_mul(self, signed: bool, accumulate: bool) -> str:
        lo, hi = self.dst(self.ops[0]), self.dst(self.ops[1])
        rn, rm = self.ops[2], self.ops[3]
        if signed:
            prod = f'(uint64_t)((int64_t)(int32_t){self.r(rn)} * (int64_t)(int32_t){self.r(rm)})'
        else:
            prod = f'(uint64_t){self.r(rn)} * (uint64_t){self.r(rm)}'
        acc = f'(((uint64_t){hi} << 32) | {lo}) + ' if accumulate else ''
        flags = ' N = (uint8_t)(__p >> 63); Z = (uint8_t)(__p == 0);' if self.mn.setflags else ''
        return f'{{ uint64_t __p = {acc}{prod}; {lo} = (uint32_t)__p; ' \
               f'{hi} = (uint32_t)(__p >> 32);{flags} }}'

    def op_umull(self) -> str:
        return self._long_mul(False, False)

    def op_smull(self) -> str:
        return self._long_mul(True, False)

    def op_umlal(self) -> str:
        return self._long_mul(False, True)

    def op_smlal(self) -> str:
        return self._long_mul(True, True)

    def _half(self, tok: str, which: str) -> str:
        r = self.r(tok)
        return f'(int32_t)(int16_t)({r})' if which == 'b' else f'(int32_t)(int16_t)({r} >> 16)'

    def _half_mul(self) -> str:
        b = self.mn.base
        rd = self.ops[0]
        if b.startswith('smul') and b[4] != 'w':           # smulxy
            return self._assign(rd, f'(uint32_t)({self._half(self.ops[1], b[4])} * '
                                    f'{self._half(self.ops[2], b[5])})')
        if b.startswith('smla') and b[4] != 'w':           # smlaxy
            return self._assign(rd, f'(uint32_t)({self._half(self.ops[1], b[4])} * '
                                    f'{self._half(self.ops[2], b[5])} + (int32_t){self.r(self.ops[3])})')
        prod = (f'(int32_t)(((int64_t)(int32_t){self.r(self.ops[1])} * '
                f'{self._half(self.ops[2], b[5])}) >> 16)')
        if b.startswith('smulw'):
            return self._assign(rd, f'(uint32_t){prod}')
        return self._assign(rd, f'(uint32_t)({prod} + (int32_t){self.r(self.ops[3])})')

    op_smulbb = op_smulbt = op_smultb = op_smultt = _half_mul
    op_smlabb = op_smlabt = op_smlatb = op_smlatt = _half_mul
    op_smulwb = op_smulwt = op_smlawb = op_smlawt = _half_mul

    def _smm(self, acc: str, rnd: bool) -> str:
        rd, rn, rm = self.ops[0], self.ops[1], self.ops[2]
        p = f'(int64_t)(int32_t){self.r(rn)} * (int64_t)(int32_t){self.r(rm)}'
        if acc:
            p = f'((int64_t){self.r(self.ops[3])} << 32) {acc} ({p})'
        r = ' + 0x80000000LL' if rnd else ''
        return self._assign(rd, f'(uint32_t)((uint64_t)(({p}){r}) >> 32)')

    def op_smmul(self) -> str:
        return self._smm('', False)

    def op_smmulr(self) -> str:
        return self._smm('', True)

    def op_smmla(self) -> str:
        return self._smm('+', False)

    def op_smmlar(self) -> str:
        return self._smm('+', True)

    def op_smmls(self) -> str:
        return self._smm('-', False)

    def op_smmlsr(self) -> str:
        return self._smm('-', True)

    def op_udiv(self) -> str:
        rd, rn, rm = self.ops if len(self.ops) == 3 else (self.ops[0], *self.ops)
        return self._assign(rd, f'__udiv({self.r(rn)}, {self.r(rm)})')

    def op_sdiv(self) -> str:
        rd, rn, rm = self.ops if len(self.ops) == 3 else (self.ops[0], *self.ops)
        return self._assign(rd, f'__sdiv({self.r(rn)}, {self.r(rm)})')

    # -- bits, extensiones, saturación ------------------------------------

    def op_clz(self) -> str:
        return self._assign(self.ops[0], f'__clz({self.r(self.ops[1])})')

    def op_rbit(self) -> str:
        return self._assign(self.ops[0], f'__rbit({self.r(self.ops[1])})')

    def op_rev(self) -> str:
        return self._assign(self.ops[0], f'__builtin_bswap32({self.r(self.ops[1])})')

    def op_rev16(self) -> str:
        x = self.r(self.ops[1])
        return self._assign(self.ops[0], f'(({x} & 0xff00ff00U) >> 8) | (({x} & 0x00ff00ffU) << 8)')

    def op_revsh(self) -> str:
        x = self.r(self.ops[1])
        return self._assign(self.ops[0],
                            f'(uint32_t)(int32_t)(int16_t)((({x} & 0xffU) << 8) | (({x} >> 8) & 0xffU))')

    def _rotation(self, toks: list[str]) -> int:
        if not toks:
            return 0
        m = _SHIFT_RE.match(toks[0].strip().lower())
        if not m or m.group(1) != 'ror':
            raise _Unsupported(toks[0])
        return imm(m.group(2))

    def _extend(self) -> str:
        ctype, add = _EXTEND[self.mn.base]
        rd = self.ops[0]
        if add:
            rn, rm, rest = self.ops[1], self.ops[2], self.ops[3:]
        else:
            rn, rm, rest = None, self.ops[1], self.ops[2:]
        val = f'(uint32_t)({ctype})__rot({self.r(rm)}, {self._rotation(rest)})'
        if add:
            val = f'{self.r(rn)} + {val}'
        return self._assign(rd, val)

    op_uxtb = op_uxth = op_sxtb = op_sxth = _extend
    op_uxtab = op_uxtah = op_sxtab = op_sxtah = _extend

    def op_uxtb16(self) -> str:
        x = f'__rot({self.r(self.ops[1])}, {self._rotation(self.ops[2:])})'
        return self._assign(self.ops[0], f'{x} & 0x00ff00ffU')

    def op_sxtb16(self) -> str:
        x = f'__rot({self.r(self.ops[1])}, {self._rotation(self.ops[2:])})'
        return self._assign(self.ops[0], f'((uint32_t)(int32_t)(int8_t){x} & 0xffffU) | '
                                         f'((uint32_t)(int32_t)(int8_t)({x} >> 16) << 16)')

    def op_ubfx(self) -> str:
        rd, rn, lsb, w = self.ops[0], self.ops[1], imm(self.ops[2]), imm(self.ops[3])
        mask = (1 << w) - 1
        return self._assign(rd, f'({self.r(rn)} >> {lsb}) & {_u32(mask)}')

    def op_sbfx(self) -> str:
        rd, rn, lsb, w = self.ops[0], self.ops[1], imm(self.ops[2]), imm(self.ops[3])
        return self._assign(rd, f'(uint32_t)((int32_t)({self.r(rn)} << {32 - lsb - w}) >> {32 - w})')

    def op_bfi(self) -> str:
        rd, rn, lsb, w = self.dst(self.ops[0]), self.ops[1], imm(self.ops[2]), imm(self.ops[3])
        mask = ((1 << w) - 1) << lsb
        return f'{rd} = ({rd} & {_u32(~mask)}) | (({self.r(rn)} << {lsb}) & {_u32(mask)});'

    def op_bfc(self) -> str:
        rd, lsb, w = self.dst(self.ops[0]), imm(self.ops[1]), imm(self.ops[2])
        mask = ((1 << w) - 1) << lsb
        return f'{rd} = {rd} & {_u32(~mask)};'

    def _sat(self, fn: str) -> str:
        rd, n, rest = self.ops[0], imm(self.ops[1]), self.ops[2:]
        val, _ = self.op2(rest)
        return self._assign(rd, f'{fn}((int64_t)(int32_t)({val}), {n})')

    def op_usat(self) -> str:
        return self._sat('__usat')

    def op_ssat(self) -> str:
        return self._sat('__ssat')

    def op_uadd8(self) -> str:
        rd, rn, rm = self.ops
        return self._assign(rd, f'__uadd8({self.r(rn)}, {self.r(rm)})')

    def op_sel(self) -> str:
        rd, rn, rm = self.ops
        return self._assign(rd, f'__sel({self.r(rn)}, {self.r(rm)})')

    # -- saltos y sistema ---------------------------------------------------

    def op_bx(self) -> str:
        if reg(self.ops[0]) == 'r14':
            return 'return;'
        return f'{{ __call_indirect({self.r(self.ops[0])}, {_u32(self.ctx.address)}); return; }}'

    op_bxj = op_bx

    def op_blx(self) -> str:
        return f'__call_indirect({self.r(self.ops[0])}, {_u32(self.ctx.address)});'

    def op_mrs(self) -> str:
        src = self.ops[1].strip().lower()
        if src not in ('apsr', 'cpsr', 'xpsr', 'iapsr', 'eapsr', 'epsr'):
            raise _Unsupported(src)
        return self._assign(self.ops[0], APSR_PACK)

    def op_msr(self) -> str:
        dst = self.ops[0].strip().lower()
        if not dst.startswith(('apsr', 'cpsr', 'xpsr')):
            raise _Unsupported(dst)
        return apsr_unpack(self.r(self.ops[1]))

    def op_clrex(self) -> str:
        return '__excl = 0;  /* clrex */'

    def op_udf(self) -> str:
        return (f'fprintf(stderr, "udf (trap) en {_u32(self.ctx.address)}\\n"); abort();')

    def op_bkpt(self) -> str:
        return '/* bkpt — punto de ruptura (ignorado en la simulación) */'

    # -- memoria ------------------------------------------------------------

    def _address(self, mem: str, post: list[str]) -> tuple[str, str, str | None]:
        """
        Operando de memoria → (expresión de dirección, actualización de base, base).
        Soporta [rn], [rn, #i], [rn, #i]!, [rn, rm], [rn, -rm], [rn, rm, lsl #n],
        [rn], #i / [rn], rm (post-índice) y [pc, #i] (literal).
        """
        mem = mem.strip()
        wb = mem.endswith('!')
        inner = mem.rstrip('!').strip()[1:-1]
        parts = [p.strip() for p in inner.split(',')]
        base = reg(parts[0])
        if base is None:
            raise _Unsupported(mem)
        off = self._offset(parts[1:]) if len(parts) > 1 else '0u'
        if base == 'r15':
            if post or wb:
                raise _Unsupported('pc writeback')
            return f'{_u32(self.pc_aligned)} + (uint32_t)({off})', '', None
        if post:
            poff = self._offset(post)
            return base, f'{base} = {base} + (uint32_t)({poff});', base
        ea = base if off == '0u' else f'{base} + (uint32_t)({off})'
        return ea, (f'{base} = __ea;' if wb else ''), base

    def _offset(self, toks: list[str]) -> str:
        v = imm(toks[0])
        if v is not None:
            return f'(int32_t){v}'
        t = toks[0].strip()
        neg = t.startswith('-')
        rm = self.r(t.lstrip('-+'))
        if len(toks) > 1:
            sh = toks[1].strip().lower()
            if sh == 'rrx':
                rm = f'__rrx({rm})'
            else:
                m = _SHIFT_RE.match(sh)
                if not m or imm(m.group(2)) is None:
                    raise _Unsupported(toks[1])
                # helpers: desplazamientos de 32 bien definidos (lsr/asr #32)
                rm = f'__{m.group(1)}({rm}, {imm(m.group(2))})'
        return f'(0u - {rm})' if neg else rm

    def _literal_word(self, index: int, size: int, signed: bool) -> str | None:
        lit = self.ctx.literal
        if lit is None or len(lit) < (index + 1) * size:
            return None
        v = int.from_bytes(lit[index * size:(index + 1) * size], 'little', signed=signed)
        return _u32(v)

    def load_store(self) -> str:
        b = self.mn.base
        ops = self.ops
        if b in _STORE_EX or b == 'strexd':
            status, regs, rest = ops[0], ops[1:-1], ops[-1:]
        elif b in ('ldrd', 'strd', 'ldrexd'):
            status, regs, rest = None, ops[:2], ops[2:]
        else:
            status, regs, rest = None, ops[:1], ops[1:]
        mem, post = rest[0], rest[1:]
        is_load = b.startswith('ldr')
        ea, wb, base = self._address(mem, post)

        if b in ('ldrd', 'strd', 'ldrexd', 'strexd'):
            size, signed = 4, False
        elif is_load:
            size, signed = _LOADS[b]
        else:
            size, signed = (_STORE_EX.get(b) or _STORES[b]), False
        rd_name = 'SIM_READ32' if size == 4 else ('SIM_READ16' if size == 2 else 'SIM_READ8')
        wr_name = 'SIM_WRITE32' if size == 4 else ('SIM_WRITE16' if size == 2 else 'SIM_WRITE8')
        cast = {1: 'int8_t', 2: 'int16_t'}.get(size) if signed else None

        stmts = [f'uint32_t __ea = {ea};']
        exclusive = b.startswith(('ldrex', 'strex'))
        if is_load and exclusive:
            stmts.append('__excl = 1;')
        if is_load:
            # Literal pool: valor constante conocido en tiempo de traducción
            temps = []
            for i in range(len(regs)):
                lit = self._literal_word(i, size, signed) if base is None else None
                if lit is not None:
                    val = lit
                else:
                    raw = f'{rd_name}(__ea + {4 * i})' if i else f'{rd_name}(__ea)'
                    val = f'(uint32_t)({cast}){raw}' if cast else f'(uint32_t){raw}'
                temps.append(f'uint32_t __v{i} = {val};')
            stmts.extend(temps)
            if wb:
                stmts.append(wb)
            for i, t in enumerate(regs):
                if reg(t) == 'r15':
                    if self.ctx.jump_table:
                        stmts.append('/* salto indexado: ver switch de salida del bloque */')
                    elif mem.replace(' ', '').lower() == '[sp]' and post and imm(post[0]) == 4:
                        stmts.append('return;')
                    else:
                        stmts.append(f'__call_indirect(__v{i}, {_u32(self.ctx.address)}); return;')
                else:
                    stmts.append(f'{self.dst(t)} = __v{i};')
        else:
            writes = []
            for i, t in enumerate(regs):
                addr = f'__ea + {4 * i}' if i else '__ea'
                writes.append(f'{wr_name}({addr}, {self.r(t)});')
            if exclusive:
                # strex: escribe y devuelve 0 solo si el monitor exclusivo está activo
                stmts.append(f'uint32_t __ok = __excl; __excl = 0; '
                             f'if (__ok) {{ {" ".join(writes)} }} '
                             f'{self.dst(status)} = __ok ? 0u : 1u;')
            else:
                stmts.extend(writes)
            if wb:
                stmts.append(wb)
        return '{ ' + ' '.join(stmts) + ' }'

    def multiple(self) -> str:
        b = self.mn.base
        if b in ('push', 'pop'):
            base_tok, regs_tok = 'sp!', self.ops[0]
            mode = 'db' if b == 'push' else 'ia'
            is_load = b == 'pop'
        else:
            base_tok, regs_tok = self.ops[0], self.ops[1]
            mode = (_LDM.get(b) or _STM[b])
            is_load = b in _LDM
        regs = _reglist(regs_tok)
        if not regs:
            raise _Unsupported(regs_tok)
        base = self.dst(base_tok)
        wb = base_tok.strip().endswith('!')
        n = len(regs)
        start = {'ia': '0', 'ib': '4', 'db': f'-{4 * n}', 'da': f'-{4 * n - 4}'}[mode]
        final = f'{base} + {4 * n}' if mode in ('ia', 'ib') else f'{base} - {4 * n}'
        stmts = [f'uint32_t __ea = {base} + (uint32_t)({start});']
        if is_load:
            for i in range(len(regs)):
                stmts.append(f'uint32_t __v{i} = SIM_READ32(__ea + {4 * i});')
            if wb:
                stmts.append(f'{base} = {final};')
            for i, r in enumerate(regs):
                if r == 'r15':
                    if base == 'r13':
                        stmts.append('return;')
                    else:
                        stmts.append(f'__call_indirect(__v{i}, {_u32(self.ctx.address)}); return;')
                else:
                    stmts.append(f'{r} = __v{i};')
        else:
            for i, r in enumerate(regs):
                stmts.append(f'SIM_WRITE32(__ea + {4 * i}, {self.r(r)});')
            if wb:
                stmts.append(f'{base} = {final};')
        return '{ ' + ' '.join(stmts) + ' }'

    # -- VFP --------------------------------------------------------------

    def vfp(self) -> str | None:
        b = self.mn.base
        # Solo VFP escalar: un tipo .f32 opera sobre s<n> y .f64 sobre d<n>. Otras
        # combinaciones (vmul.f32 d0, d1, d2; tipos enteros .i32/.u8...; registros q)
        # son Advanced SIMD (NEON), que no se simula.
        regs = [t.strip().lower() for t in self.ops if t.strip()[:1].lower() in 'sdq'
                and t.strip()[1:].isdigit()]
        if any(r[0] == 'q' for r in regs):
            raise _Unsupported('NEON')
        if self.mn.types and not b.startswith('vcvt'):
            want = {'f32': 's', 'f64': 'd'}.get(self.mn.types[0])
            if want is None or any(r[0] != want for r in regs):
                raise _Unsupported('NEON')
        handler = getattr(self, f'v_{b}', None)
        if handler is not None:
            return handler()
        if b in ('vadd', 'vsub', 'vmul', 'vdiv', 'vnmul', 'vmaxnm', 'vminnm'):
            return self.v_binary()
        if b in ('vfma', 'vfms', 'vfnma', 'vfnms', 'vmla', 'vmls', 'vnmla', 'vnmls'):
            return self.v_multiply_accumulate()
        if b in ('vneg', 'vabs', 'vsqrt') or b.startswith('vrint'):
            return self.v_unary()
        if b.startswith('vsel'):
            return self.v_select()
        if b.startswith('vcvt'):
            return self.v_convert()
        return None

    @staticmethod
    def _freg(tok: str) -> tuple[str, int]:
        t = tok.strip().lower()
        if t[0] in 'sd' and t[1:].isdigit() and int(t[1:]) < 32:
            return t[0], int(t[1:])
        raise _Unsupported(tok)

    def _fget(self, tok: str) -> str:
        kind, n = self._freg(tok)
        return f'__getf({n})' if kind == 's' else f'__getd({n})'

    def _fset(self, tok: str, expr: str) -> str:
        kind, n = self._freg(tok)
        return f'__setf({n}, (float)({expr}));' if kind == 's' else f'__setd({n}, (double)({expr}));'

    def _fsuffix(self, tok: str) -> str:
        return 'f' if self._freg(tok)[0] == 's' else ''

    def v_binary(self) -> str:
        d, n, m = self.ops if len(self.ops) == 3 else (self.ops[0], *self.ops)
        a, c = self._fget(n), self._fget(m)
        t = 'f' if self._fsuffix(d) else 'd'
        expr = {
            'vadd': f'__vadd{t}({a}, {c})', 'vsub': f'__vsub{t}({a}, {c})',
            'vmul': f'__vmul{t}({a}, {c})', 'vdiv': f'__vdiv{t}({a}, {c})',
            'vnmul': f'-__vmul{t}({a}, {c})',      # FPNeg: también cambia el signo de un NaN
            'vmaxnm': f'__vmaxnm{t}({a}, {c})', 'vminnm': f'__vminnm{t}({a}, {c})',
        }[self.mn.base]
        return self._fset(d, expr)

    def v_multiply_accumulate(self) -> str:
        d, n, m = self.ops
        acc, a, c = self._fget(d), self._fget(n), self._fget(m)
        f = 'f' if self._fsuffix(d) else 'd'
        t = 'float' if f == 'f' else 'double'
        # Las negaciones (FPNeg) se aplican a los operandos antes de procesar NaN
        expr = {
            'vfma': f'__vfma{f}({acc}, {a}, {c})', 'vfms': f'__vfma{f}({acc}, -{a}, {c})',
            'vfnma': f'__vfma{f}(-{acc}, -{a}, {c})', 'vfnms': f'__vfma{f}(-{acc}, {a}, {c})',
        }.get(self.mn.base)
        if expr is not None:
            return self._fset(d, expr)
        # vmla/vmls/vnmla/vnmls: producto y suma redondeados por separado
        combine = {'vmla': f'__vadd{f}({acc}, __p)', 'vmls': f'__vadd{f}({acc}, -__p)',
                   'vnmla': f'__vadd{f}(-{acc}, -__p)', 'vnmls': f'__vadd{f}(-{acc}, __p)'}[self.mn.base]
        return f'{{ {t} __p = __vmul{f}({a}, {c}); {self._fset(d, combine)} }}'

    def v_unary(self) -> str:
        d, m = self.ops
        b = self.mn.base
        kd, nd = self._freg(d)
        km, nm = self._freg(m)
        if b in ('vneg', 'vabs'):
            # operación sobre el bit de signo, exacta también para NaN
            op = '^ 0x80000000U' if b == 'vneg' else '& 0x7fffffffU'
            if kd == 's':
                return f'__s[{nd}] = __s[{nm}] {op};'
            return f'__s[{2 * nd}] = __s[{2 * nm}]; __s[{2 * nd + 1}] = __s[{2 * nm + 1}] {op};'
        f = self._fsuffix(d)
        if b == 'vsqrt':
            return self._fset(d, f'__vsqrt{f or "d"}({self._fget(m)})')
        fn = {'vrinta': 'round', 'vrintm': 'floor', 'vrintp': 'ceil',
              'vrintn': 'nearbyint', 'vrintz': 'trunc', 'vrintx': 'rint',
              'vrintr': 'nearbyint'}[b]
        return self._fset(d, f'{fn}{f}({self._fget(m)})')

    def v_select(self) -> str:
        d, n, m = self.ops
        cond = ARM32_COND_TO_C[self.mn.base[4:]]
        kd, nd = self._freg(d)
        _, nn = self._freg(n)
        _, nm = self._freg(m)
        if kd == 's':
            return f'__s[{nd}] = ({cond}) ? __s[{nn}] : __s[{nm}];'
        return (f'if ({cond}) {{ __s[{2 * nd}] = __s[{2 * nn}]; __s[{2 * nd + 1}] = __s[{2 * nn + 1}]; }} '
                f'else {{ __s[{2 * nd}] = __s[{2 * nm}]; __s[{2 * nd + 1}] = __s[{2 * nm + 1}]; }}')

    def v_vmov(self) -> str:
        ops = self.ops
        if len(ops) == 3:
            if reg(ops[0]) and reg(ops[1]):             # vmov rA, rB, dN
                _, n = self._freg(ops[2])
                return f'{self.dst(ops[0])} = __s[{2 * n}]; {self.dst(ops[1])} = __s[{2 * n + 1}];'
            _, n = self._freg(ops[0])                    # vmov dN, rA, rB
            return f'__s[{2 * n}] = {self.r(ops[1])}; __s[{2 * n + 1}] = {self.r(ops[2])};'
        if len(ops) == 4:
            if reg(ops[0]):                              # vmov rA, rB, sN, sN+1
                _, n = self._freg(ops[2])
                return f'{self.dst(ops[0])} = __s[{n}]; {self.dst(ops[1])} = __s[{n + 1}];'
            _, n = self._freg(ops[0])                    # vmov sN, sN+1, rA, rB
            return f'__s[{n}] = {self.r(ops[2])}; __s[{n + 1}] = {self.r(ops[3])};'
        d, m = ops
        if reg(d):                                       # vmov rT, sN
            _, n = self._freg(m)
            return f'{self.dst(d)} = __s[{n}];'
        kd, nd = self._freg(d)
        if reg(m):                                       # vmov sN, rT
            return f'__s[{nd}] = {self.r(m)};'
        if m.strip().startswith('#'):                    # vmov.f32 sN, #1.5
            val = float(m.strip()[1:])
            if kd == 's':
                return f'__s[{nd}] = {_u32(struct.unpack("<I", struct.pack("<f", val))[0])};'
            lo, hi = struct.unpack('<II', struct.pack('<d', val))
            return f'__s[{2 * nd}] = {_u32(lo)}; __s[{2 * nd + 1}] = {_u32(hi)};'
        km, nm = self._freg(m)
        if kd == 's':
            return f'__s[{nd}] = __s[{nm}];'
        return f'__s[{2 * nd}] = __s[{2 * nm}]; __s[{2 * nd + 1}] = __s[{2 * nm + 1}];'

    def v_vcmp(self) -> str:
        a, b = self.ops
        rhs = '0.0' if b.strip().startswith('#') else f'(double){self._fget(b)}'
        return f'__vcmp((double){self._fget(a)}, {rhs});'

    v_vcmpe = v_vcmp

    def v_vmrs(self) -> str:
        d = self.ops[0].strip().lower()
        if d in ('apsr_nzcv', 'apsr'):
            return ('N = (uint8_t)(__fpscr >> 31); Z = (uint8_t)((__fpscr >> 30) & 1u); '
                    'C = (uint8_t)((__fpscr >> 29) & 1u); V = (uint8_t)((__fpscr >> 28) & 1u);')
        return f'{self.dst(d)} = __fpscr;'

    def v_vmsr(self) -> str:
        return f'__fpscr = {self.r(self.ops[1])};'

    def v_vldr(self) -> str:
        return self._vldst(load=True)

    def v_vstr(self) -> str:
        return self._vldst(load=False)

    def _vldst(self, load: bool) -> str:
        kind, n = self._freg(self.ops[0])
        words = [n] if kind == 's' else [2 * n, 2 * n + 1]
        ea, _, base = self._address(self.ops[1], [])
        stmts = [f'uint32_t __ea = {ea};']
        for i, w in enumerate(words):
            addr = f'__ea + {4 * i}' if i else '__ea'
            if load:
                lit = self._literal_word(i, 4, False) if base is None else None
                stmts.append(f'__s[{w}] = {lit or f"SIM_READ32({addr})"};')
            else:
                stmts.append(f'SIM_WRITE32({addr}, __s[{w}]);')
        return '{ ' + ' '.join(stmts) + ' }'

    def _vmulti(self, base_tok: str, list_tok: str, load: bool, mode: str) -> str:
        words = _vfp_words(list_tok)
        if not words:
            raise _Unsupported(list_tok)
        base = self.dst(base_tok)
        wb = base_tok.strip().endswith('!')
        n = len(words)
        start = '0' if mode == 'ia' else f'-{4 * n}'
        stmts = [f'uint32_t __ea = {base} + (uint32_t)({start});']
        for i, w in enumerate(words):
            if load:
                stmts.append(f'__s[{w}] = SIM_READ32(__ea + {4 * i});')
            else:
                stmts.append(f'SIM_WRITE32(__ea + {4 * i}, __s[{w}]);')
        if wb:
            stmts.append(f'{base} = {base} {"+" if mode == "ia" else "-"} {4 * n};')
        return '{ ' + ' '.join(stmts) + ' }'

    def v_vpush(self) -> str:
        return self._vmulti('sp!', self.ops[0], False, 'db')

    def v_vpop(self) -> str:
        return self._vmulti('sp!', self.ops[0], True, 'ia')

    def v_vldmia(self) -> str:
        return self._vmulti(self.ops[0], self.ops[1], True, 'ia')

    v_vldm = v_vldmia

    def v_vstmia(self) -> str:
        return self._vmulti(self.ops[0], self.ops[1], False, 'ia')

    v_vstm = v_vstmia

    def v_vldmdb(self) -> str:
        return self._vmulti(self.ops[0], self.ops[1], True, 'db')

    def v_vstmdb(self) -> str:
        return self._vmulti(self.ops[0], self.ops[1], False, 'db')

    def v_convert(self) -> str:
        b = self.mn.base
        types = self.mn.types
        if len(types) != 2:
            raise _Unsupported('vcvt')
        to, frm = types
        d, m = self.ops[0], self.ops[1]
        fbits = imm(self.ops[2]) if len(self.ops) > 2 else 0
        kd, nd = self._freg(d)
        km, nm = self._freg(m)
        # Registros esperados (las formas vectoriales NEON no se aceptan)
        if fbits:
            want_d = want_m = 'd' if 'f64' in types else 's'
        else:
            want_d = 'd' if to == 'f64' else 's'
            want_m = 'd' if frm == 'f64' else 's'
        if (kd, km) != (want_d, want_m):
            raise _Unsupported('vcvt NEON')
        rnd = {'vcvtr': 'nearbyint', 'vcvta': 'round', 'vcvtn': 'nearbyint',
               'vcvtp': 'ceil', 'vcvtm': 'floor'}.get(b)
        if to in ('f32', 'f64') and frm in ('f32', 'f64'):
            return self._fset(d, f'({"float" if to == "f32" else "double"}){self._fget(m)}')
        if to in ('f32', 'f64'):
            # entero (o punto fijo) → flotante; el entero está en la palabra baja de m
            word = nm if km == 's' else 2 * nm
            ival = f'(double)(int32_t)__s[{word}]' if frm == 's32' else f'(double)__s[{word}]'
            if frm not in ('s32', 'u32'):
                raise _Unsupported(frm)
            if fbits:
                ival = f'({ival} / {float(1 << fbits)!r})'
            return self._fset(d, ival)
        if to in ('s32', 'u32'):
            x = f'(double){self._fget(m)}'
            if fbits:
                x = f'({x} * {float(1 << fbits)!r})'
            if rnd:
                x = f'{rnd}({x})'
            fn = '__f2s32' if to == 's32' else '__f2u32'
            word = nd if kd == 's' else 2 * nd
            return f'__s[{word}] = {fn}({x});'
        raise _Unsupported(to)
