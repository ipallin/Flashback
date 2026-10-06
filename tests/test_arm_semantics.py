"""
Pruebas de la semántica ARM / Thumb-2 / VFP → C (PAS01-PAS05).

Las pruebas de ejecución (PAS03-PAS04) compilan con gcc el C generado para una
secuencia de instrucciones, lo ejecutan desde un estado inicial conocido y
comprueban registros, flags, banco VFP y memoria. Los valores esperados siguen
el ARM Architecture Reference Manual.

La validación exhaustiva frente a un emulador (Unicorn) está en
tools/arm_difftest.py.
"""

import shutil
import struct
import subprocess

import pytest

from flashback.arch.arm32.semantics import (
    C_RUNTIME, InsnContext, Mnemonic, parse_mnemonic, translate,
)

_RAM = 0x20000000
_RAM_SIZE = 0x1000
_REGS = [f'r{i}' for i in range(15)]


# ---------------------------------------------------------------------------
# PAS01 – parse_mnemonic
# ---------------------------------------------------------------------------

class TestParseMnemonic:

    @pytest.mark.parametrize('mnemonic, expected', [
        ('movs', Mnemonic('mov', True)),             # no es 'mo' + condición 'vs'
        ('lsls', Mnemonic('lsl', True)),             # no es 'ls' + 'ls'
        ('muls', Mnemonic('mul', True)),
        ('adcs', Mnemonic('adc', True)),             # no es 'ad' + 'cs'
        ('bics', Mnemonic('bic', True)),
        ('mls', Mnemonic('mls')),                    # multiply-subtract, no 'm' + 'ls'
        ('mulls', Mnemonic('mul', False, 'ls')),
        ('movvs', Mnemonic('mov', False, 'vs')),
        ('ldrhs', Mnemonic('ldr', False, 'hs')),     # ldr + hs, no ldrh + s
        ('ldrsh', Mnemonic('ldrsh')),
        ('teqeq', Mnemonic('teq', False, 'eq')),
        ('mvnsne', Mnemonic('mvn', True, 'ne')),
        ('add.w', Mnemonic('add')),
        ('vmovmi.f32', Mnemonic('vmov', False, 'mi', ('f32',))),
        ('vcvt.f64.s32', Mnemonic('vcvt', types=('f64', 's32'))),
        ('vselgt.f32', Mnemonic('vselgt', types=('f32',))),
    ])
    def test_parse(self, mnemonic, expected):
        assert parse_mnemonic(mnemonic) == expected

    def test_unknown(self):
        assert parse_mnemonic('frobnicate') is None


# ---------------------------------------------------------------------------
# PAS02 – cobertura de traducción
# ---------------------------------------------------------------------------

def _t(mnemonic, operands, thumb=True, literal=None):
    return translate(mnemonic, operands, InsnContext(0x8000100, 4, thumb, literal))


class TestCoverage:

    @pytest.mark.parametrize('mnemonic, operands', [
        ('add.w', 'r0, r1, r2, lsl #2'), ('orr', 'r1, ip, r1, lsr #12'),
        ('rsbs', 'r5, r4, r5, lsr #21'), ('mvns', 'ip, r4, asr #21'),
        ('ldrb', 'r3, [r0], #1'), ('strd', 'ip, lr, [sp, #-0x10]!'),
        ('ldr', 'r0, [r1, r2, lsl #2]'), ('ldm.w', 'r4, {r0, r1}'), ('stmdb', 'r4, {r2, r3}'),
        ('mla', 'r2, r1, r2, r3'), ('umull', 'sb, r4, r0, r2'), ('smlabb', 'r0, r2, r0, r3'),
        ('ubfx', 'r3, r3, #3, #1'), ('bfi', 'r3, r4, #0, #1'), ('bfc', 'r3, #1, #1'),
        ('uxtab', 'r3, r3, r1'), ('rev16', 'r3, r3'), ('clz', 'r3, r1'), ('udiv', 'r6, lr, r8'),
        ('vldr', 'd6, [pc, #0x2c]'), ('vmov', 'd7, r2, r3'), ('vmul.f64', 'd6, d7, d6'),
        ('vfma.f32', 's0, s14, s15'), ('vcvt.f64.f32', 'd7, s15'), ('vcvt.f32.s32', 's0, s0, #4'),
        ('vmrs', 'apsr_nzcv, fpscr'), ('vpush', '{d8, d9}'), ('vselgt.f32', 's19, s19, s15'),
        ('vrinta.f32', 's0, s0'), ('vldmia', 'r1!, {s15}'), ('it', 'eq'),
        ('pop', '{r4, pc}'), ('bx', 'r3'), ('dmb', 'ish'),
    ])
    def test_translated(self, mnemonic, operands):
        stmt = _t(mnemonic, operands)
        assert stmt is not None
        assert 'UNSUPPORTED' not in stmt

    @pytest.mark.parametrize('mnemonic, operands', [
        ('vmul.f32', 'd15, d5, d20'),        # NEON: 2 carriles float en registros d
        ('vadd.i32', 'd0, d1, d2'),          # NEON entero
        ('vcvt.f32.s32', 'd0, d1'),          # NEON
    ])
    def test_neon_rejected(self, mnemonic, operands):
        assert _t(mnemonic, operands) is None

    def test_literal_resolved_to_constant(self):
        stmt = _t('ldr', 'r0, [pc, #4]', literal=bytes.fromhex('78563412'))
        assert '0x12345678U' in stmt
        assert 'SIM_READ32' not in stmt

    def test_pc_read_thumb_vs_arm(self):
        assert '0x8000104U' in _t('mov', 'r0, pc', thumb=True)
        assert '0x8000108U' in _t('mov', 'r0, pc', thumb=False)

    def test_adr_aligned(self):
        # Thumb: Align(0x8000102 + 4, 4) + 8
        stmt = translate('adr', 'r0, #8', InsnContext(0x8000102, 2, True))
        assert '0x800010cU' in stmt


# ---------------------------------------------------------------------------
# Arnés de ejecución
# ---------------------------------------------------------------------------

_PRELUDE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static uint8_t RAM[%(size)d + 16];
static uintptr_t __sim_addr(uint64_t va) {
    if (va >= %(base)du && va < %(base)du + %(size)du) return (uintptr_t)(RAM + (va - %(base)du));
    fprintf(stderr, "acceso fuera de RAM: %%llx\n", (unsigned long long)va); exit(3);
}
#define SIM_READ8(a)  (*(uint8_t  *)__sim_addr((uint64_t)(a)))
#define SIM_READ16(a) (*(uint16_t *)__sim_addr((uint64_t)(a)))
#define SIM_READ32(a) (*(uint32_t *)__sim_addr((uint64_t)(a)))
#define SIM_WRITE8(a, v)  (*(uint8_t  *)__sim_addr((uint64_t)(a)) = (uint8_t)(v))
#define SIM_WRITE16(a, v) (*(uint16_t *)__sim_addr((uint64_t)(a)) = (uint16_t)(v))
#define SIM_WRITE32(a, v) (*(uint32_t *)__sim_addr((uint64_t)(a)) = (uint32_t)(v))
static uint32_t r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15;
#define sp r13
#define lr r14
#define ip r12
#define fp r11
#define sl r10
#define sb r9
static uint8_t N, Z, C, V;
%(runtime)s
static void __call_indirect(uint32_t t, uint32_t s) { printf("call_indirect=%%u\n", t); }
static void run(void) {
%(body)s
}
int main(void) {
%(init)s
    run();
    uint32_t regs[15] = {r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14};
    for (int i = 0; i < 15; i++) printf("r%%d=%%u\n", i, regs[i]);
    printf("N=%%u\nZ=%%u\nC=%%u\nV=%%u\n", N, Z, C, V);
    for (int i = 0; i < 64; i++) printf("s%%d=%%u\n", i, __s[i]);
    printf("fpscr=%%u\n", __fpscr);
    for (int i = 0; i < 64; i++) printf("m%%d=%%u\n", i, ((uint32_t *)RAM)[i]);
    return 0;
}
'''


def _f32(x: float) -> int:
    return struct.unpack('<I', struct.pack('<f', x))[0]


def _run(tmp_path, insns, **init):
    """
    Ejecuta [(mnemonic, operands[, literal])] desde el estado init y devuelve
    {'r0': .., 'N': .., 's0': .., 'm0': (palabra 0 de RAM), ...}.
    init admite rN, N/Z/C/V, sN (bits), mN (palabras de RAM) y fpscr.
    """
    if shutil.which('gcc') is None:
        pytest.skip('gcc no disponible')
    body = []
    addr = 0x8000100
    for item in insns:
        mnemonic, operands = item[0], item[1]
        literal = item[2] if len(item) > 2 else None
        stmt = translate(mnemonic, operands, InsnContext(addr, 4, True, literal))
        assert stmt is not None, f'sin traducir: {mnemonic} {operands}'
        body.append(f'    {stmt}')
        addr += 4
    lines = []
    for k, v in init.items():
        if k[0] == 's' and k[1:].isdigit():
            lines.append(f'    __s[{k[1:]}] = {v}u;')
        elif k[0] == 'm' and k[1:].isdigit():
            lines.append(f'    ((uint32_t *)RAM)[{k[1:]}] = {v}u;')
        elif k == 'fpscr':
            lines.append(f'    __fpscr = {v}u;')
        else:
            lines.append(f'    {k} = {v}u;')
    src = _PRELUDE % {'base': _RAM, 'size': _RAM_SIZE, 'runtime': C_RUNTIME,
                      'body': '\n'.join(body), 'init': '\n'.join(lines)}
    c_file = tmp_path / 'sem.c'
    c_file.write_text(src, encoding='utf-8')
    exe = tmp_path / 'sem'
    res = subprocess.run(['gcc', '-O0', '-w', str(c_file), '-o', str(exe), '-lm'],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    out = subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout
    return {k: int(v) for k, v in (line.split('=') for line in out.split())}


# ---------------------------------------------------------------------------
# PAS03 – ejecución: enteros, flags y memoria
# ---------------------------------------------------------------------------

class TestIntegerExecution:

    def test_adds_overflow(self, tmp_path):
        s = _run(tmp_path, [('adds', 'r0, r1, r2')], r1=0x7fffffff, r2=1)
        assert s['r0'] == 0x80000000
        assert (s['N'], s['Z'], s['C'], s['V']) == (1, 0, 0, 1)

    def test_subs_borrow(self, tmp_path):
        s = _run(tmp_path, [('subs', 'r0, r1, #1')], r1=0)
        assert s['r0'] == 0xffffffff
        assert (s['N'], s['Z'], s['C'], s['V']) == (1, 0, 0, 0)

    def test_cmp_equal_sets_z_and_c(self, tmp_path):
        s = _run(tmp_path, [('cmp', 'r0, #5')], r0=5)
        assert (s['Z'], s['C']) == (1, 1)

    def test_movs_sets_flags(self, tmp_path):
        s = _run(tmp_path, [('movs', 'r0, #0')], r0=7, V=1)
        assert (s['r0'], s['Z'], s['N'], s['V']) == (0, 1, 0, 1)

    def test_lsls_carry_out(self, tmp_path):
        s = _run(tmp_path, [('lsls', 'r0, r1, #1')], r1=0x80000001)
        assert (s['r0'], s['C']) == (2, 1)

    def test_asr_32(self, tmp_path):
        s = _run(tmp_path, [('asrs', 'r0, r1, #0x20')], r1=0x80000000)
        assert (s['r0'], s['C']) == (0xffffffff, 1)

    def test_ands_replicated_immediate_keeps_carry(self, tmp_path):
        # 0x10001000 es un inmediato Thumb replicado (no rotado): C no cambia
        s = _run(tmp_path, [('ands', 'r2, r2, #0x10001000')], r2=0xffffffff, C=1)
        assert (s['r2'], s['C']) == (0x10001000, 1)

    def test_ands_rotated_immediate_sets_carry(self, tmp_path):
        s = _run(tmp_path, [('ands', 'r2, r2, #0x80000000')], r2=0xffffffff, C=0)
        assert (s['r2'], s['C']) == (0x80000000, 1)

    def test_adc_and_rsb(self, tmp_path):
        s = _run(tmp_path, [('adc', 'r0, r1, r2'), ('rsb', 'r3, r1, #10')], r1=3, r2=2, C=1)
        assert (s['r0'], s['r3']) == (6, 7)

    def test_it_block_condition(self, tmp_path):
        s = _run(tmp_path, [('it', 'eq'), ('addeq', 'r0, #1'), ('addne', 'r1, #1')], Z=0)
        assert (s['r0'], s['r1']) == (0, 1)

    def test_post_and_pre_index_writeback(self, tmp_path):
        s = _run(tmp_path, [('str', 'r2, [r1], #4'), ('ldr', 'r3, [r1, #-4]!')],
                 r1=_RAM, r2=0xdeadbeef)
        assert s['m0'] == 0xdeadbeef
        assert s['r3'] == 0xdeadbeef
        assert s['r1'] == _RAM

    def test_shifted_register_offset(self, tmp_path):
        s = _run(tmp_path, [('ldr', 'r0, [r1, r2, lsl #2]')], r1=_RAM, r2=3, m3=42)
        assert s['r0'] == 42

    def test_push_pop(self, tmp_path):
        s = _run(tmp_path, [('push', '{r4, lr}'), ('movs', 'r4, #0'), ('pop', '{r4, r5}')],
                 r13=_RAM + 0x100, r4=11, r14=22)
        assert (s['r4'], s['r5'], s['r13']) == (11, 22, _RAM + 0x100)

    def test_ldrd_strd(self, tmp_path):
        s = _run(tmp_path, [('strd', 'r2, r3, [r1, #8]'), ('ldrd', 'r4, r5, [r1, #8]')],
                 r1=_RAM, r2=1, r3=2)
        assert (s['m2'], s['m3'], s['r4'], s['r5']) == (1, 2, 1, 2)

    def test_umull_and_division(self, tmp_path):
        s = _run(tmp_path, [('umull', 'r0, r1, r2, r3'), ('udiv', 'r4, r2, r5'),
                            ('sdiv', 'r6, r7, r8')],
                 r2=0xffffffff, r3=2, r5=0, r7=0x80000000, r8=0xffffffff)
        assert (s['r0'], s['r1']) == (0xfffffffe, 1)
        assert s['r4'] == 0                  # división por cero → 0 (DIV_0_TRP = 0)
        assert s['r6'] == 0x80000000         # INT_MIN / -1

    def test_bitfields(self, tmp_path):
        s = _run(tmp_path, [('ubfx', 'r0, r1, #4, #8'), ('sbfx', 'r2, r1, #4, #8'),
                            ('bfi', 'r3, r1, #8, #4')], r1=0xf80, r3=0)
        assert (s['r0'], s['r2'], s['r3']) == (0xf8, 0xfffffff8, 0x0)

    def test_literal_constant(self, tmp_path):
        s = _run(tmp_path, [('ldr', 'r0, [pc, #4]', bytes.fromhex('efbeadde'))])
        assert s['r0'] == 0xdeadbeef

    def test_strex_requires_monitor(self, tmp_path):
        s = _run(tmp_path, [('strex', 'r0, r2, [r1]'), ('ldrex', 'r3, [r1]'),
                            ('strex', 'r4, r2, [r1]')], r1=_RAM, r2=9, m0=5)
        assert s['r0'] == 1                  # sin ldrex previo: falla y no escribe
        assert s['r3'] == 5
        assert (s['r4'], s['m0']) == (0, 9)

    def test_indirect_call(self, tmp_path):
        s = _run(tmp_path, [('blx', 'r3')], r3=0x8001235)
        assert s['call_indirect'] == 0x8001235


# ---------------------------------------------------------------------------
# PAS04 – ejecución: VFP
# ---------------------------------------------------------------------------

class TestVfpExecution:

    def test_add_and_compare(self, tmp_path):
        s = _run(tmp_path, [('vadd.f32', 's2, s0, s1'), ('vcmpe.f32', 's0, s1'),
                            ('vmrs', 'apsr_nzcv, fpscr')], s0=_f32(1.0), s1=_f32(2.0))
        assert s['s2'] == _f32(3.0)
        assert (s['N'], s['Z'], s['C'], s['V']) == (1, 0, 0, 0)    # 1.0 < 2.0

    def test_default_nan(self, tmp_path):
        # inf + -inf: operación inválida → NaN por defecto de ARM (positivo)
        s = _run(tmp_path, [('vadd.f32', 's2, s0, s1')],
                 s0=_f32(float('inf')), s1=_f32(float('-inf')))
        assert s['s2'] == 0x7fc00000

    def test_signaling_nan_is_quieted(self, tmp_path):
        s = _run(tmp_path, [('vmul.f32', 's2, s0, s1')], s0=_f32(2.0), s1=0x7f800001)
        assert s['s2'] == 0x7fc00001

    def test_vneg_flips_nan_sign(self, tmp_path):
        s = _run(tmp_path, [('vneg.f32', 's1, s0')], s0=0x7fc00000)
        assert s['s1'] == 0xffc00000

    def test_convert_saturates(self, tmp_path):
        s = _run(tmp_path, [('vcvt.s32.f32', 's1, s0'), ('vcvt.u32.f32', 's3, s2'),
                            ('vcvt.s32.f32', 's5, s4')],
                 s0=_f32(3e9), s2=_f32(-5.0), s4=0x7fc00000)
        assert (s['s1'], s['s3'], s['s5']) == (0x7fffffff, 0, 0)

    def test_fixed_point_convert(self, tmp_path):
        s = _run(tmp_path, [('vcvt.f32.s32', 's0, s0, #4')], s0=0xfffffff0)   # -16 / 2^4
        assert s['s0'] == _f32(-1.0)

    def test_double_from_core_registers(self, tmp_path):
        lo, hi = struct.unpack('<II', struct.pack('<d', 1.5))
        s = _run(tmp_path, [('vmov', 'd0, r0, r1'), ('vadd.f64', 'd1, d0, d0'),
                            ('vmov', 'r2, r3, d1')], r0=lo, r1=hi)
        assert struct.unpack('<d', struct.pack('<II', s['r2'], s['r3']))[0] == 3.0

    def test_immediate_and_fma(self, tmp_path):
        s = _run(tmp_path, [('vmov.f32', 's0, #2.500000e+00'), ('vmov.f32', 's1, #4.000000e+00'),
                            ('vfma.f32', 's2, s0, s1')], s2=_f32(1.0))
        assert s['s2'] == _f32(11.0)

    def test_vpush_vpop(self, tmp_path):
        s = _run(tmp_path, [('vpush', '{d8}'), ('vmov.f32', 's16, #1.000000e+00'),
                            ('vpop', '{d8}')], r13=_RAM + 0x40, s16=7, s17=8)
        assert (s['s16'], s['s17'], s['r13']) == (7, 8, _RAM + 0x40)


# ---------------------------------------------------------------------------
# PAS05 – integración en el translator Cortex-M
# ---------------------------------------------------------------------------

class TestCortexMTranslatorIntegration:

    def _translate(self, insns):
        from flashback.arch.cortexm import CortexMEnricher, CortexMTranslator
        from flashback.arch.cortexm.disassembler import _CORTEXM_MNEMONICS
        from flashback.core.cfg_builder import BinaryMeta, CFGBuilder, RawInstruction
        raw = {}
        addr = 0x100
        for m, o, size in insns:
            raw[addr] = RawInstruction(addr, m, o, '00' * size, size)
            addr += size
        meta = BinaryMeta(path='/fw.elf', sha256='a' * 64, entry_point=0x100,
                          architecture='cortexm', func_symbols={0x100: 'f'})
        cfg = CortexMEnricher().enrich(
            CFGBuilder(arch_mnemonics=_CORTEXM_MNEMONICS).build(raw, meta), granularity='none')
        return CortexMTranslator(tool_version='test').translate(cfg)

    def test_no_unsupported_and_dispatcher(self):
        c = self._translate([
            ('movs', 'r0, #1', 2), ('lsls', 'r1, r0, #3', 2), ('vmov', 's0, r1', 4),
            ('vcvt.f32.s32', 's0, s0', 4), ('mrs', 'r2, apsr', 4), ('blx', 'r3', 2),
            ('bx', 'lr', 2),
        ])
        assert 'UNSUPPORTED' not in c
        assert 'no simulado' not in c
        assert 'static void __call_indirect(uint32_t target, uint32_t site)' in c
        assert 'case 0x100U: func_100(); return;' in c
        assert '__call_indirect(r3, 0x110U);' in c
        assert 'r2 = ((uint32_t)N << 31)' in c        # mrs apsr → flags NZCV
