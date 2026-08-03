"""
CLI de Flashback.

Uso:
    python flashback.py <binario.elf> -o <salida.c>
    python flashback.py <binario.elf> -o <salida.c> --export-cfg <salida.json>
    python flashback.py <binario.elf> -o <salida.c> --functions main,foo
    python flashback.py <binario.elf> -o <salida.c> --granularity block
    python flashback.py <binario.elf> -o <salida.c> --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

VERSION = '0.1.0'


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='flashback',
        description='Binary-to-C reconstruction with bidirectional traceability.',
    )
    p.add_argument('binary', help='Binario ELF de entrada (x86-64, x86, ARM64 o ARM32)')
    p.add_argument('-o', '--output', help='Fichero C de salida (default: <binario>.c)')
    p.add_argument(
        '--export-cfg', metavar='FILE',
        help='Exportar el CFG enriquecido a JSON',
    )
    p.add_argument(
        '--functions', metavar='FUNC1,FUNC2',
        help='Traducir solo estas funciones (separadas por coma)',
    )
    p.add_argument(
        '--granularity',
        choices=['none', 'block', 'instruction', 'selective'],
        default='selective',
        help='Política de trazabilidad (default: selective)',
    )
    p.add_argument(
        '--arch',
        choices=['auto', 'x86_64', 'x86', 'arm64', 'arm32', 'cortexm'],
        default='auto',
        help='Arquitectura del binario (default: auto)',
    )
    p.add_argument('--tui', action='store_true', help='Lanzar interfaz TUI (roadmap)')
    p.add_argument('-v', '--verbose', action='store_true', help='Logging detallado')
    p.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    return p


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )


def _detect_arch(binary_path: Path) -> str:
    """Auto-detecta la arquitectura del ELF leyendo la cabecera.

    Devuelve 'x86_64', 'x86', 'arm64' o 'arm32'.
    Lanza RuntimeError para arquitecturas no soportadas.
    """
    try:
        import lief
        elf = lief.parse(str(binary_path))
        if elf is None:
            return 'x86_64'
        arch = elf.header.machine_type
        if arch == lief.ELF.ARCH.X86_64:
            return 'x86_64'
        if arch == lief.ELF.ARCH.AARCH64:
            return 'arm64'
        if arch == lief.ELF.ARCH.I386:
            return 'x86'
        if arch == lief.ELF.ARCH.ARM:
            # Thumb bit en entry + sin sección .dynamic → firmware Cortex-M bare-metal
            if elf.entrypoint & 1:
                has_dynamic = False
                try:
                    has_dynamic = elf.get_section('.dynamic') is not None
                except Exception:
                    pass
                if not has_dynamic:
                    return 'cortexm'
            return 'arm32'
        raise RuntimeError(
            f'Arquitectura no soportada: {arch}. '
            f'Flashback admite: x86-64, x86 (i386), AArch64 (ARM64), ARM32.'
        )
    except RuntimeError:
        raise
    except Exception:
        return 'x86_64'


def _build_pipeline(arch: str):
    """Devuelve (Disassembler, Enricher, Translator, DisassemblerError) para la arquitectura dada."""
    if arch == 'arm64':
        from flashback.arch.arm64.disassembler import Arm64Disassembler, DisassemblerError
        from flashback.arch.arm64.enricher import Arm64Enricher
        from flashback.arch.arm64.translator import Arm64Translator
        return Arm64Disassembler(), Arm64Enricher(), Arm64Translator(tool_version=VERSION), DisassemblerError
    elif arch == 'x86_64':
        from flashback.arch.x86_64.disassembler import X86_64Disassembler, DisassemblerError
        from flashback.arch.x86_64.enricher import X86_64Enricher
        from flashback.arch.x86_64.translator import X86_64Translator
        return X86_64Disassembler(), X86_64Enricher(), X86_64Translator(tool_version=VERSION), DisassemblerError
    elif arch == 'x86':
        from flashback.arch.x86.disassembler import X86Disassembler, DisassemblerError
        from flashback.arch.x86.enricher import X86Enricher
        from flashback.arch.x86.translator import X86Translator
        return X86Disassembler(), X86Enricher(), X86Translator(tool_version=VERSION), DisassemblerError
    elif arch == 'arm32':
        from flashback.arch.arm32.disassembler import Arm32Disassembler, DisassemblerError
        from flashback.arch.arm32.enricher import Arm32Enricher
        from flashback.arch.arm32.translator import Arm32Translator
        return Arm32Disassembler(), Arm32Enricher(), Arm32Translator(tool_version=VERSION), DisassemblerError
    elif arch == 'cortexm':
        from flashback.arch.cortexm.disassembler import CortexMDisassembler, DisassemblerError
        from flashback.arch.cortexm.enricher import CortexMEnricher
        from flashback.arch.cortexm.translator import CortexMTranslator
        return CortexMDisassembler(), CortexMEnricher(), CortexMTranslator(tool_version=VERSION), DisassemblerError
    else:
        raise RuntimeError(
            f'Arquitectura "{arch}" no reconocida. '
            f'Usa --arch x86_64 | x86 | arm64 | arm32.'
        )


def run(args: argparse.Namespace) -> int:
    from flashback.core.translator import TranslatorError
    from flashback.core.exporter import Exporter, ExporterError

    binary = Path(args.binary)
    output = Path(args.output) if args.output else binary.with_suffix('.c')
    logger = logging.getLogger('flashback')

    # Detectar arquitectura
    try:
        arch = args.arch if args.arch != 'auto' else _detect_arch(binary)
    except RuntimeError as exc:
        print(f'Error: {exc}', file=__import__('sys').stderr)
        return 1
    logger.info(f'[*] Arquitectura: {arch}')

    try:
        dis, enricher, translator, DisassemblerError = _build_pipeline(arch)
    except RuntimeError as exc:
        print(f'Error: {exc}', file=__import__('sys').stderr)
        return 1

    try:
        # 1. Desensamblar
        logger.info(f'[*] Cargando ELF: {binary.name}')
        cfg = dis.disassemble(str(binary))
        # Pasar SP inicial al traductor Cortex-M (extraído del vector table)
        if hasattr(dis, '_initial_sp') and hasattr(translator, '_initial_sp'):
            translator._initial_sp = dis._initial_sp
        logger.info(
            f'[*] Desensamblado: {sum(1 for f in cfg.functions.values() if not f.is_plt)} funciones, '
            f'{len(cfg.instructions)} instrucciones'
        )
        logger.info(f'[*] CFG construido: {len(cfg.basic_blocks)} bloques, {len(cfg.edges)} aristas')

        # 2. Enriquecer
        enriched = enricher.enrich(cfg, granularity=args.granularity)
        ext_calls = sum(
            1 for i in enriched.instructions.values()
            if any(a.type == 'external_call' for a in i.annotations)
        )
        syscalls = sum(
            1 for i in enriched.instructions.values()
            if any(a.type == 'syscall' for a in i.annotations)
        )
        logger.info(f'[*] Enriquecimiento: {ext_calls} llamadas externas, {syscalls} syscalls')

        # 3. Exportar CFG si se pidió
        if args.export_cfg:
            exp = Exporter()
            exp.save(enriched, args.export_cfg)
            logger.info(f'[*] CFG exportado en {args.export_cfg}')

        # 4. Traducir
        c_code = translator.translate(enriched)
        logger.info(f'[*] Traducción: {len(enriched.basic_blocks)} bloques → {c_code.count(chr(10))} líneas de C')

        # 5. Guardar
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(c_code, encoding='utf-8')
        logger.info(f'[*] Salida escrita en {output}')
        print(f'{output}')
        return 0

    except DisassemblerError as e:
        print(f'Error de desensamblado: {e}', file=sys.stderr)
        return 1
    except (TranslatorError, ExporterError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrumpido', file=sys.stderr)
        return 130


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    if args.tui:
        print('TUI no implementada todavía (roadmap v0.3)', file=sys.stderr)
        return 1

    return run(args)


if __name__ == '__main__':
    sys.exit(main())
