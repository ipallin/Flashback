#!/usr/bin/env python3
"""
Flashback — punto de entrada principal.

Uso:
    python flashback.py firmware.elf -o firmware.c
    python flashback.py malware.elf -o malware.c --export-cfg cfg.json
    python flashback.py target.elf -o target.c --functions main,parse_input
    python flashback.py sample.elf -o sample.c --verbose
    python flashback.py sample.elf --tui
"""

import sys
from flashback.ui.cli import main

if __name__ == '__main__':
    sys.exit(main())
