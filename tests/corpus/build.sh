#!/usr/bin/env bash
# build.sh — Compila todos los binarios del corpus de evaluación.
# Requiere: gcc en el PATH.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
BIN_DIR="$SCRIPT_DIR/binaries"

mkdir -p "$BIN_DIR"

ok=0; fail=0
for src in "$SRC_DIR"/0*.c; do
    name=$(basename "$src" .c)
    out="$BIN_DIR/${name}.elf"
    if gcc -O0 -g -no-pie -fno-stack-protector "$src" -o "$out" 2>&1; then
        echo "  OK  $out"
        ok=$((ok + 1))
    else
        echo "  FAIL  $src"
        fail=$((fail + 1))
    fi
done

echo ""
echo "Compilados: $ok  Fallidos: $fail"
[ "$fail" -eq 0 ]
