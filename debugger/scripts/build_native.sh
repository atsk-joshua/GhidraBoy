#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.deps/rgbds-bin:$PATH"
make -C .deps/SameBoy -j "${JOBS:-4}" lib CONF=release
make -C .deps/SameBoy -j "${JOBS:-4}" bootroms CONF=release
mkdir -p build
if [[ $(uname -s) == Darwin ]]; then
  suffix=dylib
  libs=(-framework Cocoa -lm -lpthread)
else
  suffix=so
  libs=(-lm -lpthread)
fi
${CC:-cc} -shared -fPIC -std=gnu11 -O2 -Wall -Wextra -I.deps/SameBoy -Inative native/ghigbc.c .deps/SameBoy/build/lib/libsameboy.a -o "build/libghigbc.$suffix" "${libs[@]}"
rgbasm -o build/banks.o tests/fixtures/banks.asm
rgblink -p 0 -o build/teaching.gbc -n build/teaching.sym build/banks.o
rgbfix -v -p 0 -C -m 0x19 -t GHIGBC-LAB build/teaching.gbc
# The same self-authored ROM-bank exercise with a DMG header; CGB-only RAM exercises are separate.
rgblink -p 0 -o build/teaching-dmg.gb build/banks.o
rgbfix -v -p 0 -m 0x19 -t GHIGBC-DMG build/teaching-dmg.gb
