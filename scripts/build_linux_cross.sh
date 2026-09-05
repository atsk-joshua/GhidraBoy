#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ZIG:=$PWD/.deps/zig-aarch64-macos-0.14.1/zig}"
export ZIG_GLOBAL_CACHE_DIR="$PWD/.deps/zig-cache"
export ZIG_LOCAL_CACHE_DIR="$PWD/.deps/zig-local"
export PATH="$PWD/.deps/rgbds-bin:$PATH"
target=x86_64-linux-gnu.2.28
objects=()
for source in .deps/SameBoy/Core/*.c; do objects+=("build-linux/obj/Core/$(basename "$source").o"); done
make -C .deps/SameBoy -j "${JOBS:-4}" "${objects[@]}" PLATFORM=Linux CONF=release OBJ=build-linux/obj LIBDIR=build-linux/lib CC="$ZIG cc -target $target"
# Zig does not support the upstream relocatable-link (-r) convenience target.
# Link the objects produced by the upstream rules directly into our shared ABI.
mkdir -p build
"$ZIG" cc -target "$target" -shared -fPIC -std=gnu11 -O2 -I.deps/SameBoy -Inative native/ghigbc.c .deps/SameBoy/build-linux/obj/Core/*.o -o build/libghigbc.so -lm -lpthread
file build/libghigbc.so
