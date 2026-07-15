#!/usr/bin/env bash
# Build the static aarch64 frida_anon_hide helper with the Android NDK.
# Usage: NDK=/path/to/android-ndk ./build.sh   (defaults to ~/android-ndk-r29)
set -euo pipefail

NDK="${NDK:-$HOME/android-ndk-r29}"
API="${API:-29}"
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
CLANG="$BIN/aarch64-linux-android${API}-clang"

[ -x "$CLANG" ] || { echo "clang not found: $CLANG"; exit 1; }

cd "$(dirname "$0")"
"$CLANG" -O2 -static -Wall -Wextra -o frida_anon_hide frida_anon_hide.c
"$BIN/llvm-strip" frida_anon_hide
echo "built: $(pwd)/frida_anon_hide"
file frida_anon_hide
