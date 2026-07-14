#!/bin/bash
# ============================================================================
#  KernelSU-Next + SuSFS v2.0.0  —  Galaxy S20 (Exynos 990 / universal9830)
#  Unified build for all S20 Exynos variants.
#
#  Usage:   ./build.sh -m <g985f|g980f|g988b|g986b|g981b>   (model number, as in Settings)
#             g985f = Galaxy S20+ 4G   (SM-G985F)   [TESTED]
#             g980f = Galaxy S20 4G    (SM-G980F)   [EXPERIMENTAL]
#             g988b = Galaxy S20 Ultra (SM-G988B)   [EXPERIMENTAL]
#             g986b = Galaxy S20+ 5G   (SM-G986B)   [EXPERIMENTAL]
#             g981b = Galaxy S20 5G    (SM-G981B)   [EXPERIMENTAL]
#
#  Config is layered:  arch/arm64/configs/exynos9830-<model>_defconfig  (Samsung base)
#                    + arch/arm64/configs/ksu.config                    (KSU-Next + SuSFS)
#  All targets share the G985F drop's kernel DRIVERS (mm / Mali GPU / NPU); only each
#  model's defconfig + device tree is its own. Only y2s (SM-G985F) is hardware-tested.
#
#  Toolchain: AOSP Clang r370808 (10.0.1) + GCC 4.9 (binutils 2.27).
#    Set CLANG_DIR / GCC_DIR, or place them at ../tc/clang10 and ../tc/gcc49.
#    >>> DO NOT use Clang 14+ : it miscompiles Exynos 990 early asm -> bootloop. <<<
# ============================================================================
set -e

MODEL=g985f
while getopts "m:" o; do case $o in m) MODEL=$OPTARG ;; esac; done
case "$MODEL" in
  g985f) BASE=exynos9830-y2slte_defconfig ;;
  g980f) BASE=exynos9830-x1slte_defconfig ;;
  g988b) BASE=exynos9830-z3sxxx_defconfig ;;
  g986b) BASE=exynos9830-y2sxxx_defconfig ;;
  g981b) BASE=exynos9830-x1sxxx_defconfig ;;
  *)   echo "Unknown model '$MODEL' (use g985f|g980f|g988b|g986b|g981b)"; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")" && pwd)"
CLANG_DIR="${CLANG_DIR:-$ROOT/../tc/clang10}"
GCC_DIR="${GCC_DIR:-$ROOT/../tc/gcc49}"
[ -x "$CLANG_DIR/bin/clang" ] || { echo "ERROR: clang not found at $CLANG_DIR — set CLANG_DIR"; exit 1; }
export PATH="$CLANG_DIR/bin:$GCC_DIR/bin:$PATH"
export ARCH=arm64 LC_ALL=C
# Samsung Kconfig macros ($(PLATFORM_VERSION), $(SEC_BUILD_CONF_VENDOR_BUILD_OS)) REQUIRE these,
# or defconfig parsing fails with "syntax error" and drops subsystems (sdcardfs/mali/hall).
export PLATFORM_VERSION=13 ANDROID_MAJOR_VERSION=t SEC_BUILD_CONF_VENDOR_BUILD_OS=13

OUT="out_$MODEL"
HCF='-fcommon -Wno-error -Wno-deprecated-declarations -Wno-implicit-function-declaration'
KCF='-Wno-unknown-warning-option -fno-builtin-stpcpy -fno-builtin-strlcpy -Wno-error -Wno-strict-prototypes -Wno-old-style-definition -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-unused-function -Wno-implicit-int -Wno-format'
COMMON="ARCH=arm64 O=$OUT CC=clang CROSS_COMPILE=aarch64-linux-android- CLANG_TRIPLE=aarch64-linux-gnu-"

cd "$ROOT"
echo ">> building $MODEL  (base=$BASE + ksu.config)  clang=$("$CLANG_DIR/bin/clang" --version | head -1)"
make $COMMON "KBUILD_HOSTCFLAGS=$HCF" "HOSTCFLAGS=$HCF" -j"$(nproc)" "$BASE"
cat arch/arm64/configs/ksu.config >> "$OUT/.config"
make $COMMON "KBUILD_HOSTCFLAGS=$HCF" "HOSTCFLAGS=$HCF" -j"$(nproc)" olddefconfig
make $COMMON "KBUILD_HOSTCFLAGS=$HCF" "HOSTCFLAGS=$HCF" "KCFLAGS=$KCF" -j"$(nproc)" Image

IMG="$OUT/arch/arm64/boot/Image"
if [ -f "$IMG" ]; then
  echo ">> DONE: $IMG ($(stat -c%s "$IMG") bytes)"
  echo ">> Flash via AnyKernel3 (keeps your device's dtb/ramdisk) or repack your stock boot.img."
else
  echo ">> BUILD FAILED"; exit 1
fi
