# exynos990-KernelSU-Next-SuSFS

**KernelSU-Next + SuSFS v2.0.0 for the Samsung Galaxy S20 series (Exynos 990 / universal9830).**
One kernel source; pick the device at build time. Built from stock Samsung source (Linux 4.19.87,
One UI 5 / Android 13) — no custom ROM required.

## Supported models

| Model | Codename | `build.sh -m` | Status |
|:--|:--|:--|:--|
| Galaxy S20+ (SM-G985F) | y2s | `g985f` | ✅ **Tested** (G985FXXSNHYB1) |
| Galaxy S20 (SM-G980F) | x1s | `g980f` | ⚠️ Experimental — untested |
| Galaxy S20 Ultra (SM-G988B) | z3s | `g988b` | ⚠️ Experimental — untested |
| Galaxy S20+ 5G (SM-G986B) | y2s | `g986b` | ⚠️ Experimental — untested |
| Galaxy S20 5G (SM-G981B) | x1s | `g981b` | ⚠️ Experimental — untested |

> Only **SM-G985F** is boot-tested. Every other model is built with **its own defconfig + device tree**
> on the shared **G985F driver kernel** (the other drops' driver differences — mm, Mali GPU, NPU — are
> **not** imported; see `PROVENANCE.md`) and has **not** been booted on hardware.
>
> **Codename note:** the 4G and 5G siblings report the same `ro.product.device` (G985F & G986B = `y2s`;
> G980F & G981B = `x1s`), so the flasher's codename check can't tell them apart — pick the zip for your
> exact model. Not for Snapdragon variants; Android 14+ is unsupported.

## Build

```sh
# Toolchain: AOSP Clang r370808 (10.0.1) + GCC 4.9. Place at ../tc/clang10 and ../tc/gcc49,
# or export CLANG_DIR / GCC_DIR. DO NOT use Clang 14+ (bootloops Exynos 990).
./build.sh -m g985f      # or g980f / g988b / g986b / g981b
# -> out_<model>/arch/arm64/boot/Image
```

Config is layered: `arch/arm64/configs/exynos9830-<model>_defconfig` (Samsung base) + `arch/arm64/configs/ksu.config`
(KernelSU-Next + SuSFS + security-disable fragment). `build.sh` merges them.

## Flash

Build a flashable zip from the Image with the bundled packaging:

```sh
./build.sh -m g985f      # -> out_g985f/arch/arm64/boot/Image
./mkzip.sh  -m g985f     # -> AnyKernel3_KSUNext_SUSFS_G985F_S20plus.zip   (or g980f / g988b / ...)
```

`mkzip.sh` wraps the built Image in the vendored [AnyKernel3](https://github.com/osm0sis/AnyKernel3)
framework (`anykernel/`) and generates `anykernel.sh` with the device-name codename check for the
model. Flash the zip in TWRP / OrangeFox (it keeps your device's own dtb + ramdisk), or repack your
stock `boot.img`. Requires an unlocked bootloader (trips KNOX). **Back up your stock boot image first.**

> The check gates on `ro.product.device` (codename), **not** `ro.product.model` — the model is
> unreliable in recovery and can falsely reject a genuine device. A 4G/5G sibling can share a codename,
> so **check your exact model before flashing.**

## Credits

KernelSU-Next team · [simonpunk](https://gitlab.com/simonpunk/susfs4ksu) / sidex15 / backslashxx (SuSFS)
· JackA1ltman (non-GKI 4.19 SuSFS backport) · [osm0sis](https://github.com/osm0sis/AnyKernel3) (AnyKernel3)
· Samsung Open Source Release Center.

See `PROVENANCE.md` for exact upstream commits and Samsung source packages. Kernel is GPL-2.0.
