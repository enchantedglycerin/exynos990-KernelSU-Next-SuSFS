# exynos990-KernelSU-Next-SuSFS

**KernelSU-Next + SuSFS v2.0.0 for the Samsung Galaxy S20 series (Exynos 990 / universal9830).**
One kernel source; pick the device at build time. Built from stock Samsung source (Linux 4.19.87,
One UI 5 / Android 13) — no custom ROM required.

## Supported models

| Model | Codename | `build.sh -m` | Status |
|:--|:--|:--|:--|
| Galaxy S20+ (SM-G985F) | y2s | `y2s` | ✅ **Tested** (G985FXXSNHYB1) |
| Galaxy S20 (SM-G980F) | x1s | `x1s` | ⚠️ Experimental — untested |
| Galaxy S20 Ultra (SM-G988B) | z3s | `z3s` | ⚠️ Experimental — untested |

> Only **SM-G985F** is boot-tested. The x1s (SM-G980F) and z3s (SM-G988B) builds compile from their own
> Samsung source drop with the same integration but have **not** been booted on hardware.
>
> **5G variants** — SM-G986B (S20+ 5G) and SM-G981B (S20 5G) — share the `y2s` / `x1s` codename and source,
> so `build.sh -m y2s` / `-m x1s` *should* apply; however no G986B/G981B source drop was used here and they
> are **completely unverified**. Not for Snapdragon variants; Android 14+ is unsupported.

## Build

```sh
# Toolchain: AOSP Clang r370808 (10.0.1) + GCC 4.9. Place at ../tc/clang10 and ../tc/gcc49,
# or export CLANG_DIR / GCC_DIR. DO NOT use Clang 14+ (bootloops Exynos 990).
./build.sh -m y2s        # or x1s / z3s
# -> out_<model>/arch/arm64/boot/Image
```

Config is layered: `arch/arm64/configs/exynos9830-<model>_defconfig` (Samsung base) + `arch/arm64/configs/ksu.config`
(KernelSU-Next + SuSFS + security-disable fragment). `build.sh` merges them.

## Flash

Package `out_<model>/arch/arm64/boot/Image` with [AnyKernel3](https://github.com/osm0sis/AnyKernel3)
(keeps your device's own dtb + ramdisk) or repack your stock `boot.img`. Requires an unlocked
bootloader (trips KNOX). **Back up your stock boot image first.**

## Credits

KernelSU-Next team · [simonpunk](https://gitlab.com/simonpunk/susfs4ksu) / sidex15 / backslashxx (SuSFS)
· JackA1ltman (non-GKI 4.19 SuSFS backport) · [osm0sis](https://github.com/osm0sis/AnyKernel3) (AnyKernel3)
· Samsung Open Source Release Center.

See `PROVENANCE.md` for exact upstream commits and Samsung source packages. Kernel is GPL-2.0.
