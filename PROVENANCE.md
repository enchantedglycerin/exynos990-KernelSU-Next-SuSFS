# Build provenance

**Platform:** Samsung Exynos 990 / `universal9830` — Linux **4.19.87** (non-GKI).
One tree builds all Galaxy S20 Exynos variants; device is selected at build time (`build.sh -m`).

## Samsung source packages (one per device family)
| Model(s) | Codename | Samsung Open Source package | Role in this tree |
|:--|:--|:--|:--|
| Galaxy S20+ / S20+ 5G (SM-G985F / G986B) | y2s | `SM-G985F_SWA_13_Opensource` | **trunk** (shared kernel source + drivers) |
| Galaxy S20 / S20 5G (SM-G980F / G981B) | x1s | `SM-G980F_13_Opensource` | device tree + defconfig imported |
| Galaxy S20 Ultra (SM-G988B) | z3s | `SM-G988B_13_Opensource` | device tree + defconfig imported |

The three drops share the same universal9830 codebase. The **G985F** drop is the trunk; only the
**device-specific deltas** from the G980F/G988B drops were imported (their `arch/arm64/boot/dts/samsung/exynos990-*.dts`
and `arch/arm64/configs/exynos9830-*_defconfig`, plus the merged dts Makefile). The shared drivers
(GPU/NPU/mm) are the G985F-drop revisions — the inter-drop differences there are Samsung packaging-date
revisions, not per-device changes (same SoC). Each model was clean-built from this tree and produced an
Image identical to its standalone build.

## Integrated components (exact revisions)
- **KernelSU-Next** — https://github.com/KernelSU-Next/KernelSU-Next
  tag `v3.1.0-legacy-susfs`, commit `ba4422f0556e10f40dda1887631d87a18ede4ec5` (manager version code 33024)
- **SuSFS v2.0.0** — non-GKI backport, `sys_reboot` transport. Reference: JackA1ltman/NonGKI_Kernel_Build_2nd
  @ `230947c728e537049dcef1b12572d85e8699faa5`; sus_path ABI aligned to sidex15/susfs4ksu.

## Toolchain
AOSP Clang 10.0.1 (r370808) + GCC 4.9 / binutils 2.27. **Do NOT use Clang 14+** (bootloops Exynos 990).

## Local modifications vs. Samsung source
- KernelSU-Next manual hooks (`CONFIG_KSU_MANUAL_HOOK`); SuSFS v2.0.0 (fs/susfs.c, include/linux/susfs*.h).
- sus_path ABI = standard pathname-first layout (official SuSFS module + WebUI compatible).
- fs/susfs.c memory-safety hardening (NULL-alloc returns, user-path NUL-termination, kzalloc nodes).
- Samsung security disabled for kernel root: CONFIG_UH (RKP), SECURITY_DEFEX, FIVE, RKP_CFP, KDP*, PROCA.

## Testing status
Only **SM-G985F** boot-tested (firmware **G985FXXSNHYB1**, Android 13). x1s / z3s (and G986B) are
compiled from their source with the same integration but **not boot-tested** — experimental.
