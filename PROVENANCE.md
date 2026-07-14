# Build provenance

**Platform:** Samsung Exynos 990 / `universal9830` — Linux **4.19.87** (non-GKI).
One tree builds all Galaxy S20 Exynos variants; device is selected at build time (`build.sh -m`).

## Samsung source packages (one per device family)
| Model(s) | Codename | Samsung Open Source package | Role in this tree |
|:--|:--|:--|:--|
| Galaxy S20+ (SM-G985F) | y2slte | `SM-G985F_SWA_13_Opensource` | **trunk** (shared kernel source + drivers) |
| Galaxy S20 (SM-G980F) | x1slte | `SM-G980F_13_Opensource` | dts + defconfig imported |
| Galaxy S20 Ultra (SM-G988B) | z3s | `SM-G988B_13_Opensource` | dts + defconfig imported |
| Galaxy S20+ 5G (SM-G986B) | y2s | `SM-G986B_13_Opensource` | dts + defconfig imported |
| Galaxy S20 5G (SM-G981B) | x1s | `SM-G981B_13_Opensource` | dts + defconfig imported |

The five drops share the same universal9830 codebase. The **G985F** drop is the **trunk** — all kernel
drivers (mm, Mali GPU, NPU, firmware, etc.) are the G985F revisions. From the other four drops
(G980F / G988B / G986B / G981B) only the **device config** was imported: their
`arch/arm64/configs/exynos9830-*_defconfig` and `arch/arm64/boot/dts/samsung/exynos990-*.dts` overlays,
plus the merged dts Makefile.

**The other drops also differ from G985F in shared driver files** — e.g. `mm/memory.c`, `mm/ksm.c`,
`firmware/npu/NPU.bin`, and many Mali/NPU sources — and **those differences were NOT imported**. Each
non-G985F target is therefore the **G985F driver kernel built with that model's defconfig + device
tree**, not a full build of that model's own source. Whether the un-imported driver differences matter
on the other models is **unverified** — only G985F is boot-tested. (Builds are not byte-reproducible: the
kernel embeds a timestamp/host string, so SHA-256 differs between builds.)

**Runtime codenames:** the 4G/5G siblings report the same `ro.product.device` — G985F and G986B both
`y2s`; G980F and G981B both `x1s`; G988B `z3s`. Their *build* codenames differ (defconfig `y2slte` vs
`y2sxxx`, `x1slte` vs `x1sxxx`), but at runtime the flasher's codename check cannot tell 4G from 5G —
select the zip for your exact model.

## Integrated components (exact revisions)
- **KernelSU-Next** — https://github.com/KernelSU-Next/KernelSU-Next
  tag `v3.1.0-legacy-susfs`, commit `ba4422f0556e10f40dda1887631d87a18ede4ec5` (manager version code 33024)
- **SuSFS v2.0.0** — non-GKI backport, `sys_reboot` transport. Reference: JackA1ltman/NonGKI_Kernel_Build_2nd
  @ `230947c728e537049dcef1b12572d85e8699faa5`; sus_path ABI aligned to sidex15/susfs4ksu.

- **AnyKernel3** (flashable packaging) — https://github.com/osm0sis/AnyKernel3
  @ `1c9a500dd4aa8081952523126e97eb155aed941b`, vendored under `anykernel/`. `mkzip.sh` generates
  the per-model `anykernel.sh` (do.devicecheck codenames only; no ro.product.model gate — the model
  is unreliable in recovery).

## Toolchain
AOSP Clang 10.0.1 (r370808) + GCC 4.9 / binutils 2.27. **Do NOT use Clang 14+** (bootloops Exynos 990).

## Local modifications vs. Samsung source
- KernelSU-Next manual hooks (`CONFIG_KSU_MANUAL_HOOK`); SuSFS v2.0.0 (fs/susfs.c, include/linux/susfs*.h).
- sus_path ABI = standard pathname-first layout (official SuSFS module + WebUI compatible).
- fs/susfs.c memory-safety hardening (NULL-alloc returns, user-path NUL-termination, kzalloc nodes).
- Samsung security disabled for kernel root: CONFIG_UH (RKP), SECURITY_DEFEX, FIVE, RKP_CFP, KDP*, PROCA.

## Testing status
Only **SM-G985F** is boot-tested (firmware **G985FXXSNHYB1**, Android 13). The other four — **G980F**
(x1s), **G988B** (z3s), **G986B** (y2s / 5G) and **G981B** (x1s / 5G) — are built with their own defconfig
+ device tree on the G985F driver kernel (their driver-tree differences are not imported; see above) and
are **not boot-tested**. All non-G985F builds are experimental.
