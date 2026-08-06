# Disaster Recovery — rebuild the modded kernel from scratch

Everything needed to rebuild the **KernelSU-Next + SuSFS Exynos 990 kernel** (with the
`sus_anon_range` / `sus_net` / `read_proc_mem` (pmread) / **o1c maps-hide + o1d fd-hide**
features) for the **Galaxy S20+ (SM-G985F)** and flash it — after a total PC loss.

Everything in THIS repo is enough to build **except two gitignored things** you must
re-obtain: the **toolchain** and **~32 firmware blobs**. Both are covered below.

- Model: **SM-G985F** (Galaxy S20+ 4G, Exynos 990 / universal9830), codename **y2s**
- Kernel: Linux **4.19.87**, One UI 5 / Android 13
- Feature tip: **`1457aa6b1`** (o1c maps-hide + o1d fd-hide) · base **`28b2fc476`**
- KernelSU-Next v3.1.0 + SuSFS v2.0.0 · KSU_VERSION pinned 33241
- >>> **DO NOT use Clang 14+ — it miscompiles Exynos 990 early asm → bootloop.** <<<

---

## 0. Host
Linux x86-64 (WSL2 Ubuntu is fine), ~40 GB free.
```sh
sudo apt update && sudo apt install -y git build-essential bc bison flex \
  libssl-dev libncurses-dev zip unzip python3 cpio kmod
```

## 1. Get the source
```sh
git clone -b susfs-anon-range \
  https://github.com/enchantedglycerin/exynos990-susfs-anon-range.git kernel
cd kernel     # full history, tip = 1457aa6b1
```
Fallback if that private repo is gone: the same tree is reconstructable from the PUBLIC
base `exynos990-KernelSU-Next-SuSFS` @ `28b2fc476` + the bundle/patches on this repo's
`main` branch (see that branch's README for the two-line `git fetch <bundle>` recipe).

## 2. Toolchain  (gitignored — re-obtain)
AOSP **Clang r370808 (10.0.1)** + **GCC 4.9** (`aarch64-linux-android-4.9`).
`build.sh` looks for them at `../tc/clang10` and `../tc/gcc49` (siblings of the repo root),
or wherever you point `CLANG_DIR` / `GCC_DIR`.

- **Preferred — this repo's `toolchain` GitHub Release** (if the tarballs were uploaded):
  ```sh
  mkdir -p ../tc/clang10 ../tc/gcc49
  tar -xzf clang10.tar.gz -C ../tc/clang10
  tar -xzf gcc49.tar.gz   -C ../tc/gcc49
  ```
- **From Google (canonical):** the aarch64 GCC 4.9 prebuilt is
  `android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9`;
  Clang **r370808** is the `clang-r370808/` directory in
  `android.googlesource.com/platform/prebuilts/clang/host/linux-x86`. Any Clang 10.0.x
  r37xxxx works; **never 14+**.

## 3. Firmware blobs  (gitignored by the generic `*.bin` rule — restore)
`CONFIG_EXTRA_FIRMWARE` bakes ~32 Samsung blobs (`npu/`, `mfc/`, `tsp_*/`, `epen/`,
`key_stm/`, `range_sensor/`, …) into the Image; a clean clone is missing them and the
build will error on the first missing file.

- **Preferred — this repo's `firmware/` backup** (if committed): already present, nothing to do.
- **From Samsung:** download the **SM-G985F** Open Source drop (e.g. `G985FXXSNHYB1`) from
  <https://opensource.samsung.com> (search `G985F`), unzip the kernel tarball, then:
  ```sh
  cp -a <stock-kernel>/firmware/. firmware/
  ```

## 4. Build
```sh
./build.sh -m g985f          # -> out_g985f/arch/arm64/boot/Image
```
`build.sh` merges `arch/arm64/configs/exynos9830-y2slte_defconfig` + `arch/arm64/configs/ksu.config`,
exports the required Samsung Kconfig env (`PLATFORM_VERSION=13 ANDROID_MAJOR_VERSION=t
SEC_BUILD_CONF_VENDOR_BUILD_OS=13`), and builds `Image` with `-j nproc`.

## 5. Package a flashable zip
```sh
./mkzip.sh -m g985f          # -> AnyKernel3_KSUNext_SUSFS_G985F_S20plus.zip
```
Uses the committed `anykernel/` framework; codename gate = `y2s`.

## 6. Flash
TWRP / recovery → install the zip (keeps your device's dtb/ramdisk, patches boot).
Or `fastboot` the `Image` inside a repacked stock `boot.img`.

---

## What is / isn't in this repo
| Component | In repo? | Recover from |
|---|---|---|
| Kernel source + feature commits | ✅ committed | `git clone` (branch `susfs-anon-range`) |
| `build.sh`, `mkzip.sh`, `anykernel/`, defconfigs, `ksu.config`, `ologk.h` | ✅ committed | `git clone` |
| Toolchain (Clang r370808 + GCC 4.9) | ❌ gitignored | §2 — Release or AOSP prebuilts |
| Firmware blobs (~32) | ❌ gitignored (`*.bin`) | §3 — Release backup or Samsung OSRC |
