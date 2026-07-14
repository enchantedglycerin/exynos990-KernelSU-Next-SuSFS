# AnyKernel3 (vendored)

This directory is [osm0sis/AnyKernel3](https://github.com/osm0sis/AnyKernel3)
@ `1c9a500dd4aa8081952523126e97eb155aed941b`, vendored here so the flashable zip is buildable + packageable from this
repository. It keeps its own license (see `LICENSE` in this directory).

The `anykernel.sh` ramdisk-mod script is intentionally **not** stored here: it is
generated per device by `../mkzip.sh`, which sets the `do.devicecheck` device-name
codenames for the selected model (y2s / x1s / z3s). Everything else here
(`tools/`, `META-INF/`, `modules/`, `patch/`, `ramdisk/`) is the unmodified
AnyKernel3 framework.

Build a flashable from source:

    ./build.sh -m g985f    # produces out_g985f/arch/arm64/boot/Image
    ./mkzip.sh  -m g985f   # produces AnyKernel3_KSUNext_SUSFS_G985F_S20plus.zip
