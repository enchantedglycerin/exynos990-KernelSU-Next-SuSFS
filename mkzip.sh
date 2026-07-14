#!/bin/bash
# mkzip.sh -- build a flashable AnyKernel3 zip from an already-built kernel Image.
#
# Usage:   ./mkzip.sh -m <g985f|g980f|g988b|g986b|g981b>   (model number)
#   Requires ./build.sh -m <model> to have produced out_<model>/arch/arm64/boot/Image.
#   Produces AnyKernel3_KSUNext_SUSFS_<model>[_EXPERIMENTAL].zip in the repo root.
#
# Device gating: this uses only AnyKernel's do.devicecheck against ro.product.device
# (the codename). There is deliberately NO ro.product.model gate -- recovery-time
# getprop for the model is unreliable and falsely rejected a genuine SM-G985F (which
# reports ro.product.device=y2s and model=SM-G985F when booted, but does NOT return
# the model in TWRP). The codename is consistent between boot and recovery. Note the
# 4G/5G siblings share a codename (G985F/G986B=y2s, G980F/G981B=x1s), so a codename
# check cannot tell them apart -- check your exact model before flashing. Non-G985F
# targets are the G985F driver kernel with that model's config. See README/PROVENANCE.
set -e
MODEL=g985f
while getopts "m:" o; do case $o in m) MODEL=$OPTARG ;; esac; done
ROOT="$(cd "$(dirname "$0")" && pwd)"

case "$MODEL" in
  g985f) CODENAMES="y2s y2slte";  BDEV="Galaxy S20+    SM-G985F";       KSTR="Galaxy S20+ (SM-G985F / Exynos 990)";              EXP="";    ZIP="AnyKernel3_KSUNext_SUSFS_G985F_S20plus.zip" ;;
  g980f) CODENAMES="x1s x1slte";  BDEV="Galaxy S20    SM-G980F";        KSTR="Galaxy S20 (SM-G980F / Exynos 990) [EXPERIMENTAL]";       EXP="yes"; ZIP="AnyKernel3_KSUNext_SUSFS_G980F_S20_EXPERIMENTAL.zip" ;;
  g988b) CODENAMES="z3s";         BDEV="Galaxy S20 Ultra    SM-G988B";  KSTR="Galaxy S20 Ultra (SM-G988B / Exynos 990) [EXPERIMENTAL]"; EXP="yes"; ZIP="AnyKernel3_KSUNext_SUSFS_G988B_S20Ultra_EXPERIMENTAL.zip" ;;
  g986b) CODENAMES="y2s";         BDEV="Galaxy S20+ 5G    SM-G986B";    KSTR="Galaxy S20+ 5G (SM-G986B / Exynos 990) [EXPERIMENTAL]"; EXP="yes"; ZIP="AnyKernel3_KSUNext_SUSFS_G986B_S20plus5G_EXPERIMENTAL.zip" ;;
  g981b) CODENAMES="x1s";         BDEV="Galaxy S20 5G    SM-G981B";     KSTR="Galaxy S20 5G (SM-G981B / Exynos 990) [EXPERIMENTAL]";  EXP="yes"; ZIP="AnyKernel3_KSUNext_SUSFS_G981B_S20_5G_EXPERIMENTAL.zip" ;;
  *)   echo "Unknown model '$MODEL' (use g985f|g980f|g988b|g986b|g981b)"; exit 1 ;;
esac

IMG="$ROOT/out_$MODEL/arch/arm64/boot/Image"
[ -f "$IMG" ] || { echo "Missing $IMG -- run ./build.sh -m $MODEL first."; exit 1; }
[ -f "$ROOT/anykernel/tools/ak3-core.sh" ] || { echo "Missing anykernel/ framework."; exit 1; }

W="$ROOT/.mkzip_$MODEL"; rm -rf "$W"; mkdir -p "$W"
cp -a "$ROOT/anykernel/." "$W/"
cp "$IMG" "$W/Image"

{
  echo '### AnyKernel3 Ramdisk Mod Script'
  echo '## osm0sis @ xda-developers'
  echo ''
  echo 'properties() { '"'"''
  echo "kernel.string=KernelSU-Next v3.1.0 + SuSFS v2.0.0 | $KSTR"
  echo 'do.devicecheck=1'; echo 'do.modules=0'; echo 'do.systemless=1'
  echo 'do.cleanup=1'; echo 'do.cleanuponabort=0'
  i=1; for cn in $CODENAMES; do echo "device.name${i}=${cn}"; i=$((i+1)); done
  while [ "$i" -le 5 ]; do echo "device.name${i}="; i=$((i+1)); done
  echo 'supported.versions=13'; echo 'supported.patchlevels='; echo 'supported.vendorpatchlevels='
  echo "'"'; } # end properties'
  echo ''
  echo 'boot_attributes() {'
  echo 'set_perm_recursive 0 0 755 644 $RAMDISK/*;'
  echo 'set_perm_recursive 0 0 750 750 $RAMDISK/init* $RAMDISK/sbin;'
  echo '} # end attributes'
  echo ''
  echo 'BLOCK=/dev/block/by-name/boot;'; echo 'IS_SLOT_DEVICE=0;'
  echo 'RAMDISK_COMPRESSION=auto;'; echo 'PATCH_VBMETA_FLAG=auto;'
  echo ''
  echo '. tools/ak3-core.sh;'
  echo ''
  echo 'AKMODEL="$(getprop ro.product.model 2>/dev/null)";'
  echo ''
  echo 'ui_print " ";'
  echo 'ui_print "==================================================";'
  echo 'ui_print "   KernelSU-Next + SuSFS  (Exynos 990)";'
  echo "ui_print \"   $BDEV\";"
  echo 'ui_print "   KernelSU-Next v3.1.0  +  SuSFS v2.0.0";'
  echo 'ui_print "   Detected model: ${AKMODEL:-(unreadable in recovery)}";'
  [ -n "$EXP" ] && echo 'ui_print "   *** EXPERIMENTAL - UNTESTED on this model ***";'
  echo 'ui_print "==================================================";'
  echo 'ui_print " ";'
  echo ''
  echo 'dump_boot;'; echo 'write_boot;'
} > "$W/anykernel.sh"

sh -n "$W/anykernel.sh" || { echo "generated anykernel.sh has a syntax error"; exit 1; }
rm -f "$ROOT/$ZIP"
( cd "$W" && zip -qr9 "$ROOT/$ZIP" . -x '.git*' )
rm -rf "$W"
echo ">> $ZIP  ($(stat -c%s "$ROOT/$ZIP") bytes; Image $(stat -c%s "$IMG"))"
echo ">> device.name = $CODENAMES   (codename check only; verify your model before flashing)"
