# frida_anon_hide

Userspace companion for the SuSFS **sus_anon_range** kernel filter (this branch).

The patched kernel hides **only** the anonymous VMAs whose exact `[start,end)` a
root process registers, and **only** inside the umount-gated target process. This
tool registers frida-gum's injected anonymous **rwx** code page so it disappears
from `/proc/<pid>/maps` and `/proc/<pid>/smaps` — which Cookie Run: Kingdom's
anti-cheat reads via a **direct syscall**, bypassing frida's own libc-level maps
cloak.

Unlike a blanket rename, this never touches the app's own regions: the kernel
matches the exact `[uid,start,end)` you register, nothing else.

## Kernel ABI

The SuSFS dispatch on this fork is a kprobe on `__arm64_sys_reboot`:

```
reboot(magic1=0xDEADBEEF, magic2=0xFAFAFAFA, cmd, &info)     [root only]
    cmd 0x60021 = add, 0x60022 = del, 0x60023 = clear
    info = struct st_susfs_sus_anon_range { u32 uid; u64 start; u64 end; int err; }
```

`magic1` (`0xDEADBEEF`) is not `LINUX_REBOOT_MAGIC1`, so the real `reboot(2)` that
runs after the kprobe returns `-EINVAL` harmlessly — the device never reboots.

## Build

```sh
NDK=~/android-ndk-r29 ./build.sh        # -> static aarch64 ./frida_anon_hide
adb push frida_anon_hide /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/frida_anon_hide
```

## Usage

```
frida_anon_hide add      <uid> <start_hex> <end_hex>
frida_anon_hide del      <uid> <start_hex>
frida_anon_hide clear    <uid>
frida_anon_hide scan     <pid>                    # print rwx-anon ranges
frida_anon_hide autohide <uid> <pid> [baseline]   # register rwx-anon ranges
```

### Surgical workflow (recommended)

```sh
PID=$(pidof com.devsisters.crg)
UID=$(stat -c %u /data/data/com.devsisters.crg)   # or the app's app_id uid

# 1) baseline BEFORE frida attaches
su -c "/data/local/tmp/frida_anon_hide scan $PID" > /data/local/tmp/base

# 2) attach frida (frida -U -f ... / frida-server)

# 3) register only ranges that appeared after attach (i.e. frida's)
su -c "/data/local/tmp/frida_anon_hide autohide $UID $PID /data/local/tmp/base"
```

Re-run step 3 after every attach: ASLR moves frida's region, so the registered
range must be refreshed (the kernel keeps one entry per `uid`+`start`; `clear`
drops them all when you detach).

Without a baseline, `autohide` registers every **unnamed** rwx region. On a
stealth frida build that is precisely frida's code page — the app's own JIT is a
**named** rwx VMA (`[anon:dalvik-...]`), so it is never matched.

## Verify

The filter gates on the **reader**: it only hides when the *gated app reads its own*
maps. So you must verify from **inside** the target process — a root-side `grep` is
deliberately ungated and is the **control**, not the test.

**Test (must run inside the gated app).** Read `/proc/self/maps` via a direct
syscall (bypassing libc/frida's own cloak — the exact vector CRK's AC uses) and
confirm the registered range is gone. From frida:

```js
// arm64: openat=56 read=63 close=57 ; call raw syscall, not libc open/read
var sc = new NativeFunction(Process.findModuleByName('libc.so').getExportByName('syscall'),
    'pointer', ['pointer','pointer','pointer','pointer','pointer','pointer','pointer']);
function maps(){ var p=Memory.allocUtf8String('/proc/self/maps');
  var fd=sc(ptr(56),ptr(-100),p,ptr(0),ptr(0),ptr(0),ptr(0)).toInt32(); var b=Memory.alloc(1<<20),o='';
  for(;;){var n=sc(ptr(63),ptr(fd),b,ptr(1<<20),ptr(0),ptr(0),ptr(0)).toInt32(); if(n<=0)break; o+=b.readUtf8String(n);}
  sc(ptr(57),ptr(fd),ptr(0),ptr(0),ptr(0),ptr(0),ptr(0)); return o; }
console.log(maps().indexOf('<start>-<end>') !== -1 ? 'VISIBLE' : 'HIDDEN');
```

Expected: `VISIBLE` before `add`, `HIDDEN` after. (This is exactly what
`hide_test.py` automates — proven on SM-G985F.)

**Control (root, ungated — the range should STILL show):**
```sh
su -c "grep rwx /proc/$PID/maps"   # root reader is not gated -> still visible; confirms the gate is scoped, not global
```
