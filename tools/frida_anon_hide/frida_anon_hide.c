// frida_anon_hide.c  (nh -- the SuSFS hardening registrar for stealth frida)
// -----------------------------------------------------------------------------
// Userspace companion for the SuSFS kernel filters on the exynos990
// KernelSU-Next fork. Registers everything that would otherwise leak the
// injected frida-server ("gpud") to CRK's anti-cheat, which reads /proc via
// direct syscalls (bypassing frida's own libc-level cloaks):
//
//   * sus_anon_range  -- frida-gum's injected rwx anonymous code region
//   * sus_net_port/unix -- gpud's LISTEN port + abstract control socket
//   * sus_path / _loop  -- gpud/nh/gp + the KSU module dir + /data/adb/.ht stage
//   * sus_map           -- a file-backed mapping to hide by pathname
//   * avc_log_spoofing  -- suppress the SELinux denials frida trips (dmesg tell)
//   * hide_sus_mnts     -- hide the module's own mounts from non-su procs
//   * sus_kstat         -- spoof stat() of a path to mirror a stock reference
//
// Kernel ABI (reboot(2) kprobe dispatch, root only):
//     reboot(magic1=0xDEADBEEF, magic2=0xFAFAFAFA, cmd, arg)
//   The KSU reboot hook calls ksu_handle_sys_reboot(m1,m2,cmd,&arg); each susfs
//   handler takes `void __user **user_info` and reads *user_info == our `arg`.
//   So userspace passes the struct pointer DIRECTLY as the 4th reboot argument
//   (identical convention for every command below). magic1 (0xDEADBEEF) is not
//   LINUX_REBOOT_MAGIC1, so the real reboot after the hook returns -EINVAL
//   harmlessly -- the device never reboots.
//
// Command numbers + struct layouts are byte-verified against the DEVICE kernel:
//   ksu-mod/exynos990/include/linux/{susfs_def.h,susfs.h}
//   ksu-mod/exynos990/KernelSU-Next/kernel/supercalls.c (dispatch)
//   ksu-mod/exynos990/fs/susfs.c (handlers)
//
// Build (NDK, static so it runs standalone under su):
//   $NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android29-clang \
//       -O2 -static -Wall -o nh frida_anon_hide.c
//
// Usage:
//   nh add          <uid> <start_hex> <end_hex>
//   nh del          <uid> <start_hex>
//   nh clear        <uid>
//   nh scan         <pid>
//   nh autohide     <uid> <pid> [baseline]           # hide frida rwx maps
//   nh autohide-net <uid> <frida_server_pid>         # hide LISTEN port + unix sock
//   nh sus-path     <path> [path...]                 # hide path(s) from stat/readdir
//   nh sus-path-loop <dir>                           # hide a directory subtree
//   nh sus-map      <path> [path...]                 # hide file-backed mappings
//   nh avc-spoof    <0|1>                            # SELinux denial log spoofing
//   nh hide-mnts    <0|1>                            # hide sus mounts (non-su procs)
//   nh sus-kstat    <target_path> <reference_path>   # spoof stat() to match ref
// -----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>

#define KSU_MAGIC1   0xDEADBEEFu
#define SUSFS_MAGIC  0xFAFAFAFAu
#define CMD_ADD      0x60021u   /* sus_anon_range add   */
#define CMD_DEL      0x60022u   /* sus_anon_range del   */
#define CMD_CLEAR    0x60023u   /* sus_anon_range clear */
#define CMD_ADD_NET_PORT   0x60024u
#define CMD_DEL_NET_PORT   0x60025u
#define CMD_CLEAR_NET_PORT 0x60026u
#define CMD_ADD_NET_UNIX   0x60027u
#define CMD_DEL_NET_UNIX   0x60028u
#define CMD_CLEAR_NET_UNIX 0x60029u
/* --- hardening commands (byte-verified vs exynos990 susfs_def.h) --- */
#define CMD_ADD_SUS_PATH        0x55550u
#define CMD_ADD_SUS_PATH_LOOP   0x55553u
#define CMD_HIDE_SUS_MNTS       0x55561u  /* HIDE_SUS_MNTS_FOR_NON_SU_PROCS */
#define CMD_ADD_SUS_KSTAT       0x55570u
#define CMD_ENABLE_AVC_SPOOF    0x60010u
#define CMD_ADD_SUS_MAP         0x60020u

#define SUS_MAX_PATH 256   /* == kernel SUSFS_MAX_LEN_PATHNAME */

// Must be byte-compatible with kernel struct st_susfs_sus_anon_range (LP64):
//   u32 target_uid; <4 pad>; u64 start; u64 end; int err; <4 pad>  => 32 bytes
struct anon_range {
	unsigned int  target_uid;
	unsigned long start;
	unsigned long end;
	int           err;
};

// kernel st_susfs_sus_net_port: u32 uid; u32 port; int err;  => 12 bytes
struct net_port {
	unsigned int target_uid;
	unsigned int port;
	int          err;
};

// kernel st_susfs_sus_net_unix: u32 uid; <4 pad>; u64 inode; int err;  => 24 bytes
struct net_unix {
	unsigned int  target_uid;
	unsigned long inode;
	int           err;
};

// kernel st_susfs_sus_path AND st_susfs_sus_map share this layout:
//   char target_pathname[256]; int err;   => 260 bytes
struct path_info {
	char target_pathname[SUS_MAX_PATH];
	int  err;
};

// kernel st_susfs_avc_log_spoofing / st_susfs_hide_sus_mnts...: bool; int err; => 8 bytes
struct toggle_info {
	unsigned char enabled;     /* _Bool: kernel reads byte 0 only */
	unsigned char _pad[3];
	int           err;
};

// kernel st_susfs_sus_kstat -- mirror field-for-field (both LP64 aarch64, so the
// compiler reproduces the kernel's natural alignment exactly).
struct kstat_info {
	int                is_statically;
	unsigned long      target_ino;
	char               target_pathname[SUS_MAX_PATH];
	unsigned long      spoofed_ino;
	unsigned long      spoofed_dev;
	unsigned int       spoofed_nlink;
	long long          spoofed_size;
	long               spoofed_atime_tv_sec;
	long               spoofed_mtime_tv_sec;
	long               spoofed_ctime_tv_sec;
	long               spoofed_atime_tv_nsec;
	long               spoofed_mtime_tv_nsec;
	long               spoofed_ctime_tv_nsec;
	unsigned long      spoofed_blksize;
	unsigned long long spoofed_blocks;
	int                err;
};

#define MAX_RANGES 256
// The kernel only ever writes 0 or a negative errno into ->err. Pre-seed a value
// it never writes, so we can tell "dispatched" from "never reached the handler".
#define ERR_SENTINEL 0x7fffffff

static int susfs_call(unsigned int cmd, struct anon_range *info)
{
	info->err = ERR_SENTINEL;
	// reboot(magic1, magic2, cmd, arg): kprobe reads x0..x3 as those args.
	syscall(SYS_reboot, (long)KSU_MAGIC1, (long)SUSFS_MAGIC,
		(long)cmd, (void *)info);
	// The kernel overwrites ->err via copy_to_user() ONLY if the dispatch ran.
	// Still-sentinel => not root, or a kernel without sus_anon_range support.
	return info->err;
}

// Generic dispatch for any info struct; caller passes the address of its err field.
static int susfs_call_raw(unsigned int cmd, void *info, int *errp)
{
	*errp = ERR_SENTINEL;
	syscall(SYS_reboot, (long)KSU_MAGIC1, (long)SUSFS_MAGIC, (long)cmd, info);
	return *errp;
}

// ---- sus_net: hide a running server's LISTEN port + abstract unix socket ----
static int inode_in(const unsigned long *inodes, int n, unsigned long ino)
{
	for (int i = 0; i < n; i++)
		if (inodes[i] == ino)
			return 1;
	return 0;
}

// socket inodes owned by pid (from /proc/<pid>/fd -> "socket:[<inode>]")
static int collect_pid_sock_inodes(int pid, unsigned long *inodes, int max)
{
	char dir[64], link[128], target[128];
	struct dirent *e;
	DIR *d;
	int n = 0;

	snprintf(dir, sizeof(dir), "/proc/%d/fd", pid);
	d = opendir(dir);
	if (!d) {
		fprintf(stderr, "cannot open %s: %s\n", dir, strerror(errno));
		return -1;
	}
	while ((e = readdir(d)) && n < max) {
		ssize_t len;
		unsigned long ino;
		if (e->d_name[0] == '.')
			continue;
		snprintf(link, sizeof(link), "%s/%s", dir, e->d_name);
		len = readlink(link, target, sizeof(target) - 1);
		if (len <= 0)
			continue;
		target[len] = '\0';
		if (sscanf(target, "socket:[%lu]", &ino) == 1)
			inodes[n++] = ino;
	}
	closedir(d);
	return n;
}

static int split_fields(char *line, char **fields, int max)
{
	int n = 0;
	char *t = strtok(line, " \t\n");
	while (t && n < max) {
		fields[n++] = t;
		t = strtok(NULL, " \t\n");
	}
	return n;
}

// register LISTEN (st==0A) local ports from /proc/net/{tcp,tcp6} owned by socks[]
static int register_listen_ports(const char *path, unsigned int uid,
				 const unsigned long *socks, int ns, int *nfail,
				 unsigned int *seen, int *nseen, int seencap)
{
	FILE *f = fopen(path, "r");
	char line[512];
	char *fields[16];
	int done = 0;

	if (!f)
		return 0; // tcp6 may be absent
	if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; } // header
	while (fgets(line, sizeof(line), f)) {
		unsigned int port = 0, st;
		unsigned long ino;
		int nf = split_fields(line, fields, 16);
		if (nf < 10)
			continue;
		st = (unsigned int)strtoul(fields[3], NULL, 16);
		ino = strtoul(fields[9], NULL, 10);
		if (st != 0x0A || !inode_in(socks, ns, ino)) // 0x0A = TCP_LISTEN
			continue;
		sscanf(fields[1], "%*[0-9A-Fa-f]:%x", &port);
		if (port) {
			struct net_port np = { .target_uid = uid, .port = port };
			int i, dup = 0;
			/* the kernel key is (uid, port); one port can back several LISTEN
			 * sockets (IPv4/IPv6, SO_REUSEPORT) -> register each port only once */
			for (i = 0; i < *nseen; i++)
				if (seen[i] == port) { dup = 1; break; }
			if (dup)
				continue;
			if (*nseen < seencap)
				seen[(*nseen)++] = port;
			susfs_call_raw(CMD_ADD_NET_PORT, &np, &np.err);
			printf("net-port uid=%u port=%u (inode %lu) -> %s\n", uid, port, ino,
			       np.err == ERR_SENTINEL ? "FAILED(no dispatch)" :
			       (np.err && np.err != -EEXIST) ? strerror(-np.err) : "ok");
			/* already-registered (0, or -EEXIST on a stricter kernel) == success */
			if (np.err && np.err != -EEXIST)
				(*nfail)++;
			else
				done++;
		}
	}
	fclose(f);
	return done;
}

// register abstract/unix socket inodes from /proc/net/unix owned by socks[]
static int register_unix_inodes(const char *path, unsigned int uid,
				const unsigned long *socks, int ns, int *nfail)
{
	FILE *f = fopen(path, "r");
	char line[512];
	char *fields[16];
	int done = 0;

	if (!f)
		return 0;
	if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; } // header
	while (fgets(line, sizeof(line), f)) {
		unsigned long ino;
		int nf = split_fields(line, fields, 16);
		if (nf < 7)
			continue;
		ino = strtoul(fields[6], NULL, 10);
		if (!ino || !inode_in(socks, ns, ino))
			continue;
		struct net_unix nu = { .target_uid = uid, .inode = ino };
		susfs_call_raw(CMD_ADD_NET_UNIX, &nu, &nu.err);
		printf("net-unix uid=%u inode=%lu (%s) -> %s\n", uid, ino,
		       nf >= 8 ? fields[7] : "",
		       nu.err == ERR_SENTINEL ? "FAILED(no dispatch)" :
		       (nu.err && nu.err != -EEXIST) ? strerror(-nu.err) : "ok");
		if (nu.err && nu.err != -EEXIST)
			(*nfail)++;
		else
			done++;
	}
	fclose(f);
	return done;
}

// Parse one /proc/<pid>/maps line. Returns 1 and fills s,e for an rwx mapping
// with an EMPTY pathname (pure anonymous); 0 otherwise.
static int parse_rwx_anon(const char *line, unsigned long *s, unsigned long *e)
{
	unsigned long start, end;
	char perms[8] = {0};
	const char *p = line;
	int fields = 0;

	if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3)
		return 0;
	if (perms[0] != 'r' || perms[1] != 'w' || perms[2] != 'x')
		return 0;

	// Walk past 5 whitespace-separated fields: addr perms offset dev inode.
	while (*p && fields < 5) {
		while (*p == ' ' || *p == '\t') p++;
		if (!*p) break;
		while (*p && *p != ' ' && *p != '\t') p++;
		fields++;
	}
	while (*p == ' ' || *p == '\t') p++;
	// Empty pathname (only newline/EOL left) => anonymous region.
	if (*p == '\0' || *p == '\n' || *p == '\r') {
		*s = start;
		*e = end;
		return 1;
	}
	return 0;
}

static int read_rwx_anon(int pid, unsigned long *starts, unsigned long *ends, int max)
{
	char path[64];
	char line[1024];
	FILE *f;
	int n = 0;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f) && n < max) {
		unsigned long s, e;
		if (parse_rwx_anon(line, &s, &e)) {
			starts[n] = s;
			ends[n] = e;
			n++;
		}
	}
	fclose(f);
	return n;
}

static int in_baseline(unsigned long *bs, unsigned long *be, int bn,
		       unsigned long s, unsigned long e)
{
	for (int i = 0; i < bn; i++)
		if (bs[i] == s && be[i] == e)
			return 1;
	return 0;
}

static int load_baseline(const char *path, unsigned long *bs, unsigned long *be, int max)
{
	FILE *f = fopen(path, "r");
	int n = 0;
	if (!f) {
		fprintf(stderr, "cannot open baseline %s: %s\n", path, strerror(errno));
		return -1;
	}
	while (n < max && fscanf(f, "%lx %lx", &bs[n], &be[n]) == 2)
		n++;
	fclose(f);
	return n;
}

static int do_add(unsigned int uid, unsigned long s, unsigned long e)
{
	struct anon_range info = { .target_uid = uid, .start = s, .end = e };
	susfs_call(CMD_ADD, &info);
	if (info.err == ERR_SENTINEL) {
		fprintf(stderr, "add   uid=%u [0x%lx,0x%lx) -> FAILED: kernel did not "
			"dispatch (need root + a sus_anon_range kernel)\n", uid, s, e);
		return 1;
	}
	printf("add   uid=%u [0x%lx,0x%lx) -> %s (err=%d)\n",
	       uid, s, e, info.err ? strerror(-info.err) : "ok", info.err);
	return info.err ? 1 : 0;
}

// ---- path/map/toggle/kstat helpers (all share the reboot dispatch) ----

// Register one path with a {char[256]; int err} command (sus_path / sus_map).
static int do_path_cmd(unsigned int cmd, const char *label, const char *path)
{
	struct path_info info;
	memset(&info, 0, sizeof(info));
	strncpy(info.target_pathname, path, SUS_MAX_PATH - 1);
	susfs_call_raw(cmd, &info, &info.err);
	if (info.err == ERR_SENTINEL) {
		fprintf(stderr, "%-13s '%s' -> FAILED: kernel did not dispatch "
			"(need root + this susfs feature)\n", label, path);
		return 1;
	}
	/* -EEXIST == already hidden == success */
	printf("%-13s '%s' -> %s (err=%d)\n", label, path,
	       (info.err && info.err != -EEXIST) ? strerror(-info.err) : "ok", info.err);
	return (info.err && info.err != -EEXIST) ? 1 : 0;
}

// Toggle command (avc-spoof / hide-mnts): {bool enabled; int err}.
static int do_toggle_cmd(unsigned int cmd, const char *label, int enabled)
{
	struct toggle_info info;
	memset(&info, 0, sizeof(info));
	info.enabled = enabled ? 1 : 0;
	susfs_call_raw(cmd, &info, &info.err);
	if (info.err == ERR_SENTINEL) {
		fprintf(stderr, "%-13s %d -> FAILED: kernel did not dispatch "
			"(need root + this susfs feature)\n", label, enabled);
		return 1;
	}
	printf("%-13s %d -> %s (err=%d)\n", label, enabled,
	       info.err ? strerror(-info.err) : "ok", info.err);
	return info.err ? 1 : 0;
}

// Spoof target_path's stat() to mirror reference_path (make a live frida file
// read as a stock file). is_statically=0 => kernel resolves target_ino by path.
static int do_kstat_cmd(const char *target, const char *ref)
{
	struct kstat_info info;
	struct stat st;

	if (stat(ref, &st) != 0) {
		fprintf(stderr, "sus-kstat: cannot stat reference '%s': %s\n",
			ref, strerror(errno));
		return 1;
	}
	memset(&info, 0, sizeof(info));
	info.is_statically      = 0;
	strncpy(info.target_pathname, target, SUS_MAX_PATH - 1);
	info.spoofed_ino        = st.st_ino;
	info.spoofed_dev        = st.st_dev;
	info.spoofed_nlink      = st.st_nlink;
	info.spoofed_size       = st.st_size;
	info.spoofed_atime_tv_sec  = st.st_atim.tv_sec;
	info.spoofed_mtime_tv_sec  = st.st_mtim.tv_sec;
	info.spoofed_ctime_tv_sec  = st.st_ctim.tv_sec;
	info.spoofed_atime_tv_nsec = st.st_atim.tv_nsec;
	info.spoofed_mtime_tv_nsec = st.st_mtim.tv_nsec;
	info.spoofed_ctime_tv_nsec = st.st_ctim.tv_nsec;
	info.spoofed_blksize    = st.st_blksize;
	info.spoofed_blocks     = st.st_blocks;
	susfs_call_raw(CMD_ADD_SUS_KSTAT, &info, &info.err);
	if (info.err == ERR_SENTINEL) {
		fprintf(stderr, "sus-kstat '%s' <- '%s' -> FAILED: kernel did not "
			"dispatch (need root + a sus_kstat kernel)\n", target, ref);
		return 1;
	}
	printf("sus-kstat     '%s' <- '%s' -> %s (err=%d)\n", target, ref,
	       info.err ? strerror(-info.err) : "ok", info.err);
	return info.err ? 1 : 0;
}

static void usage(const char *a0)
{
	fprintf(stderr,
		"nh -- SuSFS hardening registrar for stealth frida (gpud)\n"
		"usage:\n"
		"  %s add           <uid> <start_hex> <end_hex>\n"
		"  %s del           <uid> <start_hex>\n"
		"  %s clear         <uid>\n"
		"  %s scan          <pid>\n"
		"  %s autohide      <uid> <pid> [baseline_file]  # hide frida rwx maps\n"
		"  %s autohide-net  <uid> <frida_server_pid>     # hide LISTEN port + unix sock\n"
		"  %s sus-path      <path> [path...]             # hide path(s) from stat/readdir\n"
		"  %s sus-path-loop <dir>                        # hide a directory subtree\n"
		"  %s sus-map       <path> [path...]             # hide file-backed mappings\n"
		"  %s avc-spoof     <0|1>                        # SELinux denial log spoofing\n"
		"  %s hide-mnts     <0|1>                        # hide sus mounts (non-su procs)\n"
		"  %s sus-kstat     <target_path> <reference>    # spoof stat() to match ref\n",
		a0, a0, a0, a0, a0, a0, a0, a0, a0, a0, a0, a0);
}

int main(int argc, char **argv)
{
	if (argc < 2) { usage(argv[0]); return 2; }

	if (!strcmp(argv[1], "add") && argc == 5) {
		unsigned int uid = (unsigned int)strtoul(argv[2], NULL, 0);
		unsigned long s = strtoul(argv[3], NULL, 16);
		unsigned long e = strtoul(argv[4], NULL, 16);
		return do_add(uid, s, e) ? 1 : 0;
	}

	if (!strcmp(argv[1], "del") && argc == 4) {
		struct anon_range info = { 0 };
		info.target_uid = (unsigned int)strtoul(argv[2], NULL, 0);
		info.start = strtoul(argv[3], NULL, 16);
		susfs_call(CMD_DEL, &info);
		if (info.err == ERR_SENTINEL) {
			fprintf(stderr, "del: FAILED -- kernel did not dispatch "
				"(need root + a sus_anon_range kernel)\n");
			return 1;
		}
		printf("del   uid=%u start=0x%lx -> %s (err=%d)\n",
		       info.target_uid, info.start,
		       info.err ? strerror(-info.err) : "ok", info.err);
		return info.err ? 1 : 0;
	}

	if (!strcmp(argv[1], "clear") && argc == 3) {
		struct anon_range info = { 0 };
		info.target_uid = (unsigned int)strtoul(argv[2], NULL, 0);
		susfs_call(CMD_CLEAR, &info);
		if (info.err == ERR_SENTINEL) {
			fprintf(stderr, "clear: FAILED -- kernel did not dispatch "
				"(need root + a sus_anon_range kernel)\n");
			return 1;
		}
		printf("clear uid=%u -> %s (err=%d)\n",
		       info.target_uid, info.err ? strerror(-info.err) : "ok", info.err);
		return info.err ? 1 : 0;
	}

	if (!strcmp(argv[1], "scan") && argc == 3) {
		unsigned long s[MAX_RANGES], e[MAX_RANGES];
		int pid = atoi(argv[2]);
		int n = read_rwx_anon(pid, s, e, MAX_RANGES);
		if (n < 0) return 1;
		for (int i = 0; i < n; i++)
			printf("%lx %lx\n", s[i], e[i]);
		fprintf(stderr, "%d rwx-anon range(s)\n", n);
		return 0;
	}

	if (!strcmp(argv[1], "autohide") && (argc == 4 || argc == 5)) {
		unsigned int uid = (unsigned int)strtoul(argv[2], NULL, 0);
		int pid = atoi(argv[3]);
		unsigned long s[MAX_RANGES], e[MAX_RANGES];
		unsigned long bs[MAX_RANGES], be[MAX_RANGES];
		int bn = 0;
		int n = read_rwx_anon(pid, s, e, MAX_RANGES);
		if (n < 0) return 1;
		if (argc == 5) {
			bn = load_baseline(argv[4], bs, be, MAX_RANGES);
			if (bn < 0) return 1;
		}
		// Transactional: drop any prior (stale) registrations for this uid so
		// repeated attaches don't accumulate entries across ASLR/restarts.
		struct anon_range clr = { .target_uid = uid };
		susfs_call(CMD_CLEAR, &clr);
		if (clr.err == ERR_SENTINEL) {
			fprintf(stderr, "autohide: FAILED -- kernel did not dispatch "
				"(need root + a sus_anon_range kernel)\n");
			return 1;
		}
		int done = 0, rc = 0;
		for (int i = 0; i < n; i++) {
			if (bn && in_baseline(bs, be, bn, s[i], e[i]))
				continue; // present before attach -> not frida
			if (do_add(uid, s[i], e[i]))
				rc = 1;
			done++;
		}
		fprintf(stderr, "registered %d/%d rwx-anon range(s)%s\n",
			done, n, bn ? " (new vs baseline)" : "");
		return rc;
	}

	if (!strcmp(argv[1], "autohide-net") && argc == 4) {
		unsigned int uid = (unsigned int)strtoul(argv[2], NULL, 0);
		int fspid = atoi(argv[3]);
		unsigned long socks[MAX_RANGES];
		int ns = collect_pid_sock_inodes(fspid, socks, MAX_RANGES);
		int ports, units;
		struct net_port pc = { .target_uid = uid };
		struct net_unix uc = { .target_uid = uid };
		char pt[64], pt6[64], pu[64];
		unsigned int seen[MAX_RANGES];
		int nseen = 0;
		int nfail = 0;
		if (ns < 0)
			return 1;
		// Best-effort clear of the uid's net sets first, then (re)register the
		// current sockets. Registration is what actually hides the live endpoint,
		// so we deliberately PROCEED even if a clear is imperfect -- the worst case
		// is a harmless leftover stale rule, whereas aborting here could leave the
		// current endpoint visible. Only a total no-dispatch (kernel without
		// sus_net) is fatal. The sus_net commands share one dispatch path, so the
		// port and unix clears are all-or-nothing together.
		susfs_call_raw(CMD_CLEAR_NET_PORT, &pc, &pc.err);
		susfs_call_raw(CMD_CLEAR_NET_UNIX, &uc, &uc.err);
		if (pc.err == ERR_SENTINEL && uc.err == ERR_SENTINEL) {
			// nothing dispatched at all -> no sus_net kernel; abort. If only one
			// class dispatched (partial support), fall through and register what
			// is supported rather than abandon an already-cleared endpoint.
			fprintf(stderr, "autohide-net: FAILED -- kernel did not dispatch "
				"(need root + a sus_net kernel)\n");
			return 1;
		}
		snprintf(pt, sizeof(pt), "/proc/%d/net/tcp", fspid);
		snprintf(pt6, sizeof(pt6), "/proc/%d/net/tcp6", fspid);
		snprintf(pu, sizeof(pu), "/proc/%d/net/unix", fspid);
		ports = register_listen_ports(pt, uid, socks, ns, &nfail, seen, &nseen, MAX_RANGES)
		      + register_listen_ports(pt6, uid, socks, ns, &nfail, seen, &nseen, MAX_RANGES);
		units = register_unix_inodes(pu, uid, socks, ns, &nfail);
		fprintf(stderr, "registered %d listen port(s), %d unix socket(s) for uid %u "
			"(fs pid %d, %d owned sockets, %d failed)\n", ports, units, uid, fspid, ns, nfail);
		if (nfail || (ns > 0 && ports == 0 && units == 0)) {
			fprintf(stderr, "autohide-net: FAILED -- %d call(s) failed / nothing hidden\n", nfail);
			return 1;
		}
		return 0;
	}

	// ---- hardening subcommands ----

	if (!strcmp(argv[1], "sus-path") && argc >= 3) {
		int rc = 0;
		for (int i = 2; i < argc; i++)
			if (do_path_cmd(CMD_ADD_SUS_PATH, "sus-path", argv[i]))
				rc = 1;
		return rc;
	}

	if (!strcmp(argv[1], "sus-path-loop") && argc == 3)
		return do_path_cmd(CMD_ADD_SUS_PATH_LOOP, "sus-path-loop", argv[2]);

	if (!strcmp(argv[1], "sus-map") && argc >= 3) {
		int rc = 0;
		for (int i = 2; i < argc; i++)
			if (do_path_cmd(CMD_ADD_SUS_MAP, "sus-map", argv[i]))
				rc = 1;
		return rc;
	}

	if (!strcmp(argv[1], "avc-spoof") && argc == 3)
		return do_toggle_cmd(CMD_ENABLE_AVC_SPOOF, "avc-spoof", atoi(argv[2]));

	if (!strcmp(argv[1], "hide-mnts") && argc == 3)
		return do_toggle_cmd(CMD_HIDE_SUS_MNTS, "hide-mnts", atoi(argv[2]));

	if (!strcmp(argv[1], "sus-kstat") && argc == 4)
		return do_kstat_cmd(argv[2], argv[3]);

	usage(argv[0]);
	return 2;
}
