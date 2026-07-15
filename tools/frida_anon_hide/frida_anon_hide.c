// frida_anon_hide.c
// -----------------------------------------------------------------------------
// Userspace companion for the SuSFS "sus_anon_range" kernel filter.
//
// The patched kernel hides ONLY the anonymous VMAs whose exact [start,end) a
// root process registers, and only inside the umount-gated target process. This
// tool registers frida-gum's injected anonymous rwx code region so it disappears
// from /proc/<pid>/maps and /proc/<pid>/smaps (which CRK's anti-cheat reads via a
// direct syscall, bypassing frida's own libc-level maps cloak).
//
// Kernel ABI (exynos990 KernelSU-Next + SuSFS fork) -- reboot(2) kprobe dispatch:
//     reboot(magic1=0xDEADBEEF, magic2=0xFAFAFAFA, cmd, &info)      [root only]
//         cmd 0x60021 = add, 0x60022 = del, 0x60023 = clear
//     info = struct st_susfs_sus_anon_range (layout must match the kernel struct)
// magic1 (0xDEADBEEF) is not LINUX_REBOOT_MAGIC1, so the real reboot(2) that runs
// after the kprobe returns -EINVAL harmlessly -- the device never reboots.
//
// Build (NDK, static so it runs standalone under su):
//   $NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android29-clang \
//       -O2 -static -Wall -o frida_anon_hide frida_anon_hide.c
//
// Usage:
//   frida_anon_hide add      <uid> <start_hex> <end_hex>
//   frida_anon_hide del      <uid> <start_hex>
//   frida_anon_hide clear    <uid>
//   frida_anon_hide scan     <pid>                     # print rwx anon ranges
//   frida_anon_hide autohide <uid> <pid> [baseline]    # register rwx anon ranges
//
// Surgical (recommended) workflow:
//   1) BEFORE frida attaches:  frida_anon_hide scan <pid> > /data/local/tmp/base
//   2) attach frida
//   3) frida_anon_hide autohide <uid> <pid> /data/local/tmp/base
//   -> only ranges that appeared AFTER attach (i.e. frida's) get registered.
// Without a baseline, autohide registers every *unnamed* rwx region; on a stealth
// frida build that is frida's code page (the app's own JIT is a *named* rwx VMA,
// e.g. [anon:dalvik-...], so it is not matched).
// -----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dirent.h>

#define KSU_MAGIC1   0xDEADBEEFu
#define SUSFS_MAGIC  0xFAFAFAFAu
#define CMD_ADD      0x60021u
#define CMD_DEL      0x60022u
#define CMD_CLEAR    0x60023u
#define CMD_ADD_NET_PORT   0x60024u
#define CMD_DEL_NET_PORT   0x60025u
#define CMD_CLEAR_NET_PORT 0x60026u
#define CMD_ADD_NET_UNIX   0x60027u
#define CMD_DEL_NET_UNIX   0x60028u
#define CMD_CLEAR_NET_UNIX 0x60029u

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
				 const unsigned long *socks, int ns)
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
			susfs_call_raw(CMD_ADD_NET_PORT, &np, &np.err);
			printf("net-port uid=%u port=%u (inode %lu) -> %s\n", uid, port, ino,
			       np.err == ERR_SENTINEL ? "FAILED(no dispatch)" :
			       np.err ? strerror(-np.err) : "ok");
			done++;
		}
	}
	fclose(f);
	return done;
}

// register abstract/unix socket inodes from /proc/net/unix owned by socks[]
static int register_unix_inodes(const char *path, unsigned int uid,
				const unsigned long *socks, int ns)
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
		       nu.err ? strerror(-nu.err) : "ok");
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

static void usage(const char *a0)
{
	fprintf(stderr,
		"usage:\n"
		"  %s add          <uid> <start_hex> <end_hex>\n"
		"  %s del          <uid> <start_hex>\n"
		"  %s clear        <uid>\n"
		"  %s scan         <pid>\n"
		"  %s autohide     <uid> <pid> [baseline_file]  # hide frida rwx maps\n"
		"  %s autohide-net <uid> <frida_server_pid>     # hide frida LISTEN port + unix socket\n",
		a0, a0, a0, a0, a0, a0);
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
		if (ns < 0)
			return 1;
		// transactional: clear the uid's net sets first (re-registered per start)
		susfs_call_raw(CMD_CLEAR_NET_PORT, &pc, &pc.err);
		if (pc.err == ERR_SENTINEL) {
			fprintf(stderr, "autohide-net: FAILED -- kernel did not dispatch "
				"(need root + a sus_net kernel)\n");
			return 1;
		}
		susfs_call_raw(CMD_CLEAR_NET_UNIX, &uc, &uc.err);
		ports = register_listen_ports("/proc/net/tcp", uid, socks, ns)
		      + register_listen_ports("/proc/net/tcp6", uid, socks, ns);
		units = register_unix_inodes("/proc/net/unix", uid, socks, ns);
		fprintf(stderr, "registered %d listen port(s), %d unix socket(s) for uid %u "
			"(fs pid %d, %d owned sockets)\n", ports, units, uid, fspid, ns);
		return 0;
	}

	usage(argv[0]);
	return 2;
}
