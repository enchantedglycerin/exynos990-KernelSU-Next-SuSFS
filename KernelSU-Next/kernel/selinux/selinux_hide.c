// SPDX-License-Identifier: GPL-2.0
/*
 * selinux_hide (minimal 4.19 backport of KernelSU-Next's selinux_hide)
 *
 * Takes a snapshot of the STOCK policydb at boot, before KernelSU injects its
 * rules, then answers /sys/fs/selinux/access queries from app UIDs (>= 10000)
 * out of that snapshot. Detectors therefore see the unmodified policy (e.g.
 * `system_server self:process execmem` = denied, `zygote adb_data_file:dir
 * search` = denied) while the live, modified policy keeps working for root and
 * modules (LSPlant/LSPosed still get execmem, etc.).
 *
 * This tree is Linux 4.19 with the selinux_ss model (KSU_COMPAT_USE_SELINUX_STATE,
 * selinux_state.ss->policydb), NOT the 5.10+ selinux_state.policy RCU model, so
 * the snapshot targets a private `struct selinux_ss`.
 *
 * Self-arming: default-enabled and snapshot taken from apply_kernelsu_rules(),
 * because ksud 3.1.0 does not know this feature name and will never toggle it.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>

#include "../klog.h" // IWYU pragma: keep
#include "../feature.h"
#include "selinux.h"       /* KSU: pulls in SELinux security.h/objsec.h, current_sid shim */
#include "ss/services.h"   /* struct selinux_ss, selinux_map, selinux_mapping */
#include "ss/policydb.h"   /* struct policydb, policy_file, policydb_* */
#include "ss/sidtab.h"     /* struct sidtab, sidtab_destroy */

#ifndef SIMPLE_TRANSACTION_LIMIT
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - 1)
#endif

/* default ON; self-arming (see file header) */
static bool ksu_selinux_hide_enabled = true;
static bool ksu_selinux_hide_backup_ready;

/* private stock-policy snapshot + a fake state that points at it */
static struct selinux_ss ksu_backup_ss;
static struct selinux_state ksu_fake_state;

/*
 * Clone the live (still-stock) policydb into ksu_backup_ss via a
 * policydb_write() -> policydb_read() round-trip, build its sidtab from the
 * initial SIDs, and copy the class map (KSU only adds types, never classes, so
 * the live map stays valid for the snapshot). Call from the very top of
 * apply_kernelsu_rules(), before the first ksu_type()/ksu_allow().
 */
void ksu_selinux_hide_snapshot(void)
{
	struct selinux_ss *live_ss;
	struct policydb *live;
	void *data;
	size_t len;
	struct policy_file fp;
	int ret;

	if (ksu_selinux_hide_backup_ready)
		return;

	live_ss = selinux_state.ss;
	if (!live_ss)
		return;
	live = &live_ss->policydb;

	/* headroom: policydb_read() re-adds each type to its own attr map, so the
	 * written image can be a little larger than live->len. */
	len = live->len + (size_t)live->p_types.nprim * (sizeof(u32) + sizeof(u64));
	data = vmalloc(len);
	if (!data) {
		pr_err("ksu_selinux_hide: vmalloc %zu failed\n", len);
		return;
	}

	fp.data = data;
	fp.len = len;

	read_lock(&live_ss->policy_rwlock);
	ret = policydb_write(live, &fp);
	read_unlock(&live_ss->policy_rwlock);
	if (ret) {
		pr_err("ksu_selinux_hide: policydb_write %d\n", ret);
		vfree(data);
		return;
	}
	len -= fp.len; /* bytes actually written */

	memset(&ksu_backup_ss, 0, sizeof(ksu_backup_ss));

	fp.data = data;
	fp.len = len;
	ret = policydb_read(&ksu_backup_ss.policydb, &fp);
	vfree(data);
	if (ret) {
		pr_err("ksu_selinux_hide: policydb_read %d\n", ret);
		return;
	}
	ksu_backup_ss.policydb.len = len;

	ret = policydb_load_isids(&ksu_backup_ss.policydb, &ksu_backup_ss.sidtab);
	if (ret) {
		pr_err("ksu_selinux_hide: policydb_load_isids %d\n", ret);
		policydb_destroy(&ksu_backup_ss.policydb);
		return;
	}

	rwlock_init(&ksu_backup_ss.policy_rwlock);
	ksu_backup_ss.latest_granting = live_ss->latest_granting;

	/* deep-copy the class map (same classes as live) so it survives any later
	 * live policy reload that would free the original mapping. */
	ksu_backup_ss.map.size = live_ss->map.size;
	ksu_backup_ss.map.mapping =
		kmemdup(live_ss->map.mapping,
			live_ss->map.size * sizeof(struct selinux_mapping),
			GFP_KERNEL);
	if (!ksu_backup_ss.map.mapping) {
		pr_err("ksu_selinux_hide: map dup failed\n");
		sidtab_destroy(&ksu_backup_ss.sidtab);
		policydb_destroy(&ksu_backup_ss.policydb);
		return;
	}

	/* only .ss is consulted by compute_av/str_to_sid; copy the rest for safety */
	ksu_fake_state = selinux_state;
	ksu_fake_state.ss = &ksu_backup_ss;

	ksu_selinux_hide_backup_ready = true;
	pr_info("ksu_selinux_hide: stock snapshot ready (len=%zu, map=%u)\n",
		len, ksu_backup_ss.map.size);
}

/*
 * Hook body for sel_write_access(). Returns -ENODATA to tell the caller to run
 * the original handler; otherwise returns the length written to buf (or a
 * negative errno, exactly as the stock handler would).
 */
ssize_t ksu_selinux_hide_access(char *buf, size_t size)
{
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid;
	u16 tclass;
	struct av_decision avd;
	ssize_t length;

	if (!ksu_selinux_hide_enabled || !ksu_selinux_hide_backup_ready)
		return -ENODATA;
	if (current_uid().val < 10000)
		return -ENODATA;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		return length;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	/* resolve + compute entirely against the stock snapshot */
	length = security_context_str_to_sid(&ksu_fake_state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;
	length = security_context_str_to_sid(&ksu_fake_state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	security_compute_av_user(&ksu_fake_state, ssid, tsid, tclass, &avd);

	length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x",
			   avd.allowed, 0xffffffff, avd.auditallow, avd.auditdeny,
			   1u /* stock seqno */, avd.flags);
out:
	kfree(tcon);
	kfree(scon);
	return length;
}

static int ksu_selinux_hide_get(u64 *value)
{
	*value = ksu_selinux_hide_enabled ? 1 : 0;
	return 0;
}

static int ksu_selinux_hide_set(u64 value)
{
	ksu_selinux_hide_enabled = !!value;
	pr_info("ksu_selinux_hide: enabled=%d\n", ksu_selinux_hide_enabled);
	return 0;
}

static const struct ksu_feature_handler ksu_selinux_hide_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = ksu_selinux_hide_get,
	.set_handler = ksu_selinux_hide_set,
};

void ksu_selinux_hide_init(void)
{
	if (ksu_register_feature_handler(&ksu_selinux_hide_handler))
		pr_err("ksu_selinux_hide: register handler failed\n");
}

void ksu_selinux_hide_late_init(void)
{
	pr_info("ksu_selinux_hide: late_init backup_ready=%d enabled=%d\n",
		ksu_selinux_hide_backup_ready, ksu_selinux_hide_enabled);
}
