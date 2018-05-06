// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* COMMON Applications Kept Enhanced (CAKE) discipline
 *
 * Copyright (C) 2014-2018 Jonathan Morton <chromatix99@gmail.com>
 * Copyright (C) 2015-2018 Toke Høiland-Jørgensen <toke@toke.dk>
 * Copyright (C) 2014-2018 Dave Täht <dave.taht@gmail.com>
 * Copyright (C) 2015-2018 Sebastian Moeller <moeller0@gmx.de>
 * (C) 2015-2018 Kevin Darbyshire-Bryant <kevin@darbyshire-bryant.me.uk>
 * Copyright (C) 2017 Ryan Mounce <ryan@mounce.com.au>
 *
 * The CAKE Principles:
 *		   (or, how to have your cake and eat it too)
 *
 * This is a combination of several shaping, AQM and FQ techniques into one
 * easy-to-use package:
 *
 * - An overall bandwidth shaper, to move the bottleneck away from dumb CPE
 *   equipment and bloated MACs.  This operates in deficit mode (as in sch_fq),
 *   eliminating the need for any sort of burst parameter (eg. token bucket
 *   depth).  Burst support is limited to that necessary to overcome scheduling
 *   latency.
 *
 * - A Diffserv-aware priority queue, giving more priority to certain classes,
 *   up to a specified fraction of bandwidth.  Above that bandwidth threshold,
 *   the priority is reduced to avoid starving other tins.
 *
 * - Each priority tin has a separate Flow Queue system, to isolate traffic
 *   flows from each other.  This prevents a burst on one flow from increasing
 *   the delay to another.  Flows are distributed to queues using a
 *   set-associative hash function.
 *
 * - Each queue is actively managed by Cobalt, which is a combination of the
 *   Codel and Blue AQM algorithms.  This serves flows fairly, and signals
 *   congestion early via ECN (if available) and/or packet drops, to keep
 *   latency low.  The codel parameters are auto-tuned based on the bandwidth
 *   setting, as is necessary at low bandwidths.
 *
 * The configuration parameters are kept deliberately simple for ease of use.
 * Everything has sane defaults.  Complete generality of configuration is *not*
 * a goal.
 *
 * The priority queue operates according to a weighted DRR scheme, combined with
 * a bandwidth tracker which reuses the shaper logic to detect which side of the
 * bandwidth sharing threshold the tin is operating.  This determines whether a
 * priority-based weight (high) or a bandwidth-based weight (low) is used for
 * that tin in the current pass.
 *
 * This qdisc was inspired by Eric Dumazet's fq_codel code, which he kindly
 * granted us permission to leverage.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/reciprocal_div.h>
#include <net/netlink.h>
#include <linux/version.h>
#include "pkt_sched.h"
#include <linux/if_vlan.h>
#include <net/tcp.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
#include <net/flow_keys.h>
#else
#include <net/flow_dissector.h>
#endif
#include "cobalt.h"

#if IS_REACHABLE(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack.h>
#endif

#if (KERNEL_VERSION(4, 4, 11) > LINUX_VERSION_CODE) || ((KERNEL_VERSION(4, 5, 0) <= LINUX_VERSION_CODE) && (KERNEL_VERSION(4, 5, 5) > LINUX_VERSION_CODE))
#define qdisc_tree_reduce_backlog(_a, _b, _c) qdisc_tree_decrease_qlen(_a, _b)
#endif

#define CAKE_SET_WAYS (8)
#define CAKE_MAX_TINS (8)
#define CAKE_QUEUES (1024)
#define CAKE_SPLIT_GSO_THRESHOLD (125000000) /* 1Gbps */

#ifndef CAKE_VERSION
#define CAKE_VERSION "unknown"
#endif
static char *cake_version __attribute__((used)) = "Cake version: "
		CAKE_VERSION;

enum {
	CAKE_SET_NONE = 0,
	CAKE_SET_SPARSE,
	CAKE_SET_SPARSE_WAIT, /* counted in SPARSE, actually in BULK */
	CAKE_SET_BULK,
	CAKE_SET_DECAYING
};

struct cake_flow {
	/* this stuff is all needed per-flow at dequeue time */
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	s32		  deficit;
	struct cobalt_vars cvars;
	u16		  srchost; /* index into cake_host table */
	u16		  dsthost;
	u8		  set;
}; /* please try to keep this structure <= 64 bytes */

struct cake_host {
	u32 srchost_tag;
	u32 dsthost_tag;
	u16 srchost_refcnt;
	u16 dsthost_refcnt;
};

struct cake_heap_entry {
	u16 t:3, b:10;
};

struct cake_tin_data {
	struct cake_flow flows[CAKE_QUEUES];
	u32	backlogs[CAKE_QUEUES];
	u32	tags[CAKE_QUEUES]; /* for set association */
	u16	overflow_idx[CAKE_QUEUES];
	struct cake_host hosts[CAKE_QUEUES]; /* for triple isolation */
	u32	perturb;
	u16	flow_quantum;

	struct cobalt_params cparams;
	u32	drop_overlimit;
	u16	bulk_flow_count;
	u16	sparse_flow_count;
	u16	decaying_flow_count;
	u16	unresponsive_flow_count;

	u32	max_skblen;

	struct list_head new_flows;
	struct list_head old_flows;
	struct list_head decaying_flows;

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u64	tin_time_next_packet;
	u32	tin_rate_ns;
	u32	tin_rate_bps;
	u16	tin_rate_shft;

	u16	tin_quantum_prio;
	u16	tin_quantum_band;
	s32	tin_deficit;
	u32	tin_backlog;
	u32	tin_dropped;
	u32	tin_ecn_mark;

	u32	packets;
	u64	bytes;

	u32	ack_drops;

	/* moving averages */
	cobalt_time_t avge_delay;
	cobalt_time_t peak_delay;
	cobalt_time_t base_delay;

	/* hash function stats */
	u32	way_directs;
	u32	way_hits;
	u32	way_misses;
	u32	way_collisions;
}; /* number of tins is small, so size of this struct doesn't matter much */

struct cake_sched_data {
	struct cake_tin_data *tins;

	struct cake_heap_entry overflow_heap[CAKE_QUEUES * CAKE_MAX_TINS];
	u16		overflow_timeout;

	u16		tin_cnt;
	u8		tin_mode;
#define	CAKE_FLOW_NAT_FLAG 64
	u8		flow_mode;
	u8		ack_filter;
	u8		atm_mode;

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u16		rate_shft;
	u64		time_next_packet;
	u64		failsafe_next_packet;
	u32		rate_ns;
	u32		rate_bps;
	u16		rate_flags;
	s16		rate_overhead;
	u16		rate_mpu;
	u32		interval;
	u32		target;

	/* resource tracking */
	u32		buffer_used;
	u32		buffer_max_used;
	u32		buffer_limit;
	u32		buffer_config_limit;

	/* indices for dequeue */
	u16		cur_tin;
	u16		cur_flow;

	struct qdisc_watchdog watchdog;
	const u8	*tin_index;
	const u8	*tin_order;

	/* bandwidth capacity estimate */
	u64		last_packet_time;
	u64		avg_packet_interval;
	u64		avg_window_begin;
	u32		avg_window_bytes;
	u32		avg_peak_bandwidth;
	u64		last_reconfig_time;

	/* packet length stats */
	u32 avg_netoff;
	u16 max_netlen;
	u16 max_adjlen;
	u16 min_netlen;
	u16 min_adjlen;
};

enum {
	CAKE_FLAG_OVERHEAD	   = BIT(0),
	CAKE_FLAG_AUTORATE_INGRESS = BIT(1),
	CAKE_FLAG_INGRESS	   = BIT(2),
	CAKE_FLAG_WASH		   = BIT(3),
	CAKE_FLAG_SPLIT_GSO	   = BIT(4)
};

static u16 quantum_div[CAKE_QUEUES + 1] = {0};

/* Diffserv lookup tables */

static const u8 precedence[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 6,
	7, 7, 7, 7, 7, 7, 7, 7,
};

static const u8 diffserv8[] = {
	2, 5, 1, 2, 4, 2, 2, 2,
	0, 2, 1, 2, 1, 2, 1, 2,
	5, 2, 4, 2, 4, 2, 4, 2,
	3, 2, 3, 2, 3, 2, 3, 2,
	6, 2, 3, 2, 3, 2, 3, 2,
	6, 2, 2, 2, 6, 2, 6, 2,
	7, 2, 2, 2, 2, 2, 2, 2,
	7, 2, 2, 2, 2, 2, 2, 2,
};

static const u8 diffserv4[] = {
	0, 2, 0, 0, 2, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0,
	2, 0, 2, 0, 2, 0, 2, 0,
	2, 0, 2, 0, 2, 0, 2, 0,
	3, 0, 2, 0, 2, 0, 2, 0,
	3, 0, 0, 0, 3, 0, 3, 0,
	3, 0, 0, 0, 0, 0, 0, 0,
	3, 0, 0, 0, 0, 0, 0, 0,
};

static const u8 diffserv3[] = {
	0, 0, 0, 0, 2, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 2, 0, 2, 0,
	2, 0, 0, 0, 0, 0, 0, 0,
	2, 0, 0, 0, 0, 0, 0, 0,
};

static const u8 besteffort[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

/* tin priority order for stats dumping */

static const u8 normal_order[] = {0, 1, 2, 3, 4, 5, 6, 7};
static const u8 bulk_order[] = {1, 0, 2, 3};

#define REC_INV_SQRT_CACHE (16)
static u32 cobalt_rec_inv_sqrt_cache[REC_INV_SQRT_CACHE] = {0};

/* http://en.wikipedia.org/wiki/Methods_of_computing_square_roots
 * new_invsqrt = (invsqrt / 2) * (3 - count * invsqrt^2)
 *
 * Here, invsqrt is a fixed point number (< 1.0), 32bit mantissa, aka Q0.32
 */

static void cobalt_newton_step(struct cobalt_vars *vars)
{
	u32 invsqrt = vars->rec_inv_sqrt;
	u32 invsqrt2 = ((u64)invsqrt * invsqrt) >> 32;
	u64 val = (3LL << 32) - ((u64)vars->count * invsqrt2);

	val >>= 2; /* avoid overflow in following multiply */
	val = (val * invsqrt) >> (32 - 2 + 1);

	vars->rec_inv_sqrt = val;
}

static void cobalt_invsqrt(struct cobalt_vars *vars)
{
	if (vars->count < REC_INV_SQRT_CACHE)
		vars->rec_inv_sqrt = cobalt_rec_inv_sqrt_cache[vars->count];
	else
		cobalt_newton_step(vars);
}

/* There is a big difference in timing between the accurate values placed in
 * the cache and the approximations given by a single Newton step for small
 * count values, particularly when stepping from count 1 to 2 or vice versa.
 * Above 16, a single Newton step gives sufficient accuracy in either
 * direction, given the precision stored.
 *
 * The magnitude of the error when stepping up to count 2 is such as to give
 * the value that *should* have been produced at count 4.
 */

static void cobalt_cache_init(void)
{
	struct cobalt_vars v;

	memset(&v, 0, sizeof(v));
	v.rec_inv_sqrt = ~0U;
	cobalt_rec_inv_sqrt_cache[0] = v.rec_inv_sqrt;

	for (v.count = 1; v.count < REC_INV_SQRT_CACHE; v.count++) {
		cobalt_newton_step(&v);
		cobalt_newton_step(&v);
		cobalt_newton_step(&v);
		cobalt_newton_step(&v);

		cobalt_rec_inv_sqrt_cache[v.count] = v.rec_inv_sqrt;
	}
}

static void cobalt_vars_init(struct cobalt_vars *vars)
{
	memset(vars, 0, sizeof(*vars));

	if (!cobalt_rec_inv_sqrt_cache[0]) {
		cobalt_cache_init();
		cobalt_rec_inv_sqrt_cache[0] = ~0;
	}
}

/* CoDel control_law is t + interval/sqrt(count)
 * We maintain in rec_inv_sqrt the reciprocal value of sqrt(count) to avoid
 * both sqrt() and divide operation.
 */
static cobalt_time_t cobalt_control(cobalt_time_t t,
				    cobalt_time_t interval,
				    u32 rec_inv_sqrt)
{
	return t + reciprocal_scale(interval, rec_inv_sqrt);
}

/* Call this when a packet had to be dropped due to queue overflow.  Returns
 * true if the BLUE state was quiescent before but active after this call.
 */
static bool cobalt_queue_full(struct cobalt_vars *vars,
			      struct cobalt_params *p,
			      cobalt_time_t now)
{
	bool up = false;

	if ((now - vars->blue_timer) > p->target) {
		up = !vars->p_drop;
		vars->p_drop += p->p_inc;
		if (vars->p_drop < p->p_inc)
			vars->p_drop = ~0;
		vars->blue_timer = now;
	}
	vars->dropping = true;
	vars->drop_next = now;
	if (!vars->count)
		vars->count = 1;

	return up;
}

/* Call this when the queue was serviced but turned out to be empty.  Returns
 * true if the BLUE state was active before but quiescent after this call.
 */
static bool cobalt_queue_empty(struct cobalt_vars *vars,
			       struct cobalt_params *p,
			       cobalt_time_t now)
{
	bool down = false;

	if (vars->p_drop && (now - vars->blue_timer) > p->target) {
		if (vars->p_drop < p->p_dec)
			vars->p_drop = 0;
		else
			vars->p_drop -= p->p_dec;
		vars->blue_timer = now;
		down = !vars->p_drop;
	}
	vars->dropping = false;

	if (vars->count && (now - vars->drop_next) >= 0) {
		vars->count--;
		cobalt_invsqrt(vars);
		vars->drop_next = cobalt_control(vars->drop_next,
						 p->interval,
						 vars->rec_inv_sqrt);
	}

	return down;
}

/* Call this with a freshly dequeued packet for possible congestion marking.
 * Returns true as an instruction to drop the packet, false for delivery.
 */
static bool cobalt_should_drop(struct cobalt_vars *vars,
			       struct cobalt_params *p,
			       cobalt_time_t now,
			       struct sk_buff *skb,
			       u32 bulk_flows)
{
	bool drop = false;

	/* Simplified Codel implementation */
	cobalt_tdiff_t sojourn  = now - cobalt_get_enqueue_time(skb);

/* The 'schedule' variable records, in its sign, whether 'now' is before or
 * after 'drop_next'.  This allows 'drop_next' to be updated before the next
 * scheduling decision is actually branched, without destroying that
 * information.  Similarly, the first 'schedule' value calculated is preserved
 * in the boolean 'next_due'.
 *
 * As for 'drop_next', we take advantage of the fact that 'interval' is both
 * the delay between first exceeding 'target' and the first signalling event,
 * *and* the scaling factor for the signalling frequency.  It's therefore very
 * natural to use a single mechanism for both purposes, and eliminates a
 * significant amount of reference Codel's spaghetti code.  To help with this,
 * both the '0' and '1' entries in the invsqrt cache are 0xFFFFFFFF, as close
 * as possible to 1.0 in fixed-point.
 */

	cobalt_tdiff_t schedule = now - vars->drop_next;
	bool over_target = sojourn > p->target &&
	                   sojourn > p->mtu_time * bulk_flows * 2 &&
	                   sojourn > p->mtu_time * 4;
	bool next_due    = vars->count && schedule >= 0;

	vars->ecn_marked = false;

	if (over_target) {
		if (!vars->dropping) {
			vars->dropping = true;
			vars->drop_next = cobalt_control(now,
							 p->interval,
							 vars->rec_inv_sqrt);
		}
		if (!vars->count)
			vars->count = 1;
	} else if (vars->dropping) {
		vars->dropping = false;
	}

	if (next_due && vars->dropping) {
		/* Use ECN mark if possible, otherwise drop */
		drop = !(vars->ecn_marked = INET_ECN_set_ce(skb));

		vars->count++;
		if (!vars->count)
			vars->count--;
		cobalt_invsqrt(vars);
		vars->drop_next = cobalt_control(vars->drop_next,
						 p->interval,
						 vars->rec_inv_sqrt);
		schedule = now - vars->drop_next;
	} else {
		while (next_due) {
			vars->count--;
			cobalt_invsqrt(vars);
			vars->drop_next = cobalt_control(vars->drop_next,
							 p->interval,
							 vars->rec_inv_sqrt);
			schedule = now - vars->drop_next;
			next_due = vars->count && schedule >= 0;
		}
	}

	/* Simple BLUE implementation.  Lack of ECN is deliberate. */
	if (vars->p_drop)
		drop |= (prandom_u32() < vars->p_drop);

	/* Overload the drop_next field as an activity timeout */
	if (!vars->count)
		vars->drop_next = now + p->interval;
	else if (schedule > 0 && !drop)
		vars->drop_next = now;

	return drop;
}

#if IS_REACHABLE(CONFIG_NF_CONNTRACK)
#if KERNEL_VERSION(4, 0, 0) > LINUX_VERSION_CODE
#define tc_skb_protocol(_skb) \
(vlan_tx_tag_present(_skb) ? _skb->vlan_proto : _skb->protocol)
#endif

static void cake_update_flowkeys(struct flow_keys *keys,
				 const struct sk_buff *skb)
{
	enum ip_conntrack_info ctinfo;
	bool rev = false;

	struct nf_conn *ct;
	const struct nf_conntrack_tuple *tuple;

	if (tc_skb_protocol(skb) != htons(ETH_P_IP))
		return;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct) {
		tuple = nf_ct_tuple(ct, CTINFO2DIR(ctinfo));
	} else {
		const struct nf_conntrack_tuple_hash *hash;
		struct nf_conntrack_tuple srctuple;

#if KERNEL_VERSION(4, 4, 0) > LINUX_VERSION_CODE
		if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb),
				       NFPROTO_IPV4, &srctuple))
#else
		if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb),
				       NFPROTO_IPV4, dev_net(skb->dev),
				       &srctuple))
#endif
			return;

#if KERNEL_VERSION(4, 3, 0) > LINUX_VERSION_CODE
		hash = nf_conntrack_find_get(dev_net(skb->dev),
					     NF_CT_DEFAULT_ZONE,
					     &srctuple);
#else
		hash = nf_conntrack_find_get(dev_net(skb->dev),
					     &nf_ct_zone_dflt,
					     &srctuple);
#endif
		if (!hash)
			return;

		rev = true;
		ct = nf_ct_tuplehash_to_ctrack(hash);
		tuple = nf_ct_tuple(ct, !hash->tuple.dst.dir);
	}

#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	keys->src = rev ? tuple->dst.u3.ip : tuple->src.u3.ip;
	keys->dst = rev ? tuple->src.u3.ip : tuple->dst.u3.ip;
#else
	keys->addrs.v4addrs.src = rev ? tuple->dst.u3.ip : tuple->src.u3.ip;
	keys->addrs.v4addrs.dst = rev ? tuple->src.u3.ip : tuple->dst.u3.ip;
#endif

#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	if (keys->ports) {
		keys->port16[0] = rev ? tuple->dst.u.all : tuple->src.u.all;
		keys->port16[1] = rev ? tuple->src.u.all : tuple->dst.u.all;
	}
#else
	if (keys->ports.ports) {
		keys->ports.src = rev ? tuple->dst.u.all : tuple->src.u.all;
		keys->ports.dst = rev ? tuple->src.u.all : tuple->dst.u.all;
	}
#endif
	if (rev)
		nf_ct_put(ct);
}
#else
static void cake_update_flowkeys(struct flow_keys *keys,
				 const struct sk_buff *skb)
{
	/* There is nothing we can do here without CONNTRACK */
}
#endif

/* Cake has several subtle multiple bit settings. In these cases you
 *  would be matching triple isolate mode as well.
 */

static bool cake_dsrc(int flow_mode)
{
	return (flow_mode & CAKE_FLOW_DUAL_SRC) == CAKE_FLOW_DUAL_SRC;
}

static bool cake_ddst(int flow_mode)
{
	return (flow_mode & CAKE_FLOW_DUAL_DST) == CAKE_FLOW_DUAL_DST;
}

static u32 cake_hash(struct cake_tin_data *q, const struct sk_buff *skb,
		     int flow_mode)
{
#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	struct flow_keys keys;
#else
	struct flow_keys keys, host_keys;
#endif
	u32 flow_hash = 0, srchost_hash, dsthost_hash;
	u16 reduced_hash, srchost_idx, dsthost_idx;

	if (unlikely(flow_mode == CAKE_FLOW_NONE))
		return 0;

#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	skb_flow_dissect(skb, &keys);

	if (flow_mode & CAKE_FLOW_NAT_FLAG)
		cake_update_flowkeys(&keys, skb);

	srchost_hash = jhash_1word((__force u32)keys.src, q->perturb);
	dsthost_hash = jhash_1word((__force u32)keys.dst, q->perturb);

	if (flow_mode & CAKE_FLOW_FLOWS)
		flow_hash = jhash_3words((__force u32)keys.dst, (__force u32)keys.src ^ keys.ip_proto, (__force u32)keys.ports, q->perturb);

#else

/* Linux kernel 4.2.x have skb_flow_dissect_flow_keys which takes only 2
 * arguments
 */
#if (KERNEL_VERSION(4, 2, 0) <= LINUX_VERSION_CODE) && (KERNEL_VERSION(4, 3, 0) >  LINUX_VERSION_CODE)
	skb_flow_dissect_flow_keys(skb, &keys);
#else
	skb_flow_dissect_flow_keys(skb, &keys,
				   FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
#endif

	if (flow_mode & CAKE_FLOW_NAT_FLAG)
		cake_update_flowkeys(&keys, skb);

	/* flow_hash_from_keys() sorts the addresses by value, so we have
	 * to preserve their order in a separate data structure to treat
	 * src and dst host addresses as independently selectable.
	 */
	host_keys = keys;
	host_keys.ports.ports     = 0;
	host_keys.basic.ip_proto  = 0;
	host_keys.keyid.keyid     = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	host_keys.tags.vlan_id    = 0;
#endif
	host_keys.tags.flow_label = 0;

	switch (host_keys.control.addr_type) {
	case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
		host_keys.addrs.v4addrs.src = 0;
		dsthost_hash = flow_hash_from_keys(&host_keys);
		host_keys.addrs.v4addrs.src = keys.addrs.v4addrs.src;
		host_keys.addrs.v4addrs.dst = 0;
		srchost_hash = flow_hash_from_keys(&host_keys);
		break;

	case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
		memset(&host_keys.addrs.v6addrs.src, 0,
		       sizeof(host_keys.addrs.v6addrs.src));
		dsthost_hash = flow_hash_from_keys(&host_keys);
		host_keys.addrs.v6addrs.src = keys.addrs.v6addrs.src;
		memset(&host_keys.addrs.v6addrs.dst, 0,
		       sizeof(host_keys.addrs.v6addrs.dst));
		srchost_hash = flow_hash_from_keys(&host_keys);
		break;

	default:
		dsthost_hash = 0;
		srchost_hash = 0;
	}

	/* This *must* be after the above switch, since as a
	 * side-effect it sorts the src and dst addresses.
	 */
	if (flow_mode & CAKE_FLOW_FLOWS)
		flow_hash = flow_hash_from_keys(&keys);
#endif

	if (!(flow_mode & CAKE_FLOW_FLOWS)) {
		if (flow_mode & CAKE_FLOW_SRC_IP)
			flow_hash ^= srchost_hash;

		if (flow_mode & CAKE_FLOW_DST_IP)
			flow_hash ^= dsthost_hash;
	}

	reduced_hash = flow_hash % CAKE_QUEUES;

	/* set-associative hashing */
	/* fast path if no hash collision (direct lookup succeeds) */
	if (likely(q->tags[reduced_hash] == flow_hash &&
		   q->flows[reduced_hash].set)) {
		q->way_directs++;
	} else {
		u32 inner_hash = reduced_hash % CAKE_SET_WAYS;
		u32 outer_hash = reduced_hash - inner_hash;
		u32 i, k;
		bool allocate_src = false;
		bool allocate_dst = false;

		/* check if any active queue in the set is reserved for
		 * this flow.
		 */
		for (i = 0, k = inner_hash; i < CAKE_SET_WAYS;
		     i++, k = (k + 1) % CAKE_SET_WAYS) {
			if (q->tags[outer_hash + k] == flow_hash) {
				if (i)
					q->way_hits++;

				if (!q->flows[outer_hash + k].set) {
					/* need to increment host refcnts */
					allocate_src = cake_dsrc(flow_mode);
					allocate_dst = cake_ddst(flow_mode);
				}

				goto found;
			}
		}

		/* no queue is reserved for this flow, look for an
		 * empty one.
		 */
		for (i = 0; i < CAKE_SET_WAYS;
			 i++, k = (k + 1) % CAKE_SET_WAYS) {
			if (!q->flows[outer_hash + k].set) {
				q->way_misses++;
				allocate_src = cake_dsrc(flow_mode);
				allocate_dst = cake_ddst(flow_mode);
				goto found;
			}
		}

		/* With no empty queues, default to the original
		 * queue, accept the collision, update the host tags.
		 */
		q->way_collisions++;
		q->hosts[q->flows[reduced_hash].srchost].srchost_refcnt--;
		q->hosts[q->flows[reduced_hash].dsthost].dsthost_refcnt--;
		allocate_src = cake_dsrc(flow_mode);
		allocate_dst = cake_ddst(flow_mode);
found:
		/* reserve queue for future packets in same flow */
		reduced_hash = outer_hash + k;
		q->tags[reduced_hash] = flow_hash;

		if (allocate_src) {
			srchost_idx = srchost_hash % CAKE_QUEUES;
			inner_hash = srchost_idx % CAKE_SET_WAYS;
			outer_hash = srchost_idx - inner_hash;
			for (i = 0, k = inner_hash; i < CAKE_SET_WAYS;
				i++, k = (k + 1) % CAKE_SET_WAYS) {
				if (q->hosts[outer_hash + k].srchost_tag ==
				    srchost_hash)
					goto found_src;
			}
			for (i = 0; i < CAKE_SET_WAYS;
				i++, k = (k + 1) % CAKE_SET_WAYS) {
				if (!q->hosts[outer_hash + k].srchost_refcnt)
					break;
			}
			q->hosts[outer_hash + k].srchost_tag = srchost_hash;
found_src:
			srchost_idx = outer_hash + k;
			q->hosts[srchost_idx].srchost_refcnt++;
			q->flows[reduced_hash].srchost = srchost_idx;
		}

		if (allocate_dst) {
			dsthost_idx = dsthost_hash % CAKE_QUEUES;
			inner_hash = dsthost_idx % CAKE_SET_WAYS;
			outer_hash = dsthost_idx - inner_hash;
			for (i = 0, k = inner_hash; i < CAKE_SET_WAYS;
			     i++, k = (k + 1) % CAKE_SET_WAYS) {
				if (q->hosts[outer_hash + k].dsthost_tag ==
				    dsthost_hash)
					goto found_dst;
			}
			for (i = 0; i < CAKE_SET_WAYS;
			     i++, k = (k + 1) % CAKE_SET_WAYS) {
				if (!q->hosts[outer_hash + k].dsthost_refcnt)
					break;
			}
			q->hosts[outer_hash + k].dsthost_tag = dsthost_hash;
found_dst:
			dsthost_idx = outer_hash + k;
			q->hosts[dsthost_idx].dsthost_refcnt++;
			q->flows[reduced_hash].dsthost = dsthost_idx;
		}
	}

	return reduced_hash;
}

/* helper functions : might be changed when/if skb use a standard list_head */
/* remove one skb from head of slot queue */

static struct sk_buff *dequeue_head(struct cake_flow *flow)
{
	struct sk_buff *skb = flow->head;

	if (skb) {
		flow->head = skb->next;
		skb->next = NULL;
	}

	return skb;
}

/* add skb to flow queue (tail add) */

static void flow_queue_add(struct cake_flow *flow, struct sk_buff *skb)
{
	if (!flow->head)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static struct iphdr *cake_get_iphdr(const struct sk_buff *skb,
				    struct ipv6hdr *buf)
{
	unsigned int offset = skb_network_offset(skb);
	struct iphdr *iph;

	iph = skb_header_pointer(skb, offset, sizeof(struct iphdr), buf);

	if (!iph)
		return NULL;

	if (iph->version == 4 && iph->protocol == IPPROTO_IPV6)
		return skb_header_pointer(skb, offset + iph->ihl * 4,
					  sizeof(struct ipv6hdr), buf);

	else if (iph->version == 4)
		return iph;

	else if (iph->version == 6)
		return skb_header_pointer(skb, offset, sizeof(struct ipv6hdr),
					  buf);

	return NULL;
}

static struct tcphdr *cake_get_tcphdr(const struct sk_buff *skb,
				      void *buf, unsigned int bufsize)
{
	unsigned int offset = skb_network_offset(skb);
	const struct ipv6hdr *ipv6h;
	const struct tcphdr *tcph;
	const struct iphdr *iph;
	struct ipv6hdr _ipv6h;
	struct tcphdr _tcph;

	ipv6h = skb_header_pointer(skb, offset, sizeof(_ipv6h), &_ipv6h);

	if (!ipv6h)
		return NULL;

	if (ipv6h->version == 4) {
		iph = (struct iphdr *)ipv6h;
		offset += iph->ihl * 4;

		/* special-case 6in4 tunnelling, as that is a common way to get
		 * v6 connectivity in the home
		 */
		if (iph->protocol == IPPROTO_IPV6) {
			ipv6h = skb_header_pointer(skb, offset,
						   sizeof(_ipv6h), &_ipv6h);

			if (!ipv6h || ipv6h->nexthdr != IPPROTO_TCP)
				return NULL;

			offset += sizeof(struct ipv6hdr);

		} else if (iph->protocol != IPPROTO_TCP) {
			return NULL;
		}

	} else if (ipv6h->version == 6) {
		if (ipv6h->nexthdr != IPPROTO_TCP)
			return NULL;

		offset += sizeof(struct ipv6hdr);
	} else {
		return NULL;
	}

	tcph = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
	if (!tcph)
		return NULL;

	return skb_header_pointer(skb, offset,
				  min(__tcp_hdrlen(tcph), bufsize), buf);
}

static bool cake_tcph_is_sack(const struct tcphdr *tcph)
{
	/* inspired by tcp_parse_options in tcp_input.c */
	int length = __tcp_hdrlen(tcph) - sizeof(struct tcphdr);
	const u8 *ptr = (const u8 *)(tcph + 1);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		if (opcode == TCPOPT_EOL)
			break;
		if (opcode == TCPOPT_NOP) {
			length--;
			continue;
		}
		opsize = *ptr++;
		if (opsize < 2 || opsize > length)
			break;
		if (opcode == TCPOPT_SACK)
			return true;
		ptr += opsize - 2;
		length -= opsize;
	}

	return false;
}

static struct sk_buff *cake_ack_filter(struct cake_sched_data *q,
				       struct cake_flow *flow)
{
	bool aggressive = q->ack_filter == CAKE_ACK_AGGRESSIVE;
	struct sk_buff *elig_ack = NULL, *elig_ack_prev = NULL;
	struct sk_buff *skb_check, *skb_prev = NULL;
	const struct ipv6hdr *ipv6h, *ipv6h_check;
	const struct tcphdr *tcph, *tcph_check;
	const struct iphdr *iph, *iph_check;
	const struct sk_buff *skb;
	struct ipv6hdr _iph, _iph_check;
	struct tcphdr _tcph_check;
	unsigned char _tcph[64]; /* need to hold maximum hdr size */
	int seglen, num_found = 0;

	/* no other possible ACKs to filter */
	if (flow->head == flow->tail)
		return NULL;

	skb = flow->tail;
	tcph = cake_get_tcphdr(skb, _tcph, sizeof(_tcph));
	iph = cake_get_iphdr(skb, &_iph);
	if (!tcph)
		return NULL;

	/* the 'triggering' packet need only have the ACK flag set.
	 * also check that SYN is not set, as there won't be any previous ACKs.
	 */
	if ((tcp_flag_word(tcph) &
	     (TCP_FLAG_ACK | TCP_FLAG_SYN)) != TCP_FLAG_ACK)
		return NULL;

	/* the 'triggering' ACK is at the tail of the queue, we have already
	 * returned if it is the only packet in the flow. loop through the rest
	 * of the queue looking for pure ACKs with the same 5-tuple as the
	 * triggering one.
	 */
	for (skb_check = flow->head;
	     skb_check && skb_check != skb;
	     skb_prev = skb_check, skb_check = skb_check->next) {
		iph_check = cake_get_iphdr(skb_check, &_iph_check);
		tcph_check = cake_get_tcphdr(skb_check, &_tcph_check,
					     sizeof(_tcph_check));

		/* only TCP packets with matching 5-tuple are eligible */
		if (!tcph_check || iph->version != iph_check->version ||
		    tcph_check->source != tcph->source ||
		    tcph_check->dest != tcph->dest)
			continue;

		if (iph_check->version == 4) {
			if (iph_check->saddr != iph->saddr ||
			    iph_check->daddr != iph->daddr)
				continue;

			seglen = ntohs(iph_check->tot_len) -
				       (4 * iph_check->ihl);
		} else if (iph_check->version == 6) {
			ipv6h = (struct ipv6hdr *)iph;
			ipv6h_check = (struct ipv6hdr *)iph_check;

			if (ipv6_addr_cmp(&ipv6h_check->saddr, &ipv6h->saddr) ||
			    ipv6_addr_cmp(&ipv6h_check->daddr, &ipv6h->daddr))
				continue;

			seglen = ntohs(ipv6h_check->payload_len);
		} else {
			WARN_ON(1);  /* shouldn't happen */
			continue;
		}

		/* stricter criteria apply to ACKs that we may filter
		 * 3 reserved flags must be unset to avoid future breakage
		 * ECE/CWR/NS can be safely ignored
		 * ACK must be set
		 * All other flags URG/PSH/RST/SYN/FIN must be unset
		 * 0x0FFF0000 = all TCP flags (confirm ACK=1, others zero)
		 * 0x01C00000 = NS/CWR/ECE (safe to ignore)
		 * 0x0E3F0000 = 0x0FFF0000 & ~0x01C00000
		 * must be 'pure' ACK, contain zero bytes of segment data
		 * options are ignored
		 */
		if (((tcp_flag_word(tcph_check) &
			   cpu_to_be32(0x0E3F0000)) != TCP_FLAG_ACK) ||
			 ((seglen - __tcp_hdrlen(tcph_check)) != 0))
			continue;

		/* The triggering packet must ACK more data than the ACK under
		 * consideration, either because is has a strictly higher ACK
		 * sequence number or because it is a SACK
		 */
		if ((ntohl(tcph_check->ack_seq) == ntohl(tcph->ack_seq) &&
		     !cake_tcph_is_sack(tcph)) ||
		    (int32_t)(ntohl(tcph_check->ack_seq) -
			      ntohl(tcph->ack_seq)) > 0)
			continue;

		/* At this point we have found an eligible pure ACK to drop; if
		 * we are in aggressive mode, we are done. Otherwise, keep
		 * searching unless this is the second eligible ACK we
		 * found.
		 *
		 * Since we want to drop ACK closest to the head of the queue,
		 * save the first eligible ACK we find, even if we need to loop
		 * again.
		 */
		if (!elig_ack) {
			elig_ack = skb_check;
			elig_ack_prev = skb_prev;
		}

		if (num_found++ > 0 || aggressive)
			goto found;
	}

	return NULL;

found:
	if (elig_ack_prev)
		elig_ack_prev->next = elig_ack->next;
	else
		flow->head = elig_ack->next;

	elig_ack->next = NULL;

	return elig_ack;
}

static cobalt_time_t cake_ewma(cobalt_time_t avg, cobalt_time_t sample,
			       u32 shift)
{
	avg -= avg >> shift;
	avg += sample >> shift;
	return avg;
}

static u32 cake_overhead(struct cake_sched_data *q, struct sk_buff *skb)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	u32 off = skb_network_offset(skb);
	u32 len = qdisc_pkt_len(skb);
	u16 segs = 1;

	if (unlikely(shinfo->gso_size)) {
		/* borrowed from qdisc_pkt_len_init() */
		unsigned int hdr_len;

		hdr_len = skb_transport_header(skb) - skb_mac_header(skb);

		/* + transport layer */
		if (likely(shinfo->gso_type & (SKB_GSO_TCPV4 |
					       SKB_GSO_TCPV6))) {
			const struct tcphdr *th;
			struct tcphdr _tcphdr;

			th = skb_header_pointer(skb, skb_transport_offset(skb),
						sizeof(_tcphdr), &_tcphdr);
			if (likely(th))
				hdr_len += __tcp_hdrlen(th);
		} else {
			struct udphdr _udphdr;

			if (skb_header_pointer(skb, skb_transport_offset(skb),
					       sizeof(_udphdr), &_udphdr))
				hdr_len += sizeof(struct udphdr);
		}

		if (unlikely(shinfo->gso_type & SKB_GSO_DODGY))
			segs = DIV_ROUND_UP(skb->len - hdr_len,
					    shinfo->gso_size);
		else
			segs = shinfo->gso_segs;

		/* The last segment may be shorter; we ignore this, which means
		 * that we will over-estimate the size of the whole GSO segment
		 * by the difference in size. This is conservative, so we live
		 * with that to avoid the complexity of dealing with it.
		 */
		len = shinfo->gso_size + hdr_len;
	}

	q->avg_netoff = cake_ewma(q->avg_netoff, off << 16, 8);

	if (q->rate_flags & CAKE_FLAG_OVERHEAD)
		len -= off;

	if (q->max_netlen < len)
		q->max_netlen = len;
	if (q->min_netlen > len)
		q->min_netlen = len;

	len += q->rate_overhead;

	if (len < q->rate_mpu)
		len = q->rate_mpu;

	if (q->atm_mode == CAKE_ATM_ATM) {
		len += 47;
		len /= 48;
		len *= 53;
	} else if (q->atm_mode == CAKE_ATM_PTM) {
		/* Add one byte per 64 bytes or part thereof.
		 * This is conservative and easier to calculate than the
		 * precise value.
		 */
		len += (len+63) / 64;
	}

	if (q->max_adjlen < len)
		q->max_adjlen = len;
	if (q->min_adjlen > len)
		q->min_adjlen = len;

	get_cobalt_cb(skb)->adjusted_len = len * segs;
	return len;
}

static void cake_heap_swap(struct cake_sched_data *q, u16 i, u16 j)
{
	struct cake_heap_entry ii = q->overflow_heap[i];
	struct cake_heap_entry jj = q->overflow_heap[j];

	q->overflow_heap[i] = jj;
	q->overflow_heap[j] = ii;

	q->tins[ii.t].overflow_idx[ii.b] = j;
	q->tins[jj.t].overflow_idx[jj.b] = i;
}

static u32 cake_heap_get_backlog(const struct cake_sched_data *q, u16 i)
{
	struct cake_heap_entry ii = q->overflow_heap[i];

	return q->tins[ii.t].backlogs[ii.b];
}

static void cake_heapify(struct cake_sched_data *q, u16 i)
{
	static const u32 a = CAKE_MAX_TINS * CAKE_QUEUES;
	u32 m = i;
	u32 mb = cake_heap_get_backlog(q, m);

	while (m < a) {
		u32 l = m + m + 1;
		u32 r = l + 1;

		if (l < a) {
			u32 lb = cake_heap_get_backlog(q, l);

			if (lb > mb) {
				m  = l;
				mb = lb;
			}
		}

		if (r < a) {
			u32 rb = cake_heap_get_backlog(q, r);

			if (rb > mb) {
				m  = r;
				mb = rb;
			}
		}

		if (m != i) {
			cake_heap_swap(q, i, m);
			i = m;
		} else {
			break;
		}
	}
}

static void cake_heapify_up(struct cake_sched_data *q, u16 i)
{
	while (i > 0 && i < CAKE_MAX_TINS * CAKE_QUEUES) {
		u16 p = (i - 1) >> 1;
		u32 ib = cake_heap_get_backlog(q, i);
		u32 pb = cake_heap_get_backlog(q, p);

		if (ib > pb) {
			cake_heap_swap(q, i, p);
			i = p;
		} else {
			break;
		}
	}
}

static int cake_advance_shaper(struct cake_sched_data *q,
			       struct cake_tin_data *b,
			       struct sk_buff *skb,
			       u64 now, bool drop)
{
	u32 len = get_cobalt_cb(skb)->adjusted_len;

	/* charge packet bandwidth to this tin
	 * and to the global shaper.
	 */
	if (q->rate_ns) {
		s64 tdiff1 = b->tin_time_next_packet - now;
		s64 tdiff2 = (len * (u64)b->tin_rate_ns) >> b->tin_rate_shft;
		s64 tdiff3 = (len * (u64)q->rate_ns) >> q->rate_shft;
		s64 tdiff4 = tdiff3 + (tdiff3 >> 1);

		if (tdiff1 < 0)
			b->tin_time_next_packet += tdiff2;
		else if (tdiff1 < tdiff2)
			b->tin_time_next_packet = now + tdiff2;

		q->time_next_packet += tdiff3;
		if (!drop)
			q->failsafe_next_packet += tdiff4;
	}
	return len;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
static unsigned int cake_drop(struct Qdisc *sch)
#else
static unsigned int cake_drop(struct Qdisc *sch, struct sk_buff **to_free)
#endif
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	u32 idx = 0, tin = 0, len;
	struct cake_tin_data *b;
	struct cake_flow *flow;
	struct cake_heap_entry qq;
	u64 now = cobalt_get_time();

	if (!q->overflow_timeout) {
		int i;
		/* Build fresh max-heap */
		for (i = CAKE_MAX_TINS * CAKE_QUEUES / 2; i >= 0; i--)
			cake_heapify(q, i);
	}
	q->overflow_timeout = 65535;

	/* select longest queue for pruning */
	qq  = q->overflow_heap[0];
	tin = qq.t;
	idx = qq.b;

	b = &q->tins[tin];
	flow = &b->flows[idx];
	skb = dequeue_head(flow);
	if (unlikely(!skb)) {
		/* heap has gone wrong, rebuild it next time */
		q->overflow_timeout = 0;
		return idx + (tin << 16);
	}

	if (cobalt_queue_full(&flow->cvars, &b->cparams, now))
		b->unresponsive_flow_count++;

	len = qdisc_pkt_len(skb);
	q->buffer_used      -= skb->truesize;
	b->backlogs[idx]    -= len;
	b->tin_backlog      -= len;
	sch->qstats.backlog -= len;
	qdisc_tree_reduce_backlog(sch, 1, len);

	b->tin_dropped++;
	sch->qstats.drops++;

	if (q->rate_flags & CAKE_FLAG_INGRESS)
		cake_advance_shaper(q, b, skb, now, true);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	kfree_skb(skb);
#else
	__qdisc_drop(skb, to_free);
#endif
	sch->q.qlen--;

	cake_heapify(q, 0);

	return idx + (tin << 16);
}

static void cake_wash_diffserv(struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ipv4_change_dsfield(ip_hdr(skb), INET_ECN_MASK, 0);
		break;
	case htons(ETH_P_IPV6):
		ipv6_change_dsfield(ipv6_hdr(skb), INET_ECN_MASK, 0);
		break;
	default:
		break;
	}
}

static u8 cake_handle_diffserv(struct sk_buff *skb, u16 wash)
{
	u8 dscp;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
		if (wash && dscp)
			ipv4_change_dsfield(ip_hdr(skb), INET_ECN_MASK, 0);
		return dscp;

	case htons(ETH_P_IPV6):
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;
		if (wash && dscp)
			ipv6_change_dsfield(ipv6_hdr(skb), INET_ECN_MASK, 0);
		return dscp;

	case htons(ETH_P_ARP):
		return 0x38;  /* CS7 - Net Control */

	default:
		/* If there is no Diffserv field, treat as best-effort */
		return 0;
	}
}

static void cake_reconfigure(struct Qdisc *sch);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
static s32 cake_enqueue(struct sk_buff *skb, struct Qdisc *sch)
#else
static s32 cake_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			struct sk_buff **to_free)
#endif
{
	struct cake_sched_data *q = qdisc_priv(sch);
	u32 idx, tin;
	struct cake_tin_data *b;
	struct cake_flow *flow;
	/* signed len to handle corner case filtered ACK larger than trigger */
	int len = qdisc_pkt_len(skb);
	u64 now = cobalt_get_time();
	struct sk_buff *ack = NULL;

	/* extract the Diffserv Precedence field, if it exists */
	/* and clear DSCP bits if washing */
	if (q->tin_mode != CAKE_DIFFSERV_BESTEFFORT) {
		tin = q->tin_index[cake_handle_diffserv(skb,
				q->rate_flags & CAKE_FLAG_WASH)];
		if (unlikely(tin >= q->tin_cnt))
			tin = 0;
	} else {
		tin = 0;
		if (q->rate_flags & CAKE_FLAG_WASH)
			cake_wash_diffserv(skb);
	}

	b = &q->tins[tin];

	/* choose flow to insert into */
	idx = cake_hash(b, skb, q->flow_mode);
	flow = &b->flows[idx];

	/* ensure shaper state isn't stale */
	if (!b->tin_backlog) {
		if (b->tin_time_next_packet < now)
			b->tin_time_next_packet = now;

		if (!sch->q.qlen) {
			if (q->time_next_packet < now) {
				q->failsafe_next_packet = now;
				q->time_next_packet = now;
			} else if (q->time_next_packet > now && q->failsafe_next_packet > now) {
				u64 next = min(q->time_next_packet,
					       q->failsafe_next_packet);
				sch->qstats.overlimits++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
				codel_watchdog_schedule_ns(&q->watchdog, next, true);
#else
				qdisc_watchdog_schedule_ns(&q->watchdog, next);
#endif
			}
		}
	}

	if (unlikely(len > b->max_skblen))
		b->max_skblen = len;

	/* Split GSO aggregates if they're likely to impair flow isolation */

	if (skb_is_gso(skb) && q->rate_flags & CAKE_FLAG_SPLIT_GSO) {
		struct sk_buff *segs, *nskb;
		netdev_features_t features = netif_skb_features(skb);
		unsigned int slen = 0;

		segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
		if (IS_ERR_OR_NULL(segs))
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
			return qdisc_reshape_fail(skb, sch);
#else
			return qdisc_drop(skb, sch, to_free);
#endif

		while (segs) {
			nskb = segs->next;
			segs->next = NULL;
			qdisc_skb_cb(segs)->pkt_len = segs->len;
			cobalt_set_enqueue_time(segs, now);
			get_cobalt_cb(segs)->adjusted_len = cake_overhead(q, segs);
			flow_queue_add(flow, segs);

			sch->q.qlen++;
			slen += segs->len;
			q->buffer_used += segs->truesize;
			b->packets++;
			segs = nskb;
		}
		/* stats */
		b->bytes	    += slen;
		b->backlogs[idx]    += slen;
		b->tin_backlog      += slen;
		sch->qstats.backlog += slen;
		q->avg_window_bytes += slen;

		qdisc_tree_reduce_backlog(sch, 1, len);
		consume_skb(skb);
	} else {
		/* not splitting */
		cobalt_set_enqueue_time(skb, now);
		get_cobalt_cb(skb)->adjusted_len = cake_overhead(q, skb);
		flow_queue_add(flow, skb);

		if (q->ack_filter)
			ack = cake_ack_filter(q, flow);

		if (ack) {
			b->ack_drops++;
			sch->qstats.drops++;
			b->bytes += qdisc_pkt_len(ack);
			len -= qdisc_pkt_len(ack);
			q->buffer_used += skb->truesize - ack->truesize;
			if (q->rate_flags & CAKE_FLAG_INGRESS)
				cake_advance_shaper(q, b, ack, now, true);

			qdisc_tree_reduce_backlog(sch, 1, qdisc_pkt_len(ack));
			consume_skb(ack);
		} else {
			sch->q.qlen++;
			q->buffer_used      += skb->truesize;
		}
		/* stats */
		b->packets++;
		b->bytes	    += len;
		b->backlogs[idx]    += len;
		b->tin_backlog      += len;
		sch->qstats.backlog += len;
		q->avg_window_bytes += len;
	}

	if (q->overflow_timeout)
		cake_heapify_up(q, b->overflow_idx[idx]);

	/* incoming bandwidth capacity estimate */
	if (q->rate_flags & CAKE_FLAG_AUTORATE_INGRESS) {
		u64 packet_interval = now - q->last_packet_time;

		if (packet_interval > NSEC_PER_SEC)
			packet_interval = NSEC_PER_SEC;

		/* filter out short-term bursts, eg. wifi aggregation */
		q->avg_packet_interval = cake_ewma(q->avg_packet_interval,
						   packet_interval,
			packet_interval > q->avg_packet_interval ? 2 : 8);

		q->last_packet_time = now;

		if (packet_interval > q->avg_packet_interval) {
			u64 window_interval = now - q->avg_window_begin;
			u64 b = q->avg_window_bytes * (u64)NSEC_PER_SEC;

			do_div(b, window_interval);
			q->avg_peak_bandwidth =
				cake_ewma(q->avg_peak_bandwidth, b,
					  b > q->avg_peak_bandwidth ? 2 : 8);
			q->avg_window_bytes = 0;
			q->avg_window_begin = now;

			if (now - q->last_reconfig_time > (NSEC_PER_SEC / 4)) {
				q->rate_bps = (q->avg_peak_bandwidth * 15) >> 4;
				cake_reconfigure(sch);
			}
		}
	} else {
		q->avg_window_bytes = 0;
		q->last_packet_time = now;
	}

	/* flowchain */
	if (!flow->set || flow->set == CAKE_SET_DECAYING) {
		struct cake_host *srchost = &b->hosts[flow->srchost];
		struct cake_host *dsthost = &b->hosts[flow->dsthost];
		u16 host_load = 1;

		if (!flow->set) {
			list_add_tail(&flow->flowchain, &b->new_flows);
		} else {
			b->decaying_flow_count--;
			list_move_tail(&flow->flowchain, &b->new_flows);
		}
		flow->set = CAKE_SET_SPARSE;
		b->sparse_flow_count++;

		if (cake_dsrc(q->flow_mode))
			host_load = max(host_load, srchost->srchost_refcnt);

		if (cake_ddst(q->flow_mode))
			host_load = max(host_load, dsthost->dsthost_refcnt);

		flow->deficit = (b->flow_quantum * quantum_div[host_load]) >> 16;
	} else if (flow->set == CAKE_SET_SPARSE_WAIT) {
		/* this flow was empty, accounted as a sparse flow, but actually
		 * in the bulk rotation.
		 */
		flow->set = CAKE_SET_BULK;
		b->sparse_flow_count--;
		b->bulk_flow_count++;
	}

	if (q->buffer_used > q->buffer_max_used)
		q->buffer_max_used = q->buffer_used;

	if (q->buffer_used > q->buffer_limit) {
		u32 dropped = 0;

		while (q->buffer_used > q->buffer_limit) {
			dropped++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
			cake_drop(sch);
#else
			cake_drop(sch, to_free);
#endif
		}
		b->drop_overlimit += dropped;
	}
	return NET_XMIT_SUCCESS;
}

static struct sk_buff *cake_dequeue_one(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_tin_data *b = &q->tins[q->cur_tin];
	struct cake_flow *flow = &b->flows[q->cur_flow];
	struct sk_buff *skb = NULL;
	u32 len;

	if (flow->head) {
		skb = dequeue_head(flow);
		len = qdisc_pkt_len(skb);
		b->backlogs[q->cur_flow] -= len;
		b->tin_backlog		 -= len;
		sch->qstats.backlog      -= len;
		q->buffer_used		 -= skb->truesize;
		sch->q.qlen--;

		if (q->overflow_timeout)
			cake_heapify(q, b->overflow_idx[q->cur_flow]);
	}
	return skb;
}

/* Discard leftover packets from a tin no longer in use. */
static void cake_clear_tin(struct Qdisc *sch, u16 tin)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	q->cur_tin = tin;
	for (q->cur_flow = 0; q->cur_flow < CAKE_QUEUES; q->cur_flow++)
		while (!!(skb = cake_dequeue_one(sch)))
			kfree_skb(skb);
}

static struct sk_buff *cake_dequeue(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct cake_tin_data *b = &q->tins[q->cur_tin];
	struct cake_flow *flow;
	struct cake_host *srchost, *dsthost;
	struct list_head *head;
	u32 len;
	u16 host_load;
	cobalt_time_t now = ktime_get_ns();
	cobalt_time_t delay;
	bool first_flow = true;

begin:
	if (!sch->q.qlen)
		return NULL;

	/* global hard shaper */
	if (q->time_next_packet > now && q->failsafe_next_packet > now) {
		u64 next = min(q->time_next_packet, q->failsafe_next_packet);
		sch->qstats.overlimits++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
		codel_watchdog_schedule_ns(&q->watchdog, next, true);
#else
		qdisc_watchdog_schedule_ns(&q->watchdog, next);
#endif
		return NULL;
	}

	/* Choose a class to work on. */
	if (!q->rate_ns) {
		/* In unlimited mode, can't rely on shaper timings, just balance
		 * with DRR
		 */
		while (b->tin_deficit < 0 ||
		       !(b->sparse_flow_count + b->bulk_flow_count)) {
			if (b->tin_deficit <= 0)
				b->tin_deficit += b->tin_quantum_band;

			q->cur_tin++;
			b++;
			if (q->cur_tin >= q->tin_cnt) {
				q->cur_tin = 0;
				b = q->tins;
			}
		}
	} else {
		/* In shaped mode, choose:
		 * - Highest-priority tin with queue and meeting schedule, or
		 * - The earliest-scheduled tin with queue.
		 */
		int tin, best_tin = 0;
		s64 best_time = 0xFFFFFFFFFFFFUL;

		for (tin = 0; tin < q->tin_cnt; tin++) {
			b = q->tins + tin;
			if ((b->sparse_flow_count + b->bulk_flow_count) > 0) {
				s64 tdiff = b->tin_time_next_packet - now;

				if (tdiff <= 0 || tdiff <= best_time) {
					best_time = tdiff;
					best_tin = tin;
				}
			}
		}

		q->cur_tin = best_tin;
		b = q->tins + best_tin;
	}

retry:
	/* service this class */
	head = &b->decaying_flows;
	if (!first_flow || list_empty(head)) {
		head = &b->new_flows;
		if (list_empty(head)) {
			head = &b->old_flows;
			if (unlikely(list_empty(head))) {
				head = &b->decaying_flows;
				if (unlikely(list_empty(head)))
					goto begin;
			}
		}
	}
	flow = list_first_entry(head, struct cake_flow, flowchain);
	q->cur_flow = flow - b->flows;
	first_flow = false;

	/* triple isolation (modified DRR++) */
	srchost = &b->hosts[flow->srchost];
	dsthost = &b->hosts[flow->dsthost];
	host_load = 1;

	if (cake_dsrc(q->flow_mode))
		host_load = max(host_load, srchost->srchost_refcnt);

	if (cake_ddst(q->flow_mode))
		host_load = max(host_load, dsthost->dsthost_refcnt);

	WARN_ON(host_load > CAKE_QUEUES);

	/* flow isolation (DRR++) */
	if (flow->deficit <= 0) {
		/* The shifted prandom_u32() is a way to apply dithering to
		 * avoid accumulating roundoff errors */
		flow->deficit += (b->flow_quantum * quantum_div[host_load] +
				  (prandom_u32() >> 16)) >> 16;
		list_move_tail(&flow->flowchain, &b->old_flows);

		/* Keep all flows with deficits out of the sparse and decaying
		 * rotations.  No non-empty flow can go into the decaying
		 * rotation, so they can't get deficits
		 */
		if (flow->set == CAKE_SET_SPARSE) {
			if (flow->head) {
				b->sparse_flow_count--;
				b->bulk_flow_count++;
				flow->set = CAKE_SET_BULK;
			} else {
				/* we've moved it to the bulk rotation for
				 * correct deficit accounting but we still want
				 * to count it as a sparse flow, not a bulk one.
				 */
				flow->set = CAKE_SET_SPARSE_WAIT;
			}
		}
		goto retry;
	}

	/* Retrieve a packet via the AQM */
	while (1) {
		skb = cake_dequeue_one(sch);
		if (!skb) {
			/* this queue was actually empty */
			if (cobalt_queue_empty(&flow->cvars, &b->cparams, now))
				b->unresponsive_flow_count--;

			if (flow->cvars.p_drop || flow->cvars.count ||
			    now < flow->cvars.drop_next) {
				/* keep in the flowchain until the state has
				 * decayed to rest
				 */
				list_move_tail(&flow->flowchain,
					       &b->decaying_flows);
				if (flow->set == CAKE_SET_BULK) {
					b->bulk_flow_count--;
					b->decaying_flow_count++;
				} else if (flow->set == CAKE_SET_SPARSE ||
					   flow->set == CAKE_SET_SPARSE_WAIT) {
					b->sparse_flow_count--;
					b->decaying_flow_count++;
				}
				flow->set = CAKE_SET_DECAYING;
			} else {
				/* remove empty queue from the flowchain */
				list_del_init(&flow->flowchain);
				if (flow->set == CAKE_SET_SPARSE ||
				    flow->set == CAKE_SET_SPARSE_WAIT)
					b->sparse_flow_count--;
				else if (flow->set == CAKE_SET_BULK)
					b->bulk_flow_count--;
				else
					b->decaying_flow_count--;

				flow->set = CAKE_SET_NONE;
				srchost->srchost_refcnt--;
				dsthost->dsthost_refcnt--;
			}
			goto begin;
		}

		/* Last packet in queue may be marked, shouldn't be dropped */
		if (!cobalt_should_drop(&flow->cvars, &b->cparams, now, skb,
			b->bulk_flow_count * !!(q->rate_flags &
						CAKE_FLAG_INGRESS)) ||
		    !flow->head)
			break;

		/* drop this packet, get another one */
		if (q->rate_flags & CAKE_FLAG_INGRESS) {
			len = cake_advance_shaper(q, b, skb,
						  now, true);
			flow->deficit -= len;
			b->tin_deficit -= len;
		}
		b->tin_dropped++;
		qdisc_tree_reduce_backlog(sch, 1, qdisc_pkt_len(skb));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
		qdisc_drop(skb, sch);
#else
		qdisc_qstats_drop(sch);
		kfree_skb(skb);
#endif
		if (q->rate_flags & CAKE_FLAG_INGRESS)
			goto retry;
	}

	b->tin_ecn_mark += !!flow->cvars.ecn_marked;
	qdisc_bstats_update(sch, skb);

	/* collect delay stats */
	delay = now - cobalt_get_enqueue_time(skb);
	b->avge_delay = cake_ewma(b->avge_delay, delay, 8);
	b->peak_delay = cake_ewma(b->peak_delay, delay,
				  delay > b->peak_delay ? 2 : 8);
	b->base_delay = cake_ewma(b->base_delay, delay,
				  delay < b->base_delay ? 2 : 8);

	len = cake_advance_shaper(q, b, skb, now, false);
	flow->deficit -= len;
	b->tin_deficit -= len;

	if (q->time_next_packet > now && sch->q.qlen) {
		u64 next = min(q->time_next_packet, q->failsafe_next_packet);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
		codel_watchdog_schedule_ns(&q->watchdog, next, true);
#else
		qdisc_watchdog_schedule_ns(&q->watchdog, next);
#endif
	} else if (!sch->q.qlen) {
		int i;

		for (i = 0; i < q->tin_cnt; i++) {
			if (q->tins[i].decaying_flow_count) {
				u64 next = now + q->tins[i].cparams.target;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
				codel_watchdog_schedule_ns(&q->watchdog, next,
							   true);
#else
				qdisc_watchdog_schedule_ns(&q->watchdog, next);
#endif
				break;
			}
		}
	}

	if (q->overflow_timeout)
		q->overflow_timeout--;

	return skb;
}

static void cake_reset(struct Qdisc *sch)
{
	u32 c;

	for (c = 0; c < CAKE_MAX_TINS; c++)
		cake_clear_tin(sch, c);
}

static const struct nla_policy cake_policy[TCA_CAKE_MAX + 1] = {
	[TCA_CAKE_BASE_RATE]     = { .type = NLA_U32 },
	[TCA_CAKE_DIFFSERV_MODE] = { .type = NLA_U32 },
	[TCA_CAKE_ATM]		 = { .type = NLA_U32 },
	[TCA_CAKE_FLOW_MODE]     = { .type = NLA_U32 },
	[TCA_CAKE_OVERHEAD]      = { .type = NLA_S32 },
	[TCA_CAKE_RTT]		 = { .type = NLA_U32 },
	[TCA_CAKE_TARGET]	 = { .type = NLA_U32 },
	[TCA_CAKE_AUTORATE]      = { .type = NLA_U32 },
	[TCA_CAKE_MEMORY]	 = { .type = NLA_U32 },
	[TCA_CAKE_NAT]		 = { .type = NLA_U32 },
	[TCA_CAKE_RAW]       = { .type = NLA_U32 },
	[TCA_CAKE_WASH]		 = { .type = NLA_U32 },
	[TCA_CAKE_MPU]		 = { .type = NLA_U32 },
	[TCA_CAKE_INGRESS]	 = { .type = NLA_U32 },
	[TCA_CAKE_ACK_FILTER]	 = { .type = NLA_U32 },
};

static void cake_set_rate(struct cake_tin_data *b, u64 rate, u32 mtu,
			  cobalt_time_t ns_target, cobalt_time_t rtt_est_ns)
{
	/* convert byte-rate into time-per-byte
	 * so it will always unwedge in reasonable time.
	 */
	static const u64 MIN_RATE = 64;
	u64 rate_ns = 0;
	u8  rate_shft = 0;
	cobalt_time_t byte_target_ns;
	u32 byte_target = mtu;

	b->flow_quantum = 1514;
	if (rate) {
		b->flow_quantum = max(min(rate >> 12, 1514ULL), 300ULL);
		rate_shft = 32;
		rate_ns = ((u64)NSEC_PER_SEC) << rate_shft;
		do_div(rate_ns, max(MIN_RATE, rate));
		while (!!(rate_ns >> 32)) {
			rate_ns >>= 1;
			rate_shft--;
		}
	} /* else unlimited, ie. zero delay */

	b->tin_rate_bps  = rate;
	b->tin_rate_ns   = rate_ns;
	b->tin_rate_shft = rate_shft;

	byte_target_ns = (byte_target * rate_ns) >> rate_shft;

	b->cparams.target = max((byte_target_ns*3)/2, ns_target);
	b->cparams.interval = max(rtt_est_ns +
				     b->cparams.target - ns_target,
				     b->cparams.target * 2);
	b->cparams.mtu_time = byte_target_ns;
	b->cparams.p_inc = 1 << 24; /* 1/256 */
	b->cparams.p_dec = 1 << 20; /* 1/4096 */
}

static int cake_config_besteffort(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_tin_data *b = &q->tins[0];
	u32 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));

	q->tin_cnt = 1;

	q->tin_index = besteffort;
	q->tin_order = normal_order;

	cake_set_rate(b, rate, mtu, US2TIME(q->target), US2TIME(q->interval));
	b->tin_quantum_band = 65535;
	b->tin_quantum_prio = 65535;

	return 0;
}

static int cake_config_precedence(struct Qdisc *sch)
{
	/* convert high-level (user visible) parameters into internal format */
	struct cake_sched_data *q = qdisc_priv(sch);
	u32 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum1 = 256;
	u32 quantum2 = 256;
	u32 i;

	q->tin_cnt = 8;
	q->tin_index = precedence;
	q->tin_order = normal_order;

	for (i = 0; i < q->tin_cnt; i++) {
		struct cake_tin_data *b = &q->tins[i];

		cake_set_rate(b, rate, mtu, US2TIME(q->target),
			      US2TIME(q->interval));

		b->tin_quantum_prio = max_t(u16, 1U, quantum1);
		b->tin_quantum_band = max_t(u16, 1U, quantum2);

		/* calculate next class's parameters */
		rate  *= 7;
		rate >>= 3;

		quantum1  *= 3;
		quantum1 >>= 1;

		quantum2  *= 7;
		quantum2 >>= 3;
	}

	return 0;
}

/*	List of known Diffserv codepoints:
 *
 *	Least Effort (CS1)
 *	Best Effort (CS0)
 *	Max Reliability & LLT "Lo" (TOS1)
 *	Max Throughput (TOS2)
 *	Min Delay (TOS4)
 *	LLT "La" (TOS5)
 *	Assured Forwarding 1 (AF1x) - x3
 *	Assured Forwarding 2 (AF2x) - x3
 *	Assured Forwarding 3 (AF3x) - x3
 *	Assured Forwarding 4 (AF4x) - x3
 *	Precedence Class 2 (CS2)
 *	Precedence Class 3 (CS3)
 *	Precedence Class 4 (CS4)
 *	Precedence Class 5 (CS5)
 *	Precedence Class 6 (CS6)
 *	Precedence Class 7 (CS7)
 *	Voice Admit (VA)
 *	Expedited Forwarding (EF)

 *	Total 25 codepoints.
 */

/*	List of traffic classes in RFC 4594:
 *		(roughly descending order of contended priority)
 *		(roughly ascending order of uncontended throughput)
 *
 *	Network Control (CS6,CS7)      - routing traffic
 *	Telephony (EF,VA)         - aka. VoIP streams
 *	Signalling (CS5)               - VoIP setup
 *	Multimedia Conferencing (AF4x) - aka. video calls
 *	Realtime Interactive (CS4)     - eg. games
 *	Multimedia Streaming (AF3x)    - eg. YouTube, NetFlix, Twitch
 *	Broadcast Video (CS3)
 *	Low Latency Data (AF2x,TOS4)      - eg. database
 *	Ops, Admin, Management (CS2,TOS1) - eg. ssh
 *	Standard Service (CS0 & unrecognised codepoints)
 *	High Throughput Data (AF1x,TOS2)  - eg. web traffic
 *	Low Priority Data (CS1)           - eg. BitTorrent

 *	Total 12 traffic classes.
 */

static int cake_config_diffserv8(struct Qdisc *sch)
{
/*	Pruned list of traffic classes for typical applications:
 *
 *		Network Control          (CS6, CS7)
 *		Minimum Latency          (EF, VA, CS5, CS4)
 *		Interactive Shell        (CS2, TOS1)
 *		Low Latency Transactions (AF2x, TOS4)
 *		Video Streaming          (AF4x, AF3x, CS3)
 *		Bog Standard             (CS0 etc.)
 *		High Throughput          (AF1x, TOS2)
 *		Background Traffic       (CS1)
 *
 *		Total 8 traffic classes.
 */

	struct cake_sched_data *q = qdisc_priv(sch);
	u32 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum1 = 256;
	u32 quantum2 = 256;
	u32 i;

	q->tin_cnt = 8;

	/* codepoint to class mapping */
	q->tin_index = diffserv8;
	q->tin_order = normal_order;

	/* class characteristics */
	for (i = 0; i < q->tin_cnt; i++) {
		struct cake_tin_data *b = &q->tins[i];

		cake_set_rate(b, rate, mtu, US2TIME(q->target),
			      US2TIME(q->interval));

		b->tin_quantum_prio = max_t(u16, 1U, quantum1);
		b->tin_quantum_band = max_t(u16, 1U, quantum2);

		/* calculate next class's parameters */
		rate  *= 7;
		rate >>= 3;

		quantum1  *= 3;
		quantum1 >>= 1;

		quantum2  *= 7;
		quantum2 >>= 3;
	}

	return 0;
}

static int cake_config_diffserv4(struct Qdisc *sch)
{
/*  Further pruned list of traffic classes for four-class system:
 *
 *	    Latency Sensitive  (CS7, CS6, EF, VA, CS5, CS4)
 *	    Streaming Media    (AF4x, AF3x, CS3, AF2x, TOS4, CS2, TOS1)
 *	    Best Effort        (CS0, AF1x, TOS2, and those not specified)
 *	    Background Traffic (CS1)
 *
 *		Total 4 traffic classes.
 */

	struct cake_sched_data *q = qdisc_priv(sch);
	u32 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum = 1024;

	q->tin_cnt = 4;

	/* codepoint to class mapping */
	q->tin_index = diffserv4;
	q->tin_order = bulk_order;

	/* class characteristics */
	cake_set_rate(&q->tins[0], rate, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[1], rate >> 4, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[2], rate >> 1, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[3], rate >> 2, mtu,
		      US2TIME(q->target), US2TIME(q->interval));

	/* priority weights */
	q->tins[0].tin_quantum_prio = quantum;
	q->tins[1].tin_quantum_prio = quantum >> 4;
	q->tins[2].tin_quantum_prio = quantum << 2;
	q->tins[3].tin_quantum_prio = quantum << 4;

	/* bandwidth-sharing weights */
	q->tins[0].tin_quantum_band = quantum;
	q->tins[1].tin_quantum_band = quantum >> 4;
	q->tins[2].tin_quantum_band = quantum >> 1;
	q->tins[3].tin_quantum_band = quantum >> 2;

	return 0;
}

static int cake_config_diffserv3(struct Qdisc *sch)
{
/*  Simplified Diffserv structure with 3 tins.
 *		Low Priority		(CS1)
 *		Best Effort
 *		Latency Sensitive	(TOS4, VA, EF, CS6, CS7)
 */
	struct cake_sched_data *q = qdisc_priv(sch);
	u32 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum = 1024;

	q->tin_cnt = 3;

	/* codepoint to class mapping */
	q->tin_index = diffserv3;
	q->tin_order = bulk_order;

	/* class characteristics */
	cake_set_rate(&q->tins[0], rate, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[1], rate >> 4, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[2], rate >> 2, mtu,
		      US2TIME(q->target), US2TIME(q->interval));

	/* priority weights */
	q->tins[0].tin_quantum_prio = quantum;
	q->tins[1].tin_quantum_prio = quantum >> 4;
	q->tins[2].tin_quantum_prio = quantum << 4;

	/* bandwidth-sharing weights */
	q->tins[0].tin_quantum_band = quantum;
	q->tins[1].tin_quantum_band = quantum >> 4;
	q->tins[2].tin_quantum_band = quantum >> 2;

	return 0;
}


static void cake_reconfigure(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int c, ft;

	switch (q->tin_mode) {
	case CAKE_DIFFSERV_BESTEFFORT:
		ft = cake_config_besteffort(sch);
		break;

	case CAKE_DIFFSERV_PRECEDENCE:
		ft = cake_config_precedence(sch);
		break;

	case CAKE_DIFFSERV_DIFFSERV8:
		ft = cake_config_diffserv8(sch);
		break;

	case CAKE_DIFFSERV_DIFFSERV4:
		ft = cake_config_diffserv4(sch);
		break;

	case CAKE_DIFFSERV_DIFFSERV3:
	default:
		ft = cake_config_diffserv3(sch);
		break;
	}

	for (c = q->tin_cnt; c < CAKE_MAX_TINS; c++) {
		cake_clear_tin(sch, c);
		q->tins[c].cparams.mtu_time = q->tins[ft].cparams.mtu_time;
	}

	q->rate_ns   = q->tins[ft].tin_rate_ns;
	q->rate_shft = q->tins[ft].tin_rate_shft;

	if (q->buffer_config_limit) {
		q->buffer_limit = q->buffer_config_limit;
	} else if (q->rate_bps) {
		u64 t = (u64)q->rate_bps * q->interval;

		do_div(t, USEC_PER_SEC / 4);
		q->buffer_limit = max_t(u32, t, 4U << 20);
	} else {
		q->buffer_limit = ~0;
	}

	sch->flags &= ~TCQ_F_CAN_BYPASS;

	q->buffer_limit = min(q->buffer_limit, max(sch->limit * psched_mtu(qdisc_dev(sch)), q->buffer_config_limit));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
static int cake_change(struct Qdisc *sch, struct nlattr *opt)
#else
static int cake_change(struct Qdisc *sch, struct nlattr *opt,
		struct netlink_ext_ack *extack)
#endif
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_CAKE_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, cake_policy);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, cake_policy, NULL);
#else
	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, cake_policy, extack);
#endif
	if (err < 0)
		return err;

	if (tb[TCA_CAKE_BASE_RATE])
		q->rate_bps = nla_get_u32(tb[TCA_CAKE_BASE_RATE]);

	if (tb[TCA_CAKE_DIFFSERV_MODE])
		q->tin_mode = nla_get_u32(tb[TCA_CAKE_DIFFSERV_MODE]);

	if (tb[TCA_CAKE_ATM])
		q->atm_mode = nla_get_u32(tb[TCA_CAKE_ATM]);

	if (tb[TCA_CAKE_WASH]) {
		if (!!nla_get_u32(tb[TCA_CAKE_WASH]))
			q->rate_flags |= CAKE_FLAG_WASH;
		else
			q->rate_flags &= ~CAKE_FLAG_WASH;
	}

	if (tb[TCA_CAKE_FLOW_MODE])
		q->flow_mode = nla_get_u32(tb[TCA_CAKE_FLOW_MODE]);

	if (tb[TCA_CAKE_NAT]) {
		q->flow_mode &= ~CAKE_FLOW_NAT_FLAG;
		q->flow_mode |= CAKE_FLOW_NAT_FLAG *
			!!nla_get_u32(tb[TCA_CAKE_NAT]);
	}

	if (tb[TCA_CAKE_OVERHEAD]) {
		q->rate_overhead = nla_get_s32(tb[TCA_CAKE_OVERHEAD]);
		q->rate_flags |= CAKE_FLAG_OVERHEAD;

		q->max_netlen = 0;
		q->max_adjlen = 0;
		q->min_netlen = ~0;
		q->min_adjlen = ~0;
	}

	if (tb[TCA_CAKE_RAW]) {
		q->rate_flags &= ~CAKE_FLAG_OVERHEAD;

		q->max_netlen = 0;
		q->max_adjlen = 0;
		q->min_netlen = ~0;
		q->min_adjlen = ~0;
	}

	if (tb[TCA_CAKE_MPU])
		q->rate_mpu = nla_get_u32(tb[TCA_CAKE_MPU]);

	if (tb[TCA_CAKE_RTT]) {
		q->interval = nla_get_u32(tb[TCA_CAKE_RTT]);

		if (!q->interval)
			q->interval = 1;
	}

	if (tb[TCA_CAKE_TARGET]) {
		q->target = nla_get_u32(tb[TCA_CAKE_TARGET]);

		if (!q->target)
			q->target = 1;
	}

	if (tb[TCA_CAKE_AUTORATE]) {
		if (!!nla_get_u32(tb[TCA_CAKE_AUTORATE]))
			q->rate_flags |= CAKE_FLAG_AUTORATE_INGRESS;
		else
			q->rate_flags &= ~CAKE_FLAG_AUTORATE_INGRESS;
	}

	if (tb[TCA_CAKE_INGRESS]) {
		if (!!nla_get_u32(tb[TCA_CAKE_INGRESS]))
			q->rate_flags |= CAKE_FLAG_INGRESS;
		else
			q->rate_flags &= ~CAKE_FLAG_INGRESS;
	}

	if (tb[TCA_CAKE_ACK_FILTER]) {
		q->ack_filter = nla_get_u32(tb[TCA_CAKE_ACK_FILTER]);
	}

	if (tb[TCA_CAKE_MEMORY])
		q->buffer_config_limit = nla_get_u32(tb[TCA_CAKE_MEMORY]);

	if (q->rate_bps && q->rate_bps <= CAKE_SPLIT_GSO_THRESHOLD)
		q->rate_flags |= CAKE_FLAG_SPLIT_GSO;
	else
		q->rate_flags &= ~CAKE_FLAG_SPLIT_GSO;

	if (q->tins) {
		sch_tree_lock(sch);
		cake_reconfigure(sch);
		sch_tree_unlock(sch);
	}

	return 0;
}

static void cake_free(void *addr)
{
	if (addr)
		kvfree(addr);
}

static void cake_destroy(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);

	if (q->tins)
		cake_free(q->tins);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
static int cake_init(struct Qdisc *sch, struct nlattr *opt)
#else
static int cake_init(struct Qdisc *sch, struct nlattr *opt,
		struct netlink_ext_ack *extack)
#endif
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int i, j;

	sch->limit = 10240;
	q->tin_mode = CAKE_DIFFSERV_DIFFSERV3;
	q->flow_mode  = CAKE_FLOW_TRIPLE;

	q->rate_bps = 0; /* unlimited by default */

	q->interval = 100000; /* 100ms default */
	q->target   =   5000; /* 5ms: codel RFC argues
			       * for 5 to 10% of interval
			       */

	q->cur_tin = 0;
	q->cur_flow  = 0;

	if (opt) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
		int err = cake_change(sch, opt);
#else
		int err = cake_change(sch, opt, extack);
#endif

		if (err)
			return err;
	}

	qdisc_watchdog_init(&q->watchdog, sch);

	quantum_div[0] = ~0;
	for (i = 1; i <= CAKE_QUEUES; i++)
		quantum_div[i] = 65535 / i;

	q->tins = kvzalloc(CAKE_MAX_TINS * sizeof(struct cake_tin_data),
			   GFP_KERNEL | __GFP_NOWARN);
	if (!q->tins)
		goto nomem;

	for (i = 0; i < CAKE_MAX_TINS; i++) {
		struct cake_tin_data *b = q->tins + i;

		b->perturb = prandom_u32();
		INIT_LIST_HEAD(&b->new_flows);
		INIT_LIST_HEAD(&b->old_flows);
		INIT_LIST_HEAD(&b->decaying_flows);
		b->sparse_flow_count = 0;
		b->bulk_flow_count = 0;
		b->decaying_flow_count = 0;

		for (j = 0; j < CAKE_QUEUES; j++) {
			struct cake_flow *flow = b->flows + j;
			u32 k = j * CAKE_MAX_TINS + i;

			INIT_LIST_HEAD(&flow->flowchain);
			cobalt_vars_init(&flow->cvars);

			q->overflow_heap[k].t = i;
			q->overflow_heap[k].b = j;
			b->overflow_idx[j] = k;
		}
	}

	cake_reconfigure(sch);
	q->avg_peak_bandwidth = q->rate_bps;
	q->min_netlen = ~0;
	q->min_adjlen = ~0;
	return 0;

nomem:
	cake_destroy(sch);
	return -ENOMEM;
}

static int cake_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_BASE_RATE, q->rate_bps))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_DIFFSERV_MODE, q->tin_mode))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_ATM, q->atm_mode))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_FLOW_MODE, q->flow_mode & ~CAKE_FLOW_NAT_FLAG))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_NAT, !!(q->flow_mode & CAKE_FLOW_NAT_FLAG)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_SPLIT_GSO,
			!!(q->rate_flags & CAKE_FLAG_SPLIT_GSO)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_WASH,
			!!(q->rate_flags & CAKE_FLAG_WASH)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_OVERHEAD, q->rate_overhead))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_MPU, q->rate_mpu))
		goto nla_put_failure;

	if (!(q->rate_flags & CAKE_FLAG_OVERHEAD))
		if (nla_put_u32(skb, TCA_CAKE_RAW, 0))
			goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_RTT, q->interval))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_TARGET, q->target))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_AUTORATE,
			!!(q->rate_flags & CAKE_FLAG_AUTORATE_INGRESS)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_INGRESS,
			!!(q->rate_flags & CAKE_FLAG_INGRESS)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_ACK_FILTER, q->ack_filter))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_MEMORY, q->buffer_config_limit))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int cake_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct nlattr *stats = nla_nest_start(d->skb, TCA_STATS_APP);
	struct nlattr *tstats, *ts;
	int i;

	if (!stats)
		return -1;

#define PUT_STAT_U32(attr, data) do {				       \
		if (nla_put_u32(d->skb, TCA_CAKE_STATS_ ## attr, data)) \
			goto nla_put_failure;			       \
	} while (0)

	PUT_STAT_U32(CAPACITY_ESTIMATE, q->avg_peak_bandwidth);
	PUT_STAT_U32(MEMORY_LIMIT, q->buffer_limit);
	PUT_STAT_U32(MEMORY_USED, q->buffer_max_used);
	PUT_STAT_U32(AVG_NETOFF, ((q->avg_netoff + 0x8000) >> 16));
	PUT_STAT_U32(MAX_NETLEN, q->max_netlen);
	PUT_STAT_U32(MAX_ADJLEN, q->max_adjlen);
	PUT_STAT_U32(MIN_NETLEN, q->min_netlen);
	PUT_STAT_U32(MIN_ADJLEN, q->min_adjlen);

#undef PUT_STAT_U32

	tstats = nla_nest_start(d->skb, TCA_CAKE_STATS_TIN_STATS);
	if (!tstats)
		goto nla_put_failure;

#define PUT_TSTAT_U32(attr, data) do {					\
		if (nla_put_u32(d->skb, TCA_CAKE_TIN_STATS_ ## attr, data)) \
			goto nla_put_failure;				\
	} while (0)
#define PUT_TSTAT_U64(attr, data) do {					\
		if (nla_put_u64_64bit(d->skb, TCA_CAKE_TIN_STATS_ ## attr, \
					data, TCA_CAKE_TIN_STATS_PAD))	\
			goto nla_put_failure;				\
	} while (0)

	for (i = 0; i < q->tin_cnt; i++) {
		struct cake_tin_data *b = &q->tins[q->tin_order[i]];

		ts = nla_nest_start(d->skb, i + 1);
		if (!ts)
			goto nla_put_failure;

		PUT_TSTAT_U32(THRESHOLD_RATE, b->tin_rate_bps);
		PUT_TSTAT_U32(TARGET_US, cobalt_time_to_us(b->cparams.target));
		PUT_TSTAT_U32(INTERVAL_US,
			      cobalt_time_to_us(b->cparams.interval));

		PUT_TSTAT_U32(SENT_PACKETS, b->packets);
		PUT_TSTAT_U64(SENT_BYTES64, b->bytes);
		PUT_TSTAT_U32(DROPPED_PACKETS, b->tin_dropped);
		PUT_TSTAT_U32(ECN_MARKED_PACKETS, b->tin_ecn_mark);
		PUT_TSTAT_U64(BACKLOG_BYTES64, b->tin_backlog);
		PUT_TSTAT_U32(ACKS_DROPPED_PACKETS, b->ack_drops);

		PUT_TSTAT_U32(PEAK_DELAY_US, cobalt_time_to_us(b->peak_delay));
		PUT_TSTAT_U32(AVG_DELAY_US, cobalt_time_to_us(b->avge_delay));
		PUT_TSTAT_U32(BASE_DELAY_US, cobalt_time_to_us(b->base_delay));

		PUT_TSTAT_U32(WAY_INDIRECT_HITS, b->way_hits);
		PUT_TSTAT_U32(WAY_MISSES, b->way_misses);
		PUT_TSTAT_U32(WAY_COLLISIONS, b->way_collisions);

		PUT_TSTAT_U32(SPARSE_FLOWS, b->sparse_flow_count +
					   b->decaying_flow_count);
		PUT_TSTAT_U32(BULK_FLOWS, b->bulk_flow_count);
		PUT_TSTAT_U32(UNRESPONSIVE_FLOWS, b->unresponsive_flow_count);
		PUT_TSTAT_U32(MAX_SKBLEN, b->max_skblen);

		PUT_TSTAT_U32(FLOW_QUANTUM, b->flow_quantum);
		nla_nest_end(d->skb, ts);
	}

#undef PUT_TSTAT_U32
#undef PUT_TSTAT_U64

	nla_nest_end(d->skb, tstats);
	return nla_nest_end(d->skb, stats);

nla_put_failure:
	nla_nest_cancel(d->skb, stats);
	return -1;
}

static struct Qdisc_ops cake_qdisc_ops __read_mostly = {
	.id		=	"cake",
	.priv_size	=	sizeof(struct cake_sched_data),
	.enqueue	=	cake_enqueue,
	.dequeue	=	cake_dequeue,
	.peek		=	qdisc_peek_dequeued,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	.drop		=	cake_drop,
#endif
	.init		=	cake_init,
	.reset		=	cake_reset,
	.destroy	=	cake_destroy,
	.change		=	cake_change,
	.dump		=	cake_dump,
	.dump_stats	=	cake_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init cake_module_init(void)
{
	return register_qdisc(&cake_qdisc_ops);
}

static void __exit cake_module_exit(void)
{
	unregister_qdisc(&cake_qdisc_ops);
}

module_init(cake_module_init)
module_exit(cake_module_exit)
MODULE_AUTHOR("Jonathan Morton");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("The Cake shaper. Version: " CAKE_VERSION);
