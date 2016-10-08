/*
 * COMMON Applications Kept Enhanced (CAKE) discipline - version 3
 *
 * Copyright (C) 2014-2015 Jonathan Morton <chromatix99@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions, and the following disclaimer,
 *	without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *	derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
#include <net/flow_keys.h>
#else
#include <net/flow_dissector.h>
#endif
#include "cobalt.c"

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack.h>
#endif

#if (KERNEL_VERSION(4,4,11) > LINUX_VERSION_CODE) || ((KERNEL_VERSION(4,5,0) <= LINUX_VERSION_CODE) && (KERNEL_VERSION(4,5,5) > LINUX_VERSION_CODE))
#define qdisc_tree_reduce_backlog(_a,_b,_c) qdisc_tree_decrease_qlen(_a,_b)
#endif

/* The CAKE Principles:
 *				 (or, how to have your cake and eat it too)
 *
 * This is a combination of several shaping, AQM and FQ
 * techniques into one easy-to-use package:
 *
 * - An overall bandwidth shaper, to move the bottleneck away
 *   from dumb CPE equipment and bloated MACs.  This operates
 *   in deficit mode (as in sch_fq), eliminating the need for
 *   any sort of burst parameter (eg. token bucket depth).
 *   Burst support is limited to that necessary to overcome
 *   scheduling latency.
 *
 * - A Diffserv-aware priority queue, giving more priority to
 *   certain classes, up to a specified fraction of bandwidth.
 *   Above that bandwidth threshold, the priority is reduced to
 *   avoid starving other tins.
 *
 * - Each priority tin has a separate Flow Queue system, to
 *   isolate traffic flows from each other.  This prevents a
 *   burst on one flow from increasing the delay to another.
 *   Flows are distributed to queues using a set-associative
 *   hash function.
 *
 * - Each queue is actively managed by Codel.  This serves
 *   flows fairly, and signals congestion early via ECN
 *   (if available) and/or packet drops, to keep latency low.
 *   The codel parameters are auto-tuned based on the bandwidth
 *   setting, as is necessary at low bandwidths.
 *
 * The configuration parameters are kept deliberately simple
 * for ease of use.  Everything has sane defaults.  Complete
 * generality of configuration is *not* a goal.
 *
 * The priority queue operates according to a weighted DRR
 * scheme, combined with a bandwidth tracker which reuses the
 * shaper logic to detect which side of the bandwidth sharing
 * threshold the tin is operating.  This determines whether
 * a priority-based weight (high) or a bandwidth-based weight
 * (low) is used for that tin in the current pass.
 *
 * This qdisc incorporates much of Eric Dumazet's fq_codel code, which
 * he kindly granted us permission to use, which we customised for use as an
 * integrated subordinate.  See sch_fq_codel.c for details of
 * operation.
 */

#define CAKE_SET_WAYS (8)
#define CAKE_MAX_TINS (8)
#define CAKE_QUEUES (1024)

#ifndef CAKE_VERSION
#define CAKE_VERSION "unknown"
#endif
static char *cake_version __attribute__((used)) = "Cake version: "
		CAKE_VERSION;

enum {
	CAKE_SET_NONE = 0,
	CAKE_SET_SPARSE,
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
	s16 srchost_deficit;
	u16 srchost_refcnt;
	u32 dsthost_tag;
	s16 dsthost_deficit;
	u16 dsthost_refcnt;
};

struct cake_heap_entry {
	u16 t:3, b:10;
};

struct cake_tin_data {
	struct cake_flow flows[CAKE_QUEUES];
	u32	backlogs[CAKE_QUEUES];
	u32 tags[CAKE_QUEUES];	/* for set association */
	u16 overflow_idx[CAKE_QUEUES];
	struct cake_host hosts[CAKE_QUEUES]; /* for triple isolation */
	u32	perturbation;
	u16	flow_quantum;
	u16	host_quantum;

	struct cobalt_params cparams;
	u32	drop_overlimit;
	u16	bulk_flow_count;
	u16	sparse_flow_count;
	u16	decaying_flow_count;
	u16	unresponsive_flow_count;

	u16	max_skblen;

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
	u8		flow_mode;

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u16		rate_shft;
	u64		time_next_packet;
	u32		rate_ns;
	u32		rate_bps;
	u16		rate_flags;
	s16		rate_overhead;
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
	u8		tin_index[64];

	/* bandwidth capacity estimate */
	u64		last_packet_time;
	u64		avg_packet_interval;
	u64		avg_window_begin;
	u32		avg_window_bytes;
	u32		avg_peak_bandwidth;
	u64		last_reconfig_time;
};

enum {
	CAKE_MODE_BESTEFFORT = 1,
	CAKE_MODE_PRECEDENCE,
	CAKE_MODE_DIFFSERV8,
	CAKE_MODE_DIFFSERV4,
	CAKE_MODE_LLT,
	CAKE_MODE_MAX
};

enum {
	CAKE_FLAG_ATM = 0x0001,
	CAKE_FLAG_PTM = 0x0002,
	CAKE_FLAG_AUTORATE_INGRESS = 0x0010,
};

enum {
	CAKE_FLOW_NONE = 0,
	CAKE_FLOW_SRC_IP,
	CAKE_FLOW_DST_IP,
	CAKE_FLOW_HOSTS,    /* = CAKE_FLOW_SRC_IP | CAKE_FLOW_DST_IP */
	CAKE_FLOW_FLOWS,
	CAKE_FLOW_DUAL_SRC, /* = CAKE_FLOW_SRC_IP | CAKE_FLOW_FLOWS */
	CAKE_FLOW_DUAL_DST, /* = CAKE_FLOW_DST_IP | CAKE_FLOW_FLOWS */
	CAKE_FLOW_TRIPLE,   /* = CAKE_FLOW_HOSTS  | CAKE_FLOW_FLOWS */
	CAKE_FLOW_MAX,
	CAKE_FLOW_NAT_FLAG = 64
};

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)

#if KERNEL_VERSION(4, 0, 0) > LINUX_VERSION_CODE
#define tc_skb_protocol(_skb) \
(vlan_tx_tag_present(_skb) ? _skb->vlan_proto : _skb->protocol)
#endif

static inline void cake_update_flowkeys(struct flow_keys *keys, const struct sk_buff *skb)
{
	enum ip_conntrack_info ctinfo;
	bool reverse = false;

	struct nf_conn *ct;
	const struct nf_conntrack_tuple *tuple;

	if (tc_skb_protocol(skb) != htons(ETH_P_IP))
		return;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct != NULL) {
		tuple = nf_ct_tuple(ct, CTINFO2DIR(ctinfo));
	} else {
		const struct nf_conntrack_tuple_hash *hash;
		struct nf_conntrack_tuple srctuple;

#if KERNEL_VERSION(4, 4, 0) > LINUX_VERSION_CODE
		if (! nf_ct_get_tuplepr(skb, skb_network_offset(skb),
					NFPROTO_IPV4, &srctuple))
#else
		if (! nf_ct_get_tuplepr(skb, skb_network_offset(skb),
					NFPROTO_IPV4, dev_net(skb->dev), &srctuple))
#endif
			return;

#if KERNEL_VERSION(4, 3, 0) > LINUX_VERSION_CODE
		hash = nf_conntrack_find_get(dev_net(skb->dev),
				NF_CT_DEFAULT_ZONE, &srctuple);
#else
		hash = nf_conntrack_find_get(dev_net(skb->dev),
				&nf_ct_zone_dflt, &srctuple);
#endif
		if (hash == NULL)
			return;

		reverse = true;
		ct = nf_ct_tuplehash_to_ctrack(hash);
		tuple = nf_ct_tuple(ct, !hash->tuple.dst.dir);
	}

#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	keys->src = ( reverse ? tuple->dst.u3.ip : tuple->src.u3.ip );
	keys->dst = ( reverse ? tuple->src.u3.ip : tuple->dst.u3.ip );
#else
	keys->addrs.v4addrs.src = ( reverse ? tuple->dst.u3.ip : tuple->src.u3.ip );
	keys->addrs.v4addrs.dst = ( reverse ? tuple->src.u3.ip : tuple->dst.u3.ip );
#endif

#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	if (keys->ports) {
		keys->port16[0] = ( reverse ? tuple->dst.u.all : tuple->src.u.all );
		keys->port16[1] = ( reverse ? tuple->src.u.all : tuple->dst.u.all );
	}
#else
	if (keys->ports.ports) {
		keys->ports.src = ( reverse ? tuple->dst.u.all : tuple->src.u.all );
		keys->ports.dst = ( reverse ? tuple->src.u.all : tuple->dst.u.all );
	}
#endif
	if (reverse)
		nf_ct_put(ct);
	return;
}
#else
static inline void cake_update_flowkeys(struct flow_keys *keys, const struct sk_buff *skb)
{
	/* There is nothing we can do here without CONNTRACK */
	return;
}
#endif

static inline u32
cake_hash(struct cake_tin_data *q, const struct sk_buff *skb, int flow_mode)
{
#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	struct flow_keys keys;
#else
	struct flow_keys keys, host_keys;
#endif
	u32 flow_hash=0, srchost_hash, dsthost_hash;
	u16 reduced_hash, srchost_idx, dsthost_idx;

	if (unlikely(flow_mode == CAKE_FLOW_NONE))
		return 0;

#if KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE
	skb_flow_dissect(skb, &keys);

	if(flow_mode & CAKE_FLOW_NAT_FLAG)
		cake_update_flowkeys(&keys, skb);

	srchost_hash = jhash_1word(
		(__force u32) keys.src, q->perturbation);

	dsthost_hash = jhash_1word(
		(__force u32) keys.dst, q->perturbation);

	if (flow_mode & CAKE_FLOW_FLOWS) {
		flow_hash = jhash_3words(
			(__force u32)keys.dst,
			(__force u32)keys.src ^ keys.ip_proto,
			(__force u32)keys.ports, q->perturbation);
	}
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

	if(flow_mode & CAKE_FLOW_NAT_FLAG)
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
		dsthost_hash = srchost_hash = 0;
	};

	/* This *must* be after the above switch, since as a
	 * side-effect it sorts the src and dst addresses.
	 */
	if (flow_mode & CAKE_FLOW_FLOWS)
		flow_hash = flow_hash_from_keys(&keys);
#endif

	if (!(flow_mode & CAKE_FLOW_FLOWS)) {
		if(flow_mode & CAKE_FLOW_SRC_IP)
			flow_hash ^= srchost_hash;

		if(flow_mode & CAKE_FLOW_DST_IP)
			flow_hash ^= dsthost_hash;
	}

	reduced_hash = flow_hash    % CAKE_QUEUES;
	srchost_idx  = srchost_hash % CAKE_QUEUES;
	dsthost_idx  = dsthost_hash % CAKE_QUEUES;

	/* set-associative hashing */
	/* fast path if no hash collision (direct lookup succeeds) */
	if (likely(q->tags[reduced_hash] == flow_hash)) {
		q->way_directs++;
	} else {
		u32 inner_hash = reduced_hash % CAKE_SET_WAYS;
		u32 outer_hash = reduced_hash - inner_hash;
		u32 i, k;
		bool need_allocate_src = false;
		bool need_allocate_dst = false;

		/* check if any active queue in the set is reserved for
		 * this flow.
		 */
		for (i = 0, k = inner_hash; i < CAKE_SET_WAYS;
		     i++, k = (k + 1) % CAKE_SET_WAYS) {
			if (q->tags[outer_hash + k] == flow_hash) {
				q->way_hits++;
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
				need_allocate_src = true;
				need_allocate_dst = true;
				goto found;
			}
		}

		/* With no empty queues, default to the original
		 * queue, accept the collision, update the host tags.
		 */
		q->way_collisions++;
		q->hosts[q->flows[reduced_hash].srchost].srchost_refcnt--;
		q->hosts[q->flows[reduced_hash].dsthost].dsthost_refcnt--;
		need_allocate_src = true;
		need_allocate_dst = true;

found:
		/* reserve queue for future packets in same flow */
		reduced_hash = outer_hash + k;
		q->tags[reduced_hash] = flow_hash;

		if(need_allocate_src) {
			inner_hash = srchost_idx % CAKE_SET_WAYS;
			outer_hash = srchost_idx - inner_hash;
			for(i = 0, k = inner_hash; i < CAKE_SET_WAYS;
				i++, k = (k + 1) % CAKE_SET_WAYS) {
				if(q->hosts[outer_hash + k].srchost_tag == srchost_hash)
					goto found_src;
			}
			for(i = 0; i < CAKE_SET_WAYS;
				i++, k = (k + 1) % CAKE_SET_WAYS) {
				if(!q->hosts[outer_hash + k].srchost_refcnt)
					break;
			}
			q->hosts[outer_hash + k].srchost_tag = srchost_hash;
found_src:
			srchost_idx = outer_hash + k;
			q->hosts[srchost_idx].srchost_refcnt++;
			q->flows[reduced_hash].srchost = srchost_idx;
		}

		if(need_allocate_dst) {
			inner_hash = dsthost_idx % CAKE_SET_WAYS;
			outer_hash = dsthost_idx - inner_hash;
			for(i = 0, k = inner_hash; i < CAKE_SET_WAYS;
				i++, k = (k + 1) % CAKE_SET_WAYS) {
				if(q->hosts[outer_hash + k].dsthost_tag == dsthost_hash)
					goto found_dst;
			}
			for(i = 0; i < CAKE_SET_WAYS;
				i++, k = (k + 1) % CAKE_SET_WAYS) {
				if(!q->hosts[outer_hash + k].dsthost_refcnt)
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

static inline struct sk_buff *dequeue_head(struct cake_flow *flow)
{
	struct sk_buff *skb = flow->head;

	if(skb) {
		flow->head = skb->next;
		skb->next = NULL;
	}

	return skb;
}

/* add skb to flow queue (tail add) */

static inline void
flow_queue_add(struct cake_flow *flow, struct sk_buff *skb)
{
	if (!flow->head)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static inline u32 cake_overhead(struct cake_sched_data *q, u32 in)
{
	u32 out = in + q->rate_overhead;

	if (q->rate_flags & CAKE_FLAG_ATM) {
		out += 47;
		out /= 48;
		out *= 53;
	} else if(q->rate_flags & CAKE_FLAG_PTM) {
		// the following adds one byte per 64 bytes or part thereof
		// this is conservative and easier to calculate than the precise value
		out += (out / 64) + !!(out % 64);
	}

	return out;
}

static inline cobalt_time_t cake_ewma(cobalt_time_t avg, cobalt_time_t sample,
				     u32 shift)
{
	avg -= avg >> shift;
	avg += sample >> shift;
	return avg;
}

static inline void cake_heap_swap(struct cake_sched_data *q, u16 i, u16 j)
{
	struct cake_heap_entry ii = q->overflow_heap[i];
	struct cake_heap_entry jj = q->overflow_heap[j];

	BUG_ON(q->tins[ii.t].overflow_idx[ii.b] != i);
	BUG_ON(q->tins[jj.t].overflow_idx[jj.b] != j);

	q->overflow_heap[i] = jj;
	q->overflow_heap[j] = ii;

	q->tins[ii.t].overflow_idx[ii.b] = j;
	q->tins[jj.t].overflow_idx[jj.b] = i;
}

static inline u32 cake_heap_get_backlog(const struct cake_sched_data *q, u16 i)
{
	struct cake_heap_entry ii = q->overflow_heap[i];

	return q->tins[ii.t].backlogs[ii.b];
}

static void cake_heapify(struct cake_sched_data *q, u16 i)
{
	static const u32 a = CAKE_MAX_TINS * CAKE_QUEUES;
	u32 m = i;
	u32 mb = cake_heap_get_backlog(q,m);

	while(m < a) {
		u32 l = m+m+1;
		u32 r = l+1;

		if(l < a) {
			u32 lb = cake_heap_get_backlog(q,l);

			if(lb > mb) {
				m  = l;
				mb = lb;
			}
		}

		if(r < a) {
			u32 rb = cake_heap_get_backlog(q,r);

			if(rb > mb) {
				m  = r;
				mb = rb;
			}
		}

		if(m != i) {
			cake_heap_swap(q,i,m);
			i = m;
		} else {
			break;
		}
	}
}

static void cake_heapify_up(struct cake_sched_data *q, u16 i)
{
	while(i > 0 && i < CAKE_MAX_TINS * CAKE_QUEUES) {
		u16 p = (i-1) >> 1;
		u32 ib = cake_heap_get_backlog(q,i);
		u32 pb = cake_heap_get_backlog(q,p);

		if(ib > pb) {
			cake_heap_swap(q,i,p);
			i = p;
		} else {
			break;
		}
	}
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

	if(!q->overflow_timeout) {
		int i;
		/* Build fresh max-heap */
		for(i = CAKE_MAX_TINS * CAKE_QUEUES / 2; i >= 0; i--)
			cake_heapify(q,i);
	}
	q->overflow_timeout = 65535;

	/* select longest queue for pruning */
	qq  = q->overflow_heap[0];
	tin = qq.t;
	idx = qq.b;

	b = &q->tins[tin];
	flow = &b->flows[idx];
	skb = dequeue_head(flow);
	if(unlikely(!skb)) {
		/* heap has gone wrong, rebuild it next time */
		q->overflow_timeout = 0;
		return idx + (tin << 16);
	}

	if(cobalt_queue_full(&flow->cvars, &b->cparams, cobalt_get_time()))
		b->unresponsive_flow_count++;

	len = qdisc_pkt_len(skb);
	q->buffer_used      -= skb->truesize;
	b->backlogs[idx]    -= len;
	b->tin_backlog      -= len;
	sch->qstats.backlog -= len;
	qdisc_tree_reduce_backlog(sch, 1, len);

	b->tin_dropped++;
	sch->qstats.drops++;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	kfree_skb(skb);
#else
	__qdisc_drop(skb, to_free);
#endif
	sch->q.qlen--;

	cake_heapify(q,0);

	return idx + (tin << 16);
}


static inline u32 cake_get_diffserv(struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		return ipv4_get_dsfield(ip_hdr(skb)) >> 2;

	case htons(ETH_P_IPV6):
		return ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	default:
		/* If there is no Diffserv field, treat as bulk */
		return 0;
	};
}

static void cake_reconfigure(struct Qdisc *sch);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
static s32 cake_enqueue(struct sk_buff *skb, struct Qdisc *sch)
#else
static s32 cake_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
#endif
{
	struct cake_sched_data *q = qdisc_priv(sch);
	u32 idx, tin;
	struct cake_tin_data *b;
	struct cake_flow *flow;
	u32 len = qdisc_pkt_len(skb);
	u64 now = cobalt_get_time();

	/* extract the Diffserv Precedence field, if it exists */
	tin = q->tin_index[cake_get_diffserv(skb)];
	if (unlikely(tin >= q->tin_cnt))
		tin = 0;

	b = &q->tins[tin];

	/* choose flow to insert into */
	idx = cake_hash(b, skb, q->flow_mode);
	flow = &b->flows[idx];

	/* ensure shaper state isn't stale */
	if (!b->tin_backlog) {
		if (b->tin_time_next_packet < now)
			b->tin_time_next_packet = now;

		if (!sch->q.qlen)
			if (q->time_next_packet < now)
				q->time_next_packet = now;
	}

	if (unlikely(len > b->max_skblen))
		b->max_skblen = len;

	/* Split GSO aggregates if they're likely to impair flow isolation
	 * or if we need to know individual packet sizes for framing overhead.
	 */

	if (skb_is_gso(skb)) {
		struct sk_buff *segs, *nskb;
		netdev_features_t features = netif_skb_features(skb);
		u32 slen = 0;
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
			flow_queue_add(flow, segs);
			/* stats */
			sch->q.qlen++;
			b->packets++;
			slen += segs->len;
			q->buffer_used += segs->truesize;
			segs = nskb;
		}

		b->bytes            += slen;
		b->backlogs[idx]    += slen;
		b->tin_backlog      += slen;
		sch->qstats.backlog += slen;
		q->avg_window_bytes += slen;

		qdisc_tree_reduce_backlog(sch, 1, len);
		consume_skb(skb);
	} else {
		/* not splitting */
		cobalt_set_enqueue_time(skb, now);
		flow_queue_add(flow, skb);

		/* stats */
		sch->q.qlen++;
		b->packets++;
		b->bytes            += len;
		b->backlogs[idx]    += len;
		b->tin_backlog      += len;
		sch->qstats.backlog += len;
		q->avg_window_bytes += len;
		q->buffer_used      += skb->truesize;
	}

	if(q->overflow_timeout)
		cake_heapify_up(q, b->overflow_idx[idx]);

	/* incoming bandwidth capacity estimate */
	if (q->rate_flags & CAKE_FLAG_AUTORATE_INGRESS)
	{
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
			u64 b = q->avg_window_bytes * (u64) NSEC_PER_SEC;

			do_div(b, window_interval);
			q->avg_peak_bandwidth =
				cake_ewma(q->avg_peak_bandwidth, b,
					b > q->avg_peak_bandwidth ? 2 : 8);
			q->avg_window_bytes = 0;
			q->avg_window_begin = now;

			if (q->rate_flags & CAKE_FLAG_AUTORATE_INGRESS &&
				now - q->last_reconfig_time >
				(NSEC_PER_SEC / 4)) {
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
		if(!flow->set) {
			list_add_tail(&flow->flowchain, &b->new_flows);
		} else {
			b->decaying_flow_count--;
			list_move_tail(&flow->flowchain, &b->new_flows);
		}
		flow->set = CAKE_SET_SPARSE;
		b->sparse_flow_count++;
		flow->deficit = b->flow_quantum;
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

	/* WARN_ON(flow != container_of(vars, struct cake_flow, cvars)); */

	if (flow->head) {
		skb = dequeue_head(flow);
		len = qdisc_pkt_len(skb);
		b->backlogs[q->cur_flow] -= len;
		b->tin_backlog           -= len;
		sch->qstats.backlog      -= len;
		q->buffer_used           -= skb->truesize;
		sch->q.qlen--;

		if(q->overflow_timeout)
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
	struct list_head *head;
	u16 deferred_hosts;
	u32 len;
	cobalt_time_t now = ktime_get_ns();
	cobalt_time_t delay;
	bool src_blocked = false, dst_blocked = false, first_flow = true;

begin:
	if (!sch->q.qlen)
		return NULL;

	/* global hard shaper */
	if (q->time_next_packet > now) {
		sch->qstats.overlimits++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
		codel_watchdog_schedule_ns(&q->watchdog, q->time_next_packet,
					   true);
#else
		qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
#endif
		return NULL;
	}

	/* Choose a class to work on. */
	while (b->tin_deficit < 0 || !(b->sparse_flow_count + b->bulk_flow_count)) {
		/* this is the priority soft-shaper magic */
		if (b->tin_deficit <= 0) {
			b->tin_deficit +=
				b->tin_time_next_packet > now ?
					b->tin_quantum_band :
					b->tin_quantum_prio;
		}

		q->cur_tin++;
		b++;
		if (q->cur_tin >= q->tin_cnt) {
			q->cur_tin = 0;
			b = q->tins;
		}
	}

	deferred_hosts = 0;

retry:
	/* service this class */
	if(deferred_hosts >= b->sparse_flow_count + b->bulk_flow_count) {
		/* looks like all hosts are exhausted; refresh them */
		u32 j;

		for(j=0; j < CAKE_QUEUES; j++) {
			if(b->hosts[j].srchost_deficit < 0)
				b->hosts[j].srchost_deficit += b->host_quantum;
			if(b->hosts[j].dsthost_deficit < 0)
				b->hosts[j].dsthost_deficit += b->host_quantum;
		}
		deferred_hosts = 0;
	}

	head = &b->decaying_flows;
	if (!first_flow || list_empty(head)) {
		head = &b->new_flows;
		if (list_empty(head) || deferred_hosts >= b->sparse_flow_count) {
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

	/* triple isolation (modified dual DRR) */
	src_blocked = (q->flow_mode & CAKE_FLOW_DUAL_SRC) == CAKE_FLOW_DUAL_SRC &&
			b->hosts[flow->srchost].srchost_deficit < 0;

	dst_blocked = (q->flow_mode & CAKE_FLOW_DUAL_DST) == CAKE_FLOW_DUAL_DST &&
			b->hosts[flow->dsthost].dsthost_deficit < 0;

	if (src_blocked || dst_blocked) {
		/* this host is exhausted, so defer the flow */
		list_move_tail(&flow->flowchain, head);
		deferred_hosts++;
		goto retry;
	}

	/* flow isolation (DRR++) */
	if (flow->deficit <= 0) {
		flow->deficit += b->flow_quantum;
		if(flow->head) {
			list_move_tail(&flow->flowchain, &b->old_flows);
			flow->set = CAKE_SET_BULK;
			if (head == &b->new_flows) {
				b->sparse_flow_count--;
				b->bulk_flow_count++;
			} else if(head == &b->decaying_flows) {
				b->decaying_flow_count--;
				b->bulk_flow_count++;
			}
		} else {
			list_move_tail(&flow->flowchain, &b->decaying_flows);
			flow->set = CAKE_SET_DECAYING;
			if (head == &b->new_flows) {
				b->sparse_flow_count--;
				b->decaying_flow_count++;
			} else if(head == &b->old_flows) {
				b->bulk_flow_count--;
				b->decaying_flow_count++;
			}
		}
		deferred_hosts = 0;
		goto retry;
	}

	/* Retrieve a packet via the AQM */
	while(1) {
		skb = cake_dequeue_one(sch);
		if(!skb) {
			/* this queue was actually empty */
			if(cobalt_queue_empty(&flow->cvars, &b->cparams, now))
				b->unresponsive_flow_count--;

			if (flow->cvars.p_drop || flow->cvars.count) {
				/* keep in the flowchain until the state has decayed to rest */
				list_move_tail(&flow->flowchain, &b->decaying_flows);
				flow->set = CAKE_SET_DECAYING;
				if (head == &b->new_flows) {
					b->sparse_flow_count--;
					b->decaying_flow_count++;
				} else if(head == &b->old_flows) {
					b->bulk_flow_count--;
					b->decaying_flow_count++;
				}
			} else {
				/* remove empty queue from the flowchain */
				list_del_init(&flow->flowchain);
				flow->set = CAKE_SET_NONE;
				if (head == &b->new_flows)
					b->sparse_flow_count--;
				else if(head == &b->old_flows)
					b->bulk_flow_count--;
				else
					b->decaying_flow_count--;
				b->hosts[flow->srchost].srchost_refcnt--;
				b->hosts[flow->dsthost].dsthost_refcnt--;
			}
			goto begin;
		}

		/* Last packet in queue may be marked, shouldn't be dropped */
		if(!cobalt_should_drop(&flow->cvars, &b->cparams, now, skb) || !flow->head)
			break;

		/* drop this packet, get another one */
		b->tin_dropped++;
		qdisc_tree_reduce_backlog(sch, 1, qdisc_pkt_len(skb));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
		qdisc_drop(skb, sch);
#else
		__qdisc_drop(skb, NULL);
#endif
	}

	b->tin_ecn_mark += !!flow->cvars.ecn_marked;
	qdisc_bstats_update(sch, skb);

	len = cake_overhead(q, qdisc_pkt_len(skb));
	flow->deficit -= len;
	b->tin_deficit -= len;
	b->hosts[flow->srchost].srchost_deficit -= len;
	b->hosts[flow->dsthost].dsthost_deficit -= len;

	/* collect delay stats */
	delay = now - cobalt_get_enqueue_time(skb);
	b->avge_delay = cake_ewma(b->avge_delay, delay, 8);
	b->peak_delay = cake_ewma(b->peak_delay, delay,
				     delay > b->peak_delay ? 2 : 8);
	b->base_delay = cake_ewma(b->base_delay, delay,
				     delay < b->base_delay ? 2 : 8);

	/* charge packet bandwidth to this tin, and
	 * to the global shaper.
	 */
	b->tin_time_next_packet +=
			(len * (u64)b->tin_rate_ns) >> b->tin_rate_shft;
	q->time_next_packet += (len * (u64)q->rate_ns) >> q->rate_shft;

	if(q->overflow_timeout)
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
	[TCA_CAKE_ATM]           = { .type = NLA_U32 },
	[TCA_CAKE_FLOW_MODE]     = { .type = NLA_U32 },
	[TCA_CAKE_OVERHEAD]      = { .type = NLA_S32 },
	[TCA_CAKE_RTT]           = { .type = NLA_U32 },
	[TCA_CAKE_TARGET]        = { .type = NLA_U32 },
	[TCA_CAKE_MEMORY]        = { .type = NLA_U32 },
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
	u32 byte_target = mtu + (mtu >> 1);

	b->flow_quantum = 1514;
	b->host_quantum = 4096;
	if (rate) {
		b->flow_quantum = max(min(rate >> 12, 1514ULL), 300ULL);
		rate_shft = 32;
		rate_ns = ((u64) NSEC_PER_SEC) << rate_shft;
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

	b->cparams.target = max(byte_target_ns, ns_target);
	b->cparams.interval = max(rtt_est_ns +
				     b->cparams.target - ns_target,
				     b->cparams.target * 2);
	b->cparams.p_inc = 1 << 24; /* 1/256 */
	b->cparams.p_dec = 1 << 20; /* 1/4096 */
}

static int cake_config_besteffort(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_tin_data *b = &q->tins[0];
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 i;

	q->tin_cnt = 1;

	for (i = 0; i < 64; i++)
		q->tin_index[i] = 0;

	cake_set_rate(b, rate, mtu, US2TIME(q->target), US2TIME(q->interval));
	b->tin_quantum_band = 65535;
	b->tin_quantum_prio = 65535;

	return 0;
}

static int cake_config_precedence(struct Qdisc *sch)
{
	/* convert high-level (user visible) parameters into internal format */
	struct cake_sched_data *q = qdisc_priv(sch);
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum1 = 256;
	u32 quantum2 = 256;
	u32 i;

	q->tin_cnt = 8;

	for (i = 0; i < 64; i++)
		q->tin_index[i] = min((u32)(i >> 3), (u32)(q->tin_cnt));

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
 *  LLT "La" (TOS5)
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
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum1 = 256;
	u32 quantum2 = 256;
	u32 i;

	q->tin_cnt = 8;

	/* codepoint to class mapping */
	for (i = 0; i < 64; i++)
		q->tin_index[i] = 2;	/* default to best-effort */

	q->tin_index[0x08] = 0;	/* CS1 */
	q->tin_index[0x02] = 1;	/* TOS2 */
	q->tin_index[0x18] = 3;	/* CS3 */
	q->tin_index[0x04] = 4;	/* TOS4 */
	q->tin_index[0x01] = 5;	/* TOS1 */
	q->tin_index[0x10] = 5;	/* CS2 */
	q->tin_index[0x20] = 6;	/* CS4 */
	q->tin_index[0x28] = 6;	/* CS5 */
	q->tin_index[0x2c] = 6;	/* VA */
	q->tin_index[0x2e] = 6;	/* EF */
	q->tin_index[0x30] = 7;	/* CS6 */
	q->tin_index[0x38] = 7;	/* CS7 */

	for (i = 2; i <= 6; i += 2) {
		q->tin_index[0x08 + i] = 1;	/* AF1x */
		q->tin_index[0x10 + i] = 4;	/* AF2x */
		q->tin_index[0x18 + i] = 3;	/* AF3x */
		q->tin_index[0x20 + i] = 3;	/* AF4x */
	}

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
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum = 1024;
	u32 i;

	q->tin_cnt = 4;

	/* codepoint to class mapping */
	for (i = 0; i < 64; i++)
		q->tin_index[i] = 1;	/* default to best-effort */

	q->tin_index[0x08] = 0;	/* CS1 */

	q->tin_index[0x18] = 2;	/* CS3 */
	q->tin_index[0x04] = 2;	/* TOS4 */
	q->tin_index[0x01] = 2;	/* TOS1 */
	q->tin_index[0x10] = 2;	/* CS2 */

	q->tin_index[0x20] = 3;	/* CS4 */
	q->tin_index[0x28] = 3;	/* CS5 */
	q->tin_index[0x2c] = 3;	/* VA */
	q->tin_index[0x2e] = 3;	/* EF */
	q->tin_index[0x30] = 3;	/* CS6 */
	q->tin_index[0x38] = 3;	/* CS7 */

	for (i = 2; i <= 6; i += 2) {
		q->tin_index[0x10 + i] = 2;	/* AF2x */
		q->tin_index[0x18 + i] = 2;	/* AF3x */
		q->tin_index[0x20 + i] = 2;	/* AF4x */
	}

	/* class characteristics */
	cake_set_rate(&q->tins[0], rate >> 4, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[1], rate, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[2], rate >> 1, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[3], rate >> 2, mtu,
		      US2TIME(q->target), US2TIME(q->interval));

	/* priority weights */
	q->tins[0].tin_quantum_prio = quantum >> 4;
	q->tins[1].tin_quantum_prio = quantum;
	q->tins[2].tin_quantum_prio = quantum << 2;
	q->tins[3].tin_quantum_prio = quantum << 4;

	/* bandwidth-sharing weights */
	q->tins[0].tin_quantum_band = quantum >> 4;
	q->tins[1].tin_quantum_band = quantum;
	q->tins[2].tin_quantum_band = quantum >> 1;
	q->tins[3].tin_quantum_band = quantum >> 2;

	/* tin 0 is not 100% rate, but tin 1 is */
	return 1;
}

static int cake_config_diffserv_llt(struct Qdisc *sch)
{
/*  Diffserv structure specialised for Latency-Loss-Tradeoff spec.
 *		Loss Sensitive		(TOS1, TOS2)
 *		Best Effort
 *		Latency Sensitive	(TOS4, TOS5, VA, EF)
 *		Low Priority		(CS1)
 *		Network Control		(CS6, CS7)
 */
	struct cake_sched_data *q = qdisc_priv(sch);
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 i;

	q->tin_cnt = 5;

	/* codepoint to class mapping */
	for (i = 0; i < 64; i++)
		q->tin_index[i] = 1;	/* default to best-effort */

	q->tin_index[0x01] = 0;	/* TOS1 */
	q->tin_index[0x02] = 0;	/* TOS2 */
	q->tin_index[0x04] = 2;	/* TOS4 */
	q->tin_index[0x05] = 2;	/* TOS5 */
	q->tin_index[0x2c] = 2;	/* VA */
	q->tin_index[0x2e] = 2;	/* EF */
	q->tin_index[0x08] = 3;	/* CS1 */
	q->tin_index[0x30] = 4;	/* CS6 */
	q->tin_index[0x38] = 4;	/* CS7 */

	/* class characteristics */
	cake_set_rate(&q->tins[0], rate, mtu,
		      US2TIME(q->target * 4), US2TIME(q->interval * 4));
	cake_set_rate(&q->tins[1], rate, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[2], rate, mtu,
		      US2TIME(q->target), US2TIME(q->target));
	cake_set_rate(&q->tins[3], rate >> 4, mtu,
		      US2TIME(q->target), US2TIME(q->interval));
	cake_set_rate(&q->tins[4], rate >> 4, mtu,
		      US2TIME(q->target * 4), US2TIME(q->interval * 4));

	/* priority weights */
	q->tins[0].tin_quantum_prio = 2048;
	q->tins[1].tin_quantum_prio = 2048;
	q->tins[2].tin_quantum_prio = 2048;
	q->tins[3].tin_quantum_prio = 16384;
	q->tins[4].tin_quantum_prio = 32768;

	/* bandwidth-sharing weights */
	q->tins[0].tin_quantum_band = 2048;
	q->tins[1].tin_quantum_band = 2048;
	q->tins[2].tin_quantum_band = 2048;
	q->tins[3].tin_quantum_band = 256;
	q->tins[4].tin_quantum_band = 16;

	return 0;
}

static void cake_reconfigure(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int c, ft;

	switch (q->tin_mode) {
	case CAKE_MODE_BESTEFFORT:
	default:
		ft = cake_config_besteffort(sch);
		break;

	case CAKE_MODE_PRECEDENCE:
		ft = cake_config_precedence(sch);
		break;

	case CAKE_MODE_DIFFSERV8:
		ft = cake_config_diffserv8(sch);
		break;

	case CAKE_MODE_DIFFSERV4:
		ft = cake_config_diffserv4(sch);
		break;

	case CAKE_MODE_LLT:
		ft = cake_config_diffserv_llt(sch);
		break;
	};

	BUG_ON(q->tin_cnt > CAKE_MAX_TINS);
	for (c = q->tin_cnt; c < CAKE_MAX_TINS; c++)
		cake_clear_tin(sch, c);

	q->rate_ns   = q->tins[ft].tin_rate_ns;
	q->rate_shft = q->tins[ft].tin_rate_shft;

	if (q->buffer_config_limit) {
		q->buffer_limit = q->buffer_config_limit;
	} else if (q->rate_bps) {
		u64 t = (u64) q->rate_bps * q->interval;
		do_div(t, USEC_PER_SEC / 4);
		q->buffer_limit = max_t(u32, t, 4U << 20);
	} else {
		q->buffer_limit = ~0;
	}

	if (q->rate_bps)
		sch->flags &= ~TCQ_F_CAN_BYPASS;
	else
		sch->flags |= TCQ_F_CAN_BYPASS;

	q->buffer_limit = min(q->buffer_limit,
		max(sch->limit * psched_mtu(qdisc_dev(sch)),
		    q->buffer_config_limit));
}

static int cake_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_CAKE_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, cake_policy);
	if (err < 0)
		return err;

	if (tb[TCA_CAKE_BASE_RATE])
		q->rate_bps = nla_get_u32(tb[TCA_CAKE_BASE_RATE]);

	if (tb[TCA_CAKE_DIFFSERV_MODE])
		q->tin_mode = nla_get_u32(tb[TCA_CAKE_DIFFSERV_MODE]);

	if (tb[TCA_CAKE_ATM]) {
		q->rate_flags &= ~(CAKE_FLAG_ATM | CAKE_FLAG_PTM);
		q->rate_flags |= nla_get_u32(tb[TCA_CAKE_ATM]) & (CAKE_FLAG_ATM | CAKE_FLAG_PTM);
	}

	if (tb[TCA_CAKE_FLOW_MODE])
		q->flow_mode = nla_get_u32(tb[TCA_CAKE_FLOW_MODE]);

	if (tb[TCA_CAKE_NAT]) {
		q->flow_mode &= ~CAKE_FLOW_NAT_FLAG;
		q->flow_mode |= CAKE_FLOW_NAT_FLAG * !!nla_get_u32(tb[TCA_CAKE_NAT]);
	}

	if (tb[TCA_CAKE_OVERHEAD])
		q->rate_overhead = nla_get_s32(tb[TCA_CAKE_OVERHEAD]);

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

	if (tb[TCA_CAKE_MEMORY])
		q->buffer_config_limit = nla_get_s32(tb[TCA_CAKE_MEMORY]);

	if (q->tins) {
		sch_tree_lock(sch);
		cake_reconfigure(sch);
		sch_tree_unlock(sch);
	}

	return 0;
}

static void *cake_zalloc(size_t sz)
{
	void *ptr = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN);

	if (!ptr)
		ptr = vzalloc(sz);
	return ptr;
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

static int cake_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int i, j;

	/* codel_cache_init(); */
	sch->limit = 10240;
	q->tin_mode = CAKE_MODE_DIFFSERV4;
	q->flow_mode  = CAKE_FLOW_FLOWS;

	q->rate_bps = 0; /* unlimited by default */

	q->interval = 100000; /* 100ms default */
	q->target   =   5000; /* 5ms: codel RFC argues
			       * for 5 to 10% of interval
			       */

	q->cur_tin = 0;
	q->cur_flow  = 0;

	if (opt) {
		int err = cake_change(sch, opt);

		if (err)
			return err;
	}

	qdisc_watchdog_init(&q->watchdog, sch);

	q->tins = cake_zalloc(CAKE_MAX_TINS * sizeof(struct cake_tin_data));
	if (!q->tins)
		goto nomem;

	for (i = 0; i < CAKE_MAX_TINS; i++) {
		struct cake_tin_data *b = q->tins + i;

		b->perturbation = prandom_u32();
		INIT_LIST_HEAD(&b->new_flows);
		INIT_LIST_HEAD(&b->old_flows);
		INIT_LIST_HEAD(&b->decaying_flows);
		b->sparse_flow_count = 0;
		b->bulk_flow_count = 0;
		b->decaying_flow_count = 0;
		/* codel_params_init(&b->cparams); */

		for (j = 0; j < CAKE_QUEUES; j++) {
			struct cake_flow *flow = b->flows + j;
			u32 k = j*CAKE_MAX_TINS + i;

			INIT_LIST_HEAD(&flow->flowchain);
			cobalt_vars_init(&flow->cvars);

			q->overflow_heap[k].t = i;
			q->overflow_heap[k].b = j;
			b->overflow_idx[j] = k;
		}
	}

	cake_reconfigure(sch);
	q->avg_peak_bandwidth = q->rate_bps;
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

	if (nla_put_u32(skb, TCA_CAKE_ATM, (q->rate_flags & (CAKE_FLAG_ATM | CAKE_FLAG_PTM))))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_FLOW_MODE, q->flow_mode))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_OVERHEAD, q->rate_overhead))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_RTT, q->interval))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_TARGET, q->target))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_AUTORATE,
			!!(q->rate_flags & CAKE_FLAG_AUTORATE_INGRESS)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_MEMORY, q->buffer_config_limit))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int cake_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	/* reuse fq_codel stats format */
	struct cake_sched_data *q = qdisc_priv(sch);
	struct tc_cake_xstats *st = cake_zalloc(sizeof(*st));
	int i;

	if (!st)
		return -1;

	BUG_ON(q->tin_cnt > TC_CAKE_MAX_TINS);

	st->version = 4;
	st->max_tins = TC_CAKE_MAX_TINS;
	st->tin_cnt = q->tin_cnt;

	for (i = 0; i < q->tin_cnt; i++) {
		struct cake_tin_data *b = &q->tins[i];

		st->threshold_rate[i] = b->tin_rate_bps;
		st->target_us[i]      = cobalt_time_to_us(b->cparams.target);
		st->interval_us[i]    = cobalt_time_to_us(b->cparams.interval);

		/* TODO FIXME: add missing aspects of these composite stats */
		st->sent[i].packets       = b->packets;
		st->sent[i].bytes         = b->bytes;
		st->dropped[i].packets    = b->tin_dropped;
		st->ecn_marked[i].packets = b->tin_ecn_mark;
		st->backlog[i].bytes      = b->tin_backlog;

		st->peak_delay_us[i] = cobalt_time_to_us(b->peak_delay);
		st->avge_delay_us[i] = cobalt_time_to_us(b->avge_delay);
		st->base_delay_us[i] = cobalt_time_to_us(b->base_delay);

		st->way_indirect_hits[i] = b->way_hits;
		st->way_misses[i]        = b->way_misses;
		st->way_collisions[i]    = b->way_collisions;

		st->sparse_flows[i]      = b->sparse_flow_count + b->decaying_flow_count;
		st->bulk_flows[i]        = b->bulk_flow_count;
		st->unresponse_flows[i]  = b->unresponsive_flow_count;
		st->spare[i]             = 0;
		st->max_skblen[i]        = b->max_skblen;
	}
	st->capacity_estimate = q->avg_peak_bandwidth;
	st->memory_limit      = q->buffer_limit;
	st->memory_used       = q->buffer_max_used;

	i = gnet_stats_copy_app(d, st, sizeof(*st));
	cake_free(st);
	return i;
}

static struct Qdisc *cake_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long cake_get(struct Qdisc *sch, u32 classid)
{
	return 0;
}

static unsigned long cake_bind(struct Qdisc *sch, unsigned long parent,
			       u32 classid)
{
	return 0;
}

static void cake_put(struct Qdisc *q, unsigned long cl)
{
}

static struct tcf_proto **cake_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	return NULL;
}

static int cake_dump_tin(struct Qdisc *sch, unsigned long cl,
			 struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int cake_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				 struct gnet_dump *d)
{
	/* reuse fq_codel stats format */
	struct cake_sched_data *q = qdisc_priv(sch);
	u32 tin = (cl-1) / CAKE_QUEUES, idx = (cl-1) % CAKE_QUEUES;
	struct cake_tin_data *b = &q->tins[tin];
	struct gnet_stats_queue qs = {0};
	struct tc_fq_codel_xstats xstats;

	if (tin < q->tin_cnt && idx < CAKE_QUEUES) {
		const struct cake_flow *flow = &b->flows[idx];
		const struct sk_buff *skb = flow->head;

		memset(&xstats, 0, sizeof(xstats));
		xstats.type = TCA_FQ_CODEL_XSTATS_CLASS;
		xstats.class_stats.deficit = flow->deficit;
		xstats.class_stats.ldelay = 0;
		xstats.class_stats.count = flow->cvars.count;
		xstats.class_stats.lastcount = 0;
		xstats.class_stats.dropping = flow->cvars.dropping;
		if (flow->cvars.dropping) {
			cobalt_tdiff_t delta = flow->cvars.drop_next -
				cobalt_get_time();

			xstats.class_stats.drop_next = (delta >= 0) ?
				cobalt_time_to_us(delta) :
				-cobalt_time_to_us(-delta);
		}
		while (skb) {
			qs.qlen++;
			skb = skb->next;
		}
		qs.backlog = b->backlogs[idx];
		qs.drops = 0;
	}
	if (codel_stats_copy_queue(d, NULL, &qs, 0) < 0)
		return -1;
	if (tin < q->tin_cnt && idx < CAKE_QUEUES)
		return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
	return 0;
}

static void cake_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	unsigned int i, j, k;

	if (arg->stop)
		return;

	for (j = k = 0; j < q->tin_cnt; j++) {
		struct cake_tin_data *b = &q->tins[j];

		for (i = 0; i < CAKE_QUEUES; i++, k++) {
			if (list_empty(&b->flows[i].flowchain) ||
			    arg->count < arg->skip) {
				arg->count++;
				continue;
			}
			if (arg->fn(sch, k + 1, arg) < 0) {
				arg->stop = 1;
				break;
			}
			arg->count++;
		}
	}
}

static const struct Qdisc_class_ops cake_class_ops = {
	.leaf		=	cake_leaf,
	.get		=	cake_get,
	.put		=	cake_put,
	.tcf_chain	=	cake_find_tcf,
	.bind_tcf	=	cake_bind,
	.unbind_tcf	=	cake_put,
	.dump		=	cake_dump_tin,
	.dump_stats	=	cake_dump_class_stats,
	.walk		=	cake_walk,
};

static struct Qdisc_ops cake_qdisc_ops __read_mostly = {
	.cl_ops		=	&cake_class_ops,
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
