/*
 * Common Applications Kept Enhanced (CAKE) discipline - version 3
 *
 *  Copyright (C) 2014-2015 Jonathan Morton <chromatix99@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#include <net/flow_keys.h>
#else
#include <net/flow_dissector.h>
#endif
#include "codel5.h"

/* The CAKE Principles:
 *                 (or, how to have your cake and eat it too)
 *
 * This is a combination of several shaping, AQM and FQ
 * techniques into one easy-to-use package:
 *
 * - An overall bandwidth shaper, to move the bottleneck away
 *   from dumb CPE equipment and bloated MACs.  This operates
 *   in deficit mode (as in sch_fq), eliminating the need for
 *   any sort of burst parameter (eg. token buxket depth).
 *   Burst support is limited to that necessary to overcome
 *   scheduling latency.
 *
 * - A Diffserv-aware priority queue, giving more priority to
 *   certain classes, up to a specified fraction of bandwidth.
 *   Above that bandwidth threshold, the priority is reduced to
 *   avoid starving other bins.
 *
 * - Each priority bin has a separate Flow Queue system, to
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
 * threshold the bin is operating.  This determines whether
 * a priority-based weight (high) or a bandwidth-based weight
 * (low) is used for that bin in the current pass.
 *
 * This qdisc incorporates much of Eric Dumazet's fq_codel code, which
 * he kindly dual-licensed, which we customised for use as an
 * integrated subordinate.  See sch_fq_codel.c for details of
 * operation.
 */

#define CAKE_SET_WAYS (8)
#define CAKE_MAX_BINS (8)

struct cake_flow {
    struct sk_buff	  *head;
    struct sk_buff	  *tail;
    struct list_head  flowchain;
    int		  deficit;
    u32		  dropped; /* number of drops (or ECN marks) on this flow */
    struct codel_vars cvars;
}; /* please try to keep this structure <= 64 bytes */

struct cake_bin_data {
    struct cake_flow *flows;    /* Flows table [flows_cnt] */
    u32      *backlogs;  /* backlog table [flows_cnt] */
	u32		 *tags;		/* for set association [flows_cnt] */
    u32      flows_cnt;  /* number of flows - must be multiple of CAKE_SET_WAYS */
    u32      perturbation;   /* hash perturbation */
    u16      quantum;    /* psched_mtu(qdisc_dev(sch)); */

    struct codel_params cparams;
    u32      drop_overlimit;
    u16	     bulk_flow_count;
    u16	     sparse_flow_count;

    u32      last_skblen;
    u32      max_skblen;

    struct list_head new_flows; /* list of new flows */
    struct list_head old_flows; /* list of old flows */

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u64		 bin_time_next_packet;
	u32		 bin_rate_ns;
	int		 bin_rate_shft;
	u32		 bin_rate_bps;

	u16		 bin_quantum_prio;
	u16		 bin_quantum_band;
	int		 bin_deficit;
	u32		 bin_backlog;
	u32		 bin_dropped;
	u32		 bin_ecn_mark;

	u32		 packets;
	u64		 bytes;

	/* moving averages */
	codel_time_t avge_delay;
	codel_time_t peak_delay;
	codel_time_t base_delay;

	/* hash function stats */
	u32		 way_directs;
	u32		 way_hits;
	u32		 way_misses;
	u32		 way_collisions;
}; /* number of bins is small, so size of this struct doesn't matter much */

struct cake_sched_data {
	struct cake_bin_data *bins;
	u16		bin_cnt;
	u16		bin_mode;
	u8		bin_index[64];
	u16		flow_mode;

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u64		time_next_packet;
	u32		rate_ns;
	u16		rate_shft;
	u16		peel_threshold;
	u32		rate_bps;
	u16		rate_flags;
	short	rate_overhead;

	/* resource tracking */
	u32		buffer_used;
	u32		buffer_limit;

	/* indices for dequeue */
	u16		cur_bin;
	u16		cur_flow;

	struct qdisc_watchdog watchdog;
};

enum {
	CAKE_MODE_BESTEFFORT = 1,
	CAKE_MODE_PRECEDENCE,
	CAKE_MODE_DIFFSERV8,
	CAKE_MODE_DIFFSERV4,
	CAKE_MODE_SQUASH,
	CAKE_MODE_MAX
};

enum {
	CAKE_FLAG_ATM = 0x0001
};

enum {
	CAKE_FLOW_NONE = 0,
	CAKE_FLOW_SRC_IP,
	CAKE_FLOW_DST_IP,
	CAKE_FLOW_HOSTS,
	CAKE_FLOW_FLOWS,
	CAKE_FLOW_DUAL_SRC,
	CAKE_FLOW_DUAL_DST,
	CAKE_FLOW_DUAL,
	CAKE_FLOW_MAX
};

static inline unsigned int
cake_hash(struct cake_bin_data *q, const struct sk_buff *skb, int flow_mode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
    struct flow_keys keys;
#else
    struct flow_keys keys, host_keys;
#endif
    u32 flow_hash, host_hash, reduced_hash;

	if(unlikely(flow_mode == CAKE_FLOW_NONE || q->flows_cnt < CAKE_SET_WAYS))
		return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
	skb_flow_dissect(skb, &keys);

	flow_hash = jhash_3words(
		(__force u32)keys.dst,
		(__force u32)keys.src ^ keys.ip_proto,
		(__force u32)keys.ports, q->perturbation);

	host_hash = jhash_3words(
		(__force u32)((flow_mode & CAKE_FLOW_DST_IP) ? keys.dst : 0),
		(__force u32)((flow_mode & CAKE_FLOW_SRC_IP) ? keys.src : 0),
		(__force u32) 0, q->perturbation);
#else
	skb_flow_dissect_flow_keys(skb, &keys, FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);

	/* flow_hash_from_keys() sorts the addresses by value, so we have to preserve
	 * their order in a separate data structure in order to treat src and dst host
	 * addresses as independently selectable.
	 */
	host_keys = keys;
	host_keys.ports.ports     = 0;
	host_keys.basic.ip_proto  = 0;
	host_keys.keyid.keyid     = 0;
	host_keys.tags.vlan_id    = 0;
	host_keys.tags.flow_label = 0;

	if(!(flow_mode & CAKE_FLOW_SRC_IP)) {
		switch (host_keys.control.addr_type) {
		case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
			host_keys.addrs.v4addrs.src = 0;
			break;

		case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
			memset(&host_keys.addrs.v6addrs.src, 0, sizeof(host_keys.addrs.v6addrs.src));
			break;
		};
	}

	if(!(flow_mode & CAKE_FLOW_DST_IP)) {
		switch (host_keys.control.addr_type) {
		case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
			host_keys.addrs.v4addrs.dst = 0;
			break;

		case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
			memset(&host_keys.addrs.v6addrs.dst, 0, sizeof(host_keys.addrs.v6addrs.dst));
			break;
		};
	}

	flow_hash = flow_hash_from_keys(&keys);
	host_hash = flow_hash_from_keys(&host_keys);
#endif

	if(!(flow_mode & CAKE_FLOW_FLOWS))
		flow_hash = host_hash;
	reduced_hash = reciprocal_scale(flow_hash, q->flows_cnt);

	/* set-associative hashing */
	/* fast path if no hash collision (direct lookup succeeds) */
	if(likely(q->tags[reduced_hash] == flow_hash)) {
		q->way_directs++;
	} else {
		u32 inner_hash = reduced_hash % CAKE_SET_WAYS;
		u32 outer_hash = reduced_hash - inner_hash;
		u32 i,j,k;

		/* check if any active queue in the set is reserved for
		 * this flow. count the empty queues in the set, too 
		 */
		
		for(i=j=0, k=inner_hash; i < CAKE_SET_WAYS; i++,
			    k = (k+1) % CAKE_SET_WAYS) {
			if(q->tags[outer_hash + k] == flow_hash) {
				q->way_hits++;
				goto found;
			} else if(list_empty(&q->flows[outer_hash + k].flowchain)) {
				j++;
			}
		}

		/* no queue is reserved for this flow */
		if(j) {
			/* there's at least one empty queue, so find one
			   to reserve */
			q->way_misses++;

			for(i=0; i < CAKE_SET_WAYS; i++, k = (k+1) % CAKE_SET_WAYS)
				if(list_empty(&q->flows[outer_hash + k].flowchain))
					goto found;
		} else {
			/* 
			 with no empty queues default to the original
			 queue and accept the collision
			 */
			q->way_collisions++;
		}

	found:
		/* reserve queue for future packets in same flow */
		reduced_hash = outer_hash + k;
		q->tags[reduced_hash] = flow_hash;
	}

	return reduced_hash;
}

/* helper functions : might be changed when/if skb use a standard list_head */
/* remove one skb from head of slot queue */

static inline struct sk_buff *dequeue_head(struct cake_flow *flow)
{
    struct sk_buff *skb = flow->head;

    flow->head = skb->next;
    skb->next = NULL;
    return skb;
}

/* add skb to flow queue (tail add) */

static inline void
flow_queue_add(struct cake_flow *flow, struct sk_buff *skb)
{
    if (flow->head == NULL)
        flow->head = skb;
    else
        flow->tail->next = skb;
    flow->tail = skb;
    skb->next = NULL;
}

static inline u32 cake_overhead(struct cake_sched_data *q, u32 in)
{
	u32 out = in + q->rate_overhead;

	if(q->rate_flags & CAKE_FLAG_ATM) {
		out += 47;
		out /= 48;
		out *= 53;
	}

	return out;
}

static inline codel_time_t cake_ewma(codel_time_t avg, codel_time_t sample, int shift)
{
	avg -= avg >> shift;
	avg += sample >> shift;
	return avg;
}

/* FIXME: In terms of speed this is a real hit and could be easily
   replaced with tail drop...  BUT it's a slow-path routine. */

static unsigned int cake_drop(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	unsigned int maxbacklog=0, idx=0, bin=0, i, j, len;
	struct cake_bin_data *fqcd;
	struct cake_flow *flow;

	/* Queue is full; check across bins in use and
	 * find the fat flow and drop a packet. */
	for(j=0; j < q->bin_cnt; j++) {
		fqcd = &q->bins[j];

		list_for_each_entry(flow, &fqcd->old_flows, flowchain) {
			i = flow - fqcd->flows;
			if(fqcd->backlogs[i] > maxbacklog) {
				maxbacklog = fqcd->backlogs[i];
				idx = i;
				bin = j;
			}
		}

		list_for_each_entry(flow, &fqcd->new_flows, flowchain) {
			i = flow - fqcd->flows;
			if(fqcd->backlogs[i] > maxbacklog) {
				maxbacklog = fqcd->backlogs[i];
				idx = i;
				bin = j;
			}
		}
	}

	fqcd = &q->bins[bin];
	flow = &fqcd->flows[idx];
	skb = dequeue_head(flow);
	len = qdisc_pkt_len(skb);

	q->buffer_used      -= skb->truesize;
	fqcd->backlogs[idx] -= len;
	fqcd->bin_backlog -= len;
	sch->qstats.backlog -= len;

	fqcd->bin_dropped++;
	sch->qstats.drops++;
	flow->dropped++;

	kfree_skb(skb);
	sch->q.qlen--;

	return idx + (bin << 16);
}

static inline void cake_squash_diffserv(struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ipv4_change_dsfield(ip_hdr(skb), 3, 0);
		break;
	case htons(ETH_P_IPV6):
		ipv6_change_dsfield(ipv6_hdr(skb), 3, 0) ;
		break;
	default: break;
	};
}

static inline unsigned int cake_get_diffserv(struct sk_buff *skb)
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

static int cake_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	unsigned int idx, bin;
	struct cake_bin_data *fqcd;
	struct cake_flow *flow;
	u32 len = qdisc_pkt_len(skb);

	/* extract the Diffserv Precedence field, if it exists */
	if(q->bin_mode != CAKE_MODE_SQUASH) {
		bin = q->bin_index[cake_get_diffserv(skb)];
		if(unlikely(bin >= q->bin_cnt))
			bin = 0;
	} else {
		cake_squash_diffserv(skb);
		bin = q->bin_index[0];
	}

	fqcd = &q->bins[bin];

	/* choose flow to insert into */
	idx = cake_hash(fqcd, skb, q->flow_mode);
	flow = &fqcd->flows[idx];

	/* ensure shaper state isn't stale */
	if(!fqcd->bin_backlog) {
		u64 now = ktime_get_ns();
		if(fqcd->bin_time_next_packet < now)
			fqcd->bin_time_next_packet = now;

		if(!sch->q.qlen)
			if(q->time_next_packet < now)
				q->time_next_packet = now;
	}

	fqcd->last_skblen = len;
	if(unlikely(fqcd->last_skblen > fqcd->max_skblen))
			fqcd->max_skblen = fqcd->last_skblen;

	/*
	 * Split GSO aggregates if they're likely to impair flow isolation
	 * or if we need to know individual packet sizes for framing overhead.
	 */
	if(unlikely((len * max((u32) fqcd->bulk_flow_count, 1U) > q->peel_threshold && skb_is_gso(skb))))
	{
		struct sk_buff *segs, *nskb;
		netdev_features_t features = netif_skb_features(skb);

		segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

		if (IS_ERR_OR_NULL(segs))
			return qdisc_reshape_fail(skb, sch);

		while (segs) {
			nskb = segs->next;
			segs->next = NULL;
			qdisc_skb_cb(segs)->pkt_len = segs->len;

			codel_set_enqueue_time(segs);
			flow_queue_add(flow, segs);

			/* stats */
			sch->q.qlen++;
			fqcd->packets++;
			fqcd->bytes         += segs->len;
			fqcd->backlogs[idx] += segs->len;
			fqcd->bin_backlog += segs->len;
			sch->qstats.backlog += segs->len;
			q->buffer_used      += segs->truesize;

			segs = nskb;
		}

		qdisc_tree_decrease_qlen(sch, 1);
		consume_skb(skb);
	} else {
		/* not splitting */
		codel_set_enqueue_time(skb);
		flow_queue_add(flow, skb);

		/* stats */
		sch->q.qlen++;
		fqcd->packets++;
		fqcd->bytes         += len;
		fqcd->backlogs[idx] += len;
		fqcd->bin_backlog += len;
		sch->qstats.backlog += len;
		q->buffer_used      += skb->truesize;
	}

	/* flowchain */
	if(list_empty(&flow->flowchain)) {
		list_add_tail(&flow->flowchain, &fqcd->new_flows);
		fqcd->sparse_flow_count++;
		flow->deficit = fqcd->quantum;
		flow->dropped = 0;
	}

	if(q->buffer_used <= q->buffer_limit) {
		return NET_XMIT_SUCCESS;
	} else {
		bool same_flow = false;
		u32  dropped = 0;

		while(q->buffer_used > q->buffer_limit) {
			dropped++;
			if(cake_drop(sch) == idx + (bin << 16))
				same_flow = true;
		}
		fqcd->drop_overlimit += dropped;
		qdisc_tree_decrease_qlen(sch, dropped - same_flow);
		return same_flow ? NET_XMIT_CN : NET_XMIT_SUCCESS;
	}
}

/* Callback from codel_dequeue(); sch->qstats.backlog is already handled. */
static struct sk_buff *custom_dequeue(struct codel_vars *vars, struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_bin_data *fqcd = &q->bins[q->cur_bin];
	struct cake_flow *flow = &fqcd->flows[q->cur_flow];
	struct sk_buff *skb = NULL;
	u32 len;

	/* WARN_ON(flow != container_of(vars, struct cake_flow, cvars)); */

	if(flow->head) {
		skb = dequeue_head(flow);
		len = qdisc_pkt_len(skb);
		fqcd->backlogs[q->cur_flow] -= len;
		fqcd->bin_backlog         -= len;
		q->buffer_used              -= skb->truesize;
		sch->q.qlen--;
	}
	return skb;
}

/* Discard leftover packets from a bin no longer in use. */
static void cake_clear_bin(struct Qdisc *sch, u16 bin)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_bin_data *b = &q->bins[bin];

	q->cur_bin = bin;
	for(q->cur_flow = 0; q->cur_flow < b->flows_cnt; q->cur_flow++)
		while(custom_dequeue(NULL, sch))
			;
}

static struct sk_buff *cake_dequeue(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct cake_bin_data *fqcd = &q->bins[q->cur_bin];
	struct cake_flow *flow;
	struct list_head *head;
	u32 prev_drop_count, prev_ecn_mark;
	u32 len;
	u64 now = ktime_get_ns();
	int i;
	codel_time_t delay;

begin:
	if(!sch->q.qlen)
		return NULL;

	/* global hard shaper */
	if(q->time_next_packet > now) {
		sch->qstats.overlimits++;
		codel_watchdog_schedule_ns(&q->watchdog, q->time_next_packet, true);
		return NULL;
	}

	/* Choose a class to work on. */
	while(!fqcd->bin_backlog || fqcd->bin_deficit <= 0)
	{
		/* this is the priority soft-shaper magic */
		if(fqcd->bin_deficit <= 0)
			fqcd->bin_deficit +=
				fqcd->bin_time_next_packet > now ?
					fqcd->bin_quantum_band :
					fqcd->bin_quantum_prio;

		q->cur_bin++;
		fqcd++;
		if(q->cur_bin >= q->bin_cnt) {
			q->cur_bin = 0;
			fqcd = q->bins;
		}
	}

retry:
	/* service this class */
	head = &fqcd->new_flows;
	if(list_empty(head)) {
		head = &fqcd->old_flows;

		if(unlikely(list_empty(head))) {
			/* shouldn't ever happen */
			WARN_ON(fqcd->bin_backlog);
			fqcd->bin_backlog = 0;
			goto begin;
		}
	}
	flow = list_first_entry(head, struct cake_flow, flowchain);
	q->cur_flow = flow - fqcd->flows;

	if(flow->deficit <= 0) {
		flow->deficit += fqcd->quantum;
		list_move_tail(&flow->flowchain, &fqcd->old_flows);
		if(head == &fqcd->new_flows) {
			fqcd->sparse_flow_count--;
			fqcd->bulk_flow_count++;
		}
		goto retry;
	}

	prev_drop_count = flow->cvars.drop_count;
	prev_ecn_mark   = flow->cvars.ecn_mark;

	skb = codel_dequeue(sch, &flow->cvars,
	                    fqcd->cparams.interval, fqcd->cparams.target, fqcd->cparams.threshold,
	                    q->buffer_used > (q->buffer_limit >> 2) + (q->buffer_limit >> 1));

	fqcd->bin_dropped  += flow->cvars.drop_count - prev_drop_count;
	fqcd->bin_ecn_mark += flow->cvars.ecn_mark   - prev_ecn_mark;
	flow->dropped        += flow->cvars.drop_count - prev_drop_count;
	flow->dropped        += flow->cvars.ecn_mark   - prev_ecn_mark;

	if(!skb) {
		/* codel dropped the last packet in this queue; try again */
		if((head == &fqcd->new_flows) && !list_empty(&fqcd->old_flows)) {
			list_move_tail(&flow->flowchain, &fqcd->old_flows);
			fqcd->sparse_flow_count--;
			fqcd->bulk_flow_count++;
		} else {
			list_del_init(&flow->flowchain);
			if(head == &fqcd->new_flows)
				fqcd->sparse_flow_count--;
			else
				fqcd->bulk_flow_count--;
		}
		goto begin;
	}

	qdisc_bstats_update(sch, skb);
	if(flow->cvars.drop_count && sch->q.qlen) {
		qdisc_tree_decrease_qlen(sch, flow->cvars.drop_count);
		flow->cvars.drop_count = 0;
	}

	len = cake_overhead(q, qdisc_pkt_len(skb));

	flow->deficit       -= len;
	fqcd->bin_deficit -= len;

	/* collect delay stats */
	delay = now - codel_get_enqueue_time(skb);
	fqcd->avge_delay = cake_ewma(fqcd->avge_delay, delay, 8);
	fqcd->peak_delay = cake_ewma(fqcd->peak_delay, delay, delay > fqcd->peak_delay ? 2 : 8);
	fqcd->base_delay = cake_ewma(fqcd->base_delay, delay, delay < fqcd->base_delay ? 2 : 8);

	/* charge packet bandwidth to this and all lower bins, and to the global shaper */
	for(i=q->cur_bin; i >= 0; i--, fqcd--)
		fqcd->bin_time_next_packet +=
			(len * (u64) fqcd->bin_rate_ns) >> fqcd->bin_rate_shft;
	q->time_next_packet += (len * (u64) q->rate_ns) >> q->rate_shft;

	return skb;
}

static void cake_reset(struct Qdisc *sch)
{
	int c;

	for(c = 0; c < CAKE_MAX_BINS; c++)
		cake_clear_bin(sch, c);
}

static const struct nla_policy cake_policy[TCA_CAKE_MAX + 1] = {
	[TCA_CAKE_BASE_RATE]     = { .type = NLA_U32 },
	[TCA_CAKE_DIFFSERV_MODE] = { .type = NLA_U32 },
	[TCA_CAKE_ATM]           = { .type = NLA_U32 },
	[TCA_CAKE_FLOW_MODE]     = { .type = NLA_U32 },
	[TCA_CAKE_OVERHEAD]      = { .type = NLA_U32 },
};

static void cake_set_rate(struct cake_bin_data *fqcd,
						  u64 rate,
						  u32 mtu,
						  u32 ns_target,
						  u32 rtt_est_ns)
{
	/* convert byte-rate into time-per-byte */
	static const u64 MIN_RATE = 64;  /* so it will always unwedge in reasonable time */
	u64 rate_ns = 0;
	u8  rate_shft = 0;
	u32 byte_target_ns;
	u32 byte_target = mtu + (mtu >> 1);

	if(rate) {
		rate_shft = 32;
		rate_ns = ((u64) NSEC_PER_SEC) << rate_shft;
		do_div(rate_ns, max(MIN_RATE, rate));
		while(!!(rate_ns >> 32)) {
			rate_ns >>= 1;
			rate_shft--;
		}
	} /* else unlimited, ie. zero delay */

	fqcd->bin_rate_bps  = rate;
	fqcd->bin_rate_ns   = rate_ns;
	fqcd->bin_rate_shft = rate_shft;

	byte_target_ns = (byte_target * rate_ns) >> rate_shft;

	fqcd->cparams.target = max(byte_target_ns, ns_target);
	fqcd->cparams.interval = max(MS2TIME(100) + fqcd->cparams.target - ns_target, fqcd->cparams.target * 8);
	fqcd->cparams.threshold = (fqcd->cparams.target >> 15) * (fqcd->cparams.interval >> 15) * 2;

	fqcd->quantum = max(min(rate >> 12, 1514ULL), 300ULL);
}

static void cake_config_besteffort(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_bin_data *fqcd = &q->bins[0];
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	unsigned int i;

	q->bin_cnt = 1;

	for(i=0; i < 64; i++)
		q->bin_index[i] = 0;

	cake_set_rate(fqcd, rate, mtu, MS2TIME(5), MS2TIME(100));
	fqcd->bin_quantum_band = fqcd->bin_quantum_prio = 65535;
}

static void cake_config_precedence(struct Qdisc *sch)
{
	/* convert high-level (user visible) parameters into internal format */
	struct cake_sched_data *q = qdisc_priv(sch);
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum1 = 256;
	u32 quantum2 = 256;
	u32 i;

	q->bin_cnt = 8;

	for(i=0; i < 64; i++)
		q->bin_index[i] = min((u32)(i >> 3), (u32)(q->bin_cnt));

	for(i=0; i < q->bin_cnt; i++) {
		struct cake_bin_data *fqcd = &q->bins[i];

		cake_set_rate(fqcd, rate, mtu, MS2TIME(5), MS2TIME(100));

		fqcd->bin_quantum_prio = max(1U, quantum1);
		fqcd->bin_quantum_band = max(1U, quantum2);

		/* calculate next class's parameters */
		rate  *= 7;
		rate >>= 3;

		quantum1  *= 3;
		quantum1 >>= 1;

		quantum2  *= 7;
		quantum2 >>= 3;
	}
}

/*	List of known Diffserv codepoints:

	Least Effort (CS1)
	Best Effort (CS0)
	Max Reliability (TOS1)
	Max Throughput (TOS2)
	Min Delay (TOS4)
	Assured Forwarding 1 (AF1x) - x3
	Assured Forwarding 2 (AF2x) - x3
	Assured Forwarding 3 (AF3x) - x3
	Assured Forwarding 4 (AF4x) - x3
	Precedence Class 2 (CS2)
	Precedence Class 3 (CS3)
	Precedence Class 4 (CS4)
	Precedence Class 5 (CS5)
	Precedence Class 6 (CS6)
	Precedence Class 7 (CS7)
	Voice Admit (VA)
	Expedited Forwarding (EF)

	Total 25 codepoints.
 */

/*	List of traffic bins in RFC 4594:
		(roughly descending order of contended priority)
		(roughly ascending order of uncontended throughput)

	Network Control (CS6,CS7)      - routing traffic
	Telephony (EF,VA)         - aka. VoIP streams
	Signalling (CS5)               - VoIP setup
	Multimedia Conferencing (AF4x) - aka. video calls
	Realtime Interactive (CS4)     - eg. games
	Multimedia Streaming (AF3x)    - eg. YouTube, NetFlix, Twitch
	Broadcast Video (CS3)
	Low Latency Data (AF2x,TOS4)      - eg. database
	Ops, Admin, Management (CS2,TOS1) - eg. ssh
	Standard Service (CS0 & unrecognised codepoints)
	High Throughput Data (AF1x,TOS2)  - eg. web traffic
	Low Priority Data (CS1)           - eg. BitTorrent

	Total 12 traffic bins.
 */

static void cake_config_diffserv8(struct Qdisc *sch)
{
	/*	Pruned list of traffic bins for typical applications:

		Network Control          (CS6, CS7)
		Minimum Latency          (EF, VA, CS5, CS4)
		Interactive Shell        (CS2, TOS1)
		Low Latency Transactions (AF2x, TOS4)
		Video Streaming          (AF4x, AF3x, CS3)
		Bog Standard             (CS0 etc.)
		High Throughput          (AF1x, TOS2)
		Background Traffic       (CS1)

		Total 8 traffic bins.
	 */

	struct cake_sched_data *q = qdisc_priv(sch);
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum1 = 256;
	u32 quantum2 = 256;
	u32 i;

	q->bin_cnt = 8;

	/* codepoint to class mapping */
	for(i=0; i < 64; i++)
		q->bin_index[i] = 2;	/* default to best-effort */

	q->bin_index[0x08] = 0;	/* CS1 */
	q->bin_index[0x02] = 1;	/* TOS2 */
	q->bin_index[0x18] = 3;	/* CS3 */
	q->bin_index[0x04] = 4;	/* TOS4 */
	q->bin_index[0x01] = 5;	/* TOS1 */
	q->bin_index[0x10] = 5;	/* CS2 */
	q->bin_index[0x20] = 6;	/* CS4 */
	q->bin_index[0x28] = 6;	/* CS5 */
	q->bin_index[0x2c] = 6;	/* VA */
	q->bin_index[0x2e] = 6;	/* EF */
	q->bin_index[0x30] = 7;	/* CS6 */
	q->bin_index[0x38] = 7;	/* CS7 */

	for(i=2; i <= 6; i += 2) {
		q->bin_index[0x08 + i] = 1;	/* AF1x */
		q->bin_index[0x10 + i] = 4;	/* AF2x */
		q->bin_index[0x18 + i] = 3;	/* AF3x */
		q->bin_index[0x20 + i] = 3;	/* AF4x */
	}

	/* class characteristics */
	for(i=0; i < q->bin_cnt; i++) {
		struct cake_bin_data *fqcd = &q->bins[i];

		cake_set_rate(fqcd, rate, mtu, MS2TIME(5), MS2TIME(100));

		fqcd->bin_quantum_prio = max(1U, quantum1);
		fqcd->bin_quantum_band = max(1U, quantum2);

		/* calculate next class's parameters */
		rate  *= 7;
		rate >>= 3;

		quantum1  *= 3;
		quantum1 >>= 1;

		quantum2  *= 7;
		quantum2 >>= 3;
	}
}

static void cake_config_diffserv4(struct Qdisc *sch)
{
	/*  Further pruned list of traffic bins for four-class system:

	    Latency Sensitive  (CS7, CS6, EF, VA, CS5, CS4)
	    Streaming Media    (AF4x, AF3x, CS3, AF2x, TOS4, CS2, TOS1)
	    Best Effort        (CS0, AF1x, TOS2, and all not otherwise specified)
	    Background Traffic (CS1)

		Total 4 traffic bins.
	 */

	struct cake_sched_data *q = qdisc_priv(sch);
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum = 256;
	u32 i;

	q->bin_cnt = 4;

	/* codepoint to class mapping */
	for(i=0; i < 64; i++)
		q->bin_index[i] = 1;	/* default to best-effort */

	q->bin_index[0x08] = 0;	/* CS1 */

	q->bin_index[0x18] = 2;	/* CS3 */
	q->bin_index[0x04] = 2;	/* TOS4 */
	q->bin_index[0x01] = 2;	/* TOS1 */
	q->bin_index[0x10] = 2;	/* CS2 */

	q->bin_index[0x20] = 3;	/* CS4 */
	q->bin_index[0x28] = 3;	/* CS5 */
	q->bin_index[0x2c] = 3;	/* VA */
	q->bin_index[0x2e] = 3;	/* EF */
	q->bin_index[0x30] = 3;	/* CS6 */
	q->bin_index[0x38] = 3;	/* CS7 */

	for(i=2; i <= 6; i += 2) {
		q->bin_index[0x10 + i] = 2;	/* AF2x */
		q->bin_index[0x18 + i] = 2;	/* AF3x */
		q->bin_index[0x20 + i] = 2;	/* AF4x */
	}

	/* class characteristics */
	cake_set_rate(&q->bins[0], rate,               mtu, MS2TIME(5), MS2TIME(100));
	cake_set_rate(&q->bins[1], rate - (rate >> 4), mtu, MS2TIME(5), MS2TIME(100));
	cake_set_rate(&q->bins[2], rate - (rate >> 2), mtu, MS2TIME(5), MS2TIME(100));
	cake_set_rate(&q->bins[3], rate >> 2,          mtu, MS2TIME(5), MS2TIME(100));

	/* priority weights */
	q->bins[0].bin_quantum_prio = quantum >> 4;
	q->bins[1].bin_quantum_prio = quantum;
	q->bins[2].bin_quantum_prio = quantum << 2;
	q->bins[3].bin_quantum_prio = quantum << 4;

	/* bandwidth-sharing weights */
	q->bins[0].bin_quantum_band = (quantum >> 4);
	q->bins[1].bin_quantum_band = (quantum >> 3) + (quantum >> 4);
	q->bins[2].bin_quantum_band = (quantum >> 1);
	q->bins[3].bin_quantum_band = (quantum >> 2);
}

static void cake_reconfigure(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int c;

	switch(q->bin_mode) {
	case CAKE_MODE_SQUASH:
	case CAKE_MODE_BESTEFFORT:
	default:
		cake_config_besteffort(sch);
		break;

	case CAKE_MODE_PRECEDENCE:
		cake_config_precedence(sch);
		break;

	case CAKE_MODE_DIFFSERV8:
		cake_config_diffserv8(sch);
		break;

	case CAKE_MODE_DIFFSERV4:
		cake_config_diffserv4(sch);
		break;
	};

	BUG_ON(CAKE_MAX_BINS < q->bin_cnt);
	for(c = q->bin_cnt; c < CAKE_MAX_BINS; c++)
		cake_clear_bin(sch, c);

	q->rate_ns   = q->bins[0].bin_rate_ns;
	q->rate_shft = q->bins[0].bin_rate_shft;

	if(q->rate_bps)
	{
		u64 t = q->rate_bps * q->bins[0].cparams.interval;
		do_div(t, NSEC_PER_SEC / 4);
		q->buffer_limit = t;

		if(q->buffer_limit < 65536)
			q->buffer_limit = 65536;

		q->peel_threshold = (q->rate_flags & CAKE_FLAG_ATM) ? 0 : min(65535U, q->rate_bps >> 12);
	} else {
		q->buffer_limit = 1 << 20;
		q->peel_threshold = 0;
	}

	q->buffer_limit = min(q->buffer_limit, sch->limit * psched_mtu(qdisc_dev(sch)));
}

static int cake_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_CAKE_MAX + 1];
	int err;

	if(!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, cake_policy);
	if(err < 0)
		return err;

	if(tb[TCA_CAKE_BASE_RATE])
		q->rate_bps = nla_get_u32(tb[TCA_CAKE_BASE_RATE]);

	if(tb[TCA_CAKE_DIFFSERV_MODE])
		q->bin_mode = nla_get_u32(tb[TCA_CAKE_DIFFSERV_MODE]);

	if(tb[TCA_CAKE_ATM]) {
		if(!!nla_get_u32(tb[TCA_CAKE_ATM]))
			q->rate_flags |= CAKE_FLAG_ATM;
		else
			q->rate_flags &= ~CAKE_FLAG_ATM;
	}

	if(tb[TCA_CAKE_FLOW_MODE])
		q->flow_mode = nla_get_u32(tb[TCA_CAKE_FLOW_MODE]);

	if(tb[TCA_CAKE_OVERHEAD])
		q->rate_overhead = nla_get_u32(tb[TCA_CAKE_OVERHEAD]);

	if(q->bins) {
		sch_tree_lock(sch);
		cake_reconfigure(sch);
		sch_tree_unlock(sch);
	}

	return 0;
}

static void *cake_zalloc(size_t sz)
{
	void *ptr = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN);

	if(!ptr)
		ptr = vzalloc(sz);
	return ptr;
}

static void cake_free(void *addr)
{
	if(addr)
		kvfree(addr);
}

static void cake_destroy(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);

	if(q->bins) {
		u32 i;
		for(i=0; i < CAKE_MAX_BINS; i++) {
			cake_free(q->bins[i].tags);
			cake_free(q->bins[i].backlogs);
			cake_free(q->bins[i].flows);
		}
		cake_free(q->bins);
	}
}

static int cake_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int i,j;

	codel_cache_init();

	sch->limit = 10240;
	q->bin_mode = CAKE_MODE_DIFFSERV4;
	q->flow_mode  = CAKE_FLOW_FLOWS;

	q->rate_bps = 0; /* unlimited by default */

	q->cur_bin = 0;
	q->cur_flow  = 0;

	if(opt) {
		int err = cake_change(sch, opt);
		if(err)
			return err;
	}

	qdisc_watchdog_init(&q->watchdog, sch);

	q->bins = cake_zalloc(CAKE_MAX_BINS * sizeof(struct cake_bin_data));
	if(!q->bins)
		goto nomem;

	for(i=0; i < CAKE_MAX_BINS; i++) {
		struct cake_bin_data *fqcd = q->bins + i;

		fqcd->flows_cnt = 1024;
		fqcd->perturbation = prandom_u32();
		INIT_LIST_HEAD(&fqcd->new_flows);
		INIT_LIST_HEAD(&fqcd->old_flows);
		fqcd->sparse_flow_count=0;
		fqcd->bulk_flow_count=0;
		/* codel_params_init(&fqcd->cparams); */

		fqcd->flows    = cake_zalloc(fqcd->flows_cnt * sizeof(struct cake_flow));
		fqcd->backlogs = cake_zalloc(fqcd->flows_cnt * sizeof(u32));
		fqcd->tags     = cake_zalloc(fqcd->flows_cnt * sizeof(u32));
		if(!fqcd->flows || !fqcd->backlogs || !fqcd->tags)
			goto nomem;

		for(j=0; j < fqcd->flows_cnt; j++) {
			struct cake_flow *flow = fqcd->flows + j;

			INIT_LIST_HEAD(&flow->flowchain);
			codel_vars_init(&flow->cvars);
		}
	}

	cake_reconfigure(sch);

	sch->flags &= ~TCQ_F_CAN_BYPASS;

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
	if(!opts)
		goto nla_put_failure;

	if(nla_put_u32(skb, TCA_CAKE_BASE_RATE, q->rate_bps))
		goto nla_put_failure;

	if(nla_put_u32(skb, TCA_CAKE_DIFFSERV_MODE, q->bin_mode))
		goto nla_put_failure;

	if(nla_put_u32(skb, TCA_CAKE_ATM, !!(q->rate_flags & CAKE_FLAG_ATM)))
		goto nla_put_failure;

	if(nla_put_u32(skb, TCA_CAKE_FLOW_MODE, q->flow_mode))
		goto nla_put_failure;

	if(nla_put_u32(skb, TCA_CAKE_OVERHEAD, q->rate_overhead))
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

	if(!st)
		return -1;

	BUG_ON(q->bin_cnt > (sizeof(st->bin) / sizeof(st->bin[0])));

	st->type = 0xCAFE;
	st->bin_cnt = q->bin_cnt;

	for(i=0; i < q->bin_cnt; i++) {
		struct cake_bin_data *fqcd = &q->bins[i];

		st->bin[i].rate          = fqcd->bin_rate_bps;
		st->bin[i].target_us     = codel_time_to_us(fqcd->cparams.target);
		st->bin[i].interval_us   = codel_time_to_us(fqcd->cparams.interval);
		st->bin[i].packets       = fqcd->packets;
		st->bin[i].bytes         = fqcd->bytes;
		st->bin[i].dropped       = fqcd->bin_dropped;
		st->bin[i].ecn_marked    = fqcd->bin_ecn_mark;
		st->bin[i].backlog_bytes = fqcd->bin_backlog;

		st->bin[i].peak_delay = codel_time_to_us(fqcd->peak_delay);
		st->bin[i].avge_delay = codel_time_to_us(fqcd->avge_delay);
		st->bin[i].base_delay = codel_time_to_us(fqcd->base_delay);

		st->bin[i].way_indirect_hits = fqcd->way_hits;
		st->bin[i].way_misses        = fqcd->way_misses;
		st->bin[i].way_collisions    = fqcd->way_collisions;

		st->bin[i].sparse_flows      = fqcd->sparse_flow_count;
		st->bin[i].bulk_flows        = fqcd->bulk_flow_count;
		st->bin[i].last_skblen       = fqcd->last_skblen;
		st->bin[i].max_skblen        = fqcd->max_skblen;
	}

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

static unsigned long cake_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
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

static int cake_dump_bin(struct Qdisc *sch, unsigned long cl, struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int cake_dump_class_stats(struct Qdisc *sch, unsigned long cl, struct gnet_dump *d)
{
	/* reuse fq_codel stats format */
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_bin_data *fqcd = q->bins;
	u32 bin=0, idx=cl-1;
	struct gnet_stats_queue qs = {0};
	struct tc_fq_codel_xstats xstats;

	while(bin < q->bin_cnt && idx >= fqcd->flows_cnt) {
		idx -= fqcd->flows_cnt;
		bin++;
		fqcd++;
	}

	if(bin < q->bin_cnt && idx >= fqcd->flows_cnt) {
		const struct cake_flow *flow = &fqcd->flows[idx];
		const struct sk_buff *skb = flow->head;

		memset(&xstats, 0, sizeof(xstats));
		xstats.type = TCA_FQ_CODEL_XSTATS_CLASS;
		xstats.class_stats.deficit = flow->deficit;
		xstats.class_stats.ldelay = 0;
		xstats.class_stats.count = flow->cvars.count;
		xstats.class_stats.lastcount = 0;
		xstats.class_stats.dropping = flow->cvars.dropping;
		if(flow->cvars.dropping) {
			codel_tdiff_t delta = flow->cvars.drop_next - codel_get_time();
			xstats.class_stats.drop_next = (delta >= 0) ?
				codel_time_to_us(delta) :
				-codel_time_to_us(-delta);
		}
		while(skb) {
			qs.qlen++;
			skb = skb->next;
		}
		qs.backlog = fqcd->backlogs[idx];
		qs.drops = flow->dropped;
	}
	if (codel_stats_copy_queue(d, NULL, &qs, 0) < 0)
		return -1;
	if(bin < q->bin_cnt && idx >= fqcd->flows_cnt)
		return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
	return 0;
}

static void cake_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	unsigned int i,j,k;

	if(arg->stop)
		return;

	for(j=k=0; j < q->bin_cnt; j++) {
		struct cake_bin_data *fqcd = &q->bins[j];

		for(i=0; i < fqcd->flows_cnt; i++,k++) {
			if(list_empty(&fqcd->flows[i].flowchain) || arg->count < arg->skip) {
				arg->count++;
				continue;
			}
			if(arg->fn(sch, k+1, arg) < 0) {
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
	.dump		=	cake_dump_bin,
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
	.drop		=	cake_drop,
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
