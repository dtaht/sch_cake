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
#include <net/netlink.h>
#include "pkt_sched.h"
#include <net/flow_keys.h>
#include "codel5.h"

/* The CAKE Principle:
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
 *   avoid starving other classes.
 *
 * - Each priority class has a separate Flow Queue system, to
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
 * threshold the class is operating.  This determines whether
 * a priority-based weight (high) or a bandwidth-based weight
 * (low) is used for that class in the current pass.
 *
 * This qdisc incorporates much of Eric Dumazet's fq_codel code,
 * customised for use as an integrated subordinate.
 * See sch_fq_codel.c for details of operation.
 */

#define CAKE_SET_WAYS (8)
#define CAKE_MAX_CLASSES (8)

struct cake_fqcd_flow {
    struct sk_buff	  *head;
    struct sk_buff	  *tail;
    struct list_head  flowchain;
    int		  deficit;
    u32		  dropped; /* number of drops (or ECN marks) on this flow */
    struct codel_vars cvars;
}; /* please try to keep this structure <= 64 bytes */

struct cake_fqcd_sched_data {
    struct cake_fqcd_flow *flows;    /* Flows table [flows_cnt] */
    u32     *backlogs;  /* backlog table [flows_cnt] */
	u32		*tags;		/* for set association [flows_cnt] */
    u32     flows_cnt;  /* number of flows - must be multiple of CAKE_SET_WAYS */
    u32     perturbation;   /* hash perturbation */
    u16     quantum;    /* psched_mtu(qdisc_dev(sch)); */

    struct codel_params cparams;
    u32     drop_overlimit;
    u32     new_flow_count;

    struct list_head new_flows; /* list of new flows */
    struct list_head old_flows; /* list of old flows */

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u64		class_time_next_packet;
	u32		class_rate_ns;
	int		class_rate_shft;
	u32		class_rate_bps;

	u16		class_quantum_prio;
	u16		class_quantum_band;
	int		class_deficit;
	u32		class_backlog;
	u32		class_dropped;
	u32		class_ecn_mark;

	u32		packets;
	u64		bytes;

	/* moving averages */
	codel_time_t avge_delay;
	codel_time_t peak_delay;
	codel_time_t base_delay;

	/* hash function stats */
	u32		way_directs;
	u32		way_hits;
	u32		way_misses;
	u32		way_collisions;
}; /* number of classes is small, so size of this struct doesn't matter much */

struct cake_sched_data {
	struct cake_fqcd_sched_data *classes;
	u16		class_cnt;
	u16		class_mode;
	u8		class_index[64];
	u16		flow_mode;

	/* time_next = time_this + ((len * rate_ns) >> rate_shft) */
	u64		time_next_packet;
	u32		rate_ns;
	int		rate_shft;
	u32		rate_bps;
	u16		rate_flags;

	/* resource tracking */
	u32		buffer_used;
	u32		buffer_limit;

	/* indices for dequeue */
	u16		cur_class;
	u16		cur_flow;

	struct qdisc_watchdog watchdog;
};

enum {
	CAKE_MODE_BESTEFFORT = 1,
	CAKE_MODE_PRECEDENCE,
	CAKE_MODE_DIFFSERV8,
	CAKE_MODE_DIFFSERV4,
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
	CAKE_FLOW_ALL,
	CAKE_FLOW_MAX
};

static inline unsigned int
cake_fqcd_hash(struct cake_fqcd_sched_data *q, const struct sk_buff *skb, int flow_mode)
{
    struct flow_keys keys;
    u32 hash, reduced_hash;

	if(unlikely(flow_mode == CAKE_FLOW_NONE || q->flows_cnt < CAKE_SET_WAYS))
		return 0;

	skb_flow_dissect(skb, &keys);

	if(flow_mode != CAKE_FLOW_ALL) {
		keys.ip_proto = 0;
		keys.ports = 0;

		if(!(flow_mode & CAKE_FLOW_SRC_IP))
			keys.src = 0;

		if(!(flow_mode & CAKE_FLOW_DST_IP))
			keys.dst = 0;
	}

	hash = jhash_3words((__force u32)keys.dst,
						(__force u32)keys.src ^ keys.ip_proto,
						(__force u32)keys.ports, q->perturbation);

	reduced_hash = reciprocal_scale(hash, q->flows_cnt);

	// set-associative hashing
	// fast path if no hash collision (direct lookup succeeds)
	if(likely(q->tags[reduced_hash] == hash)) {
		q->way_directs++;
	} else {
		u32 inner_hash = reduced_hash % CAKE_SET_WAYS;
		u32 outer_hash = reduced_hash - inner_hash;
		u32 i,j,k;

		// check if any active queue in the set is reserved for this flow
		// count the empty queues in the set, too
		for(i=j=0, k=inner_hash; i < CAKE_SET_WAYS; i++, k = (k+1) % CAKE_SET_WAYS) {
			if(!q->backlogs[outer_hash + k]) {
				j++;
			} else if(q->tags[outer_hash + k] == hash) {
				q->way_hits++;
				goto found;
			}
		}

		// no queue is reserved for this flow
		if(j) {
			// there's at least one empty queue, so find one to reserve
			q->way_misses++;

			for(i=0; i < CAKE_SET_WAYS; i++, k = (k+1) % CAKE_SET_WAYS)
				if(!q->backlogs[outer_hash + k])
					goto found;
		} else {
			// there are no empty queues
			// just default to the original queue and accept the collision
			q->way_collisions++;
		}

	found:
		// reserve queue for future packets in same flow
		reduced_hash = outer_hash + k;
		q->tags[reduced_hash] = hash;
	}

	return reduced_hash;
}

/* helper functions : might be changed when/if skb use a standard list_head */

/* remove one skb from head of slot queue */
static inline struct sk_buff *dequeue_head(struct cake_fqcd_flow *flow)
{
    struct sk_buff *skb = flow->head;

    flow->head = skb->next;
    skb->next = NULL;
    return skb;
}

/* add skb to flow queue (tail add) */
static inline void
flow_queue_add(struct cake_fqcd_flow *flow, struct sk_buff *skb)
{
    if (flow->head == NULL)
        flow->head = skb;
    else
        flow->tail->next = skb;
    flow->tail = skb;
    skb->next = NULL;
}

static inline u32 cake_quantise(u32 in, u32 net, u32 gross)
{
	return gross * ((in + net-1) / net);
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
	unsigned int maxbacklog=0, idx=0, cls=0, i, j, len;
	struct cake_fqcd_sched_data *fqcd;
	struct cake_fqcd_flow *flow;

	/* Queue is full; find the fat flow and drop a packet. */
	for(j=0; j < CAKE_MAX_CLASSES; j++) {
		fqcd = &q->classes[j];
		for(i=0; i < fqcd->flows_cnt; i++) {
			if(fqcd->backlogs[i] > maxbacklog) {
				maxbacklog = fqcd->backlogs[i];
				idx = i;
				cls = j;
			}
		}
	}

	fqcd = &q->classes[cls];
	flow = &fqcd->flows[idx];
	skb = dequeue_head(flow);
	len = qdisc_pkt_len(skb);

	q->buffer_used      -= skb->truesize;
	fqcd->backlogs[idx] -= len;
	fqcd->class_backlog -= len;
	sch->qstats.backlog -= len;

	fqcd->class_dropped++;
	sch->qstats.drops++;
	flow->dropped++;

	kfree_skb(skb);
	sch->q.qlen--;

	return idx + (cls << 16);
}

static inline unsigned int cake_get_diffserv(struct sk_buff *skb)
{
	/* borrowed from sch_dsmark */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
	  // FIXME: cow is not needed
	  // if (!pskb_network_may_pull(skb, sizeof(struct iphdr)))

		if (unlikely(skb_cow_head(skb, sizeof(struct iphdr))))
			return 0;
		return ipv4_get_dsfield(ip_hdr(skb)) >> 2;

	case htons(ETH_P_IPV6):
		if (unlikely(skb_cow_head(skb, sizeof(struct ipv6hdr))))
			return 0;
		return ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	default:
		/* If there is no Diffserv field, treat as bulk */
		return 0;
	};
}

static int cake_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	unsigned int idx, cls;
	struct cake_fqcd_sched_data *fqcd;
	struct cake_fqcd_flow *flow;
	u32 len = qdisc_pkt_len(skb);

	/* extract the Diffserv Precedence field, if it exists */
	cls = q->class_index[cake_get_diffserv(skb)];
	if(unlikely(cls >= q->class_cnt))
		cls = 0;
	fqcd = &q->classes[cls];

	/* choose flow to insert into, and do so */
	idx = cake_fqcd_hash(fqcd, skb, q->flow_mode);

	codel_set_enqueue_time(skb);
	flow = &fqcd->flows[idx];
	flow_queue_add(flow, skb);

	/* ensure shaper state isn't stale */
	if(!fqcd->class_backlog) {
		u64 now = ktime_get_ns();
		if(fqcd->class_time_next_packet < now)
			fqcd->class_time_next_packet = now;

		if(!sch->q.qlen)
			if(q->time_next_packet < now)
				q->time_next_packet = now;
	}

	/* stats */
	fqcd->packets++;
	fqcd->bytes         += len;
	fqcd->backlogs[idx] += len;
	fqcd->class_backlog += len;
	sch->qstats.backlog += len;
	q->buffer_used      += skb->truesize;

	/* flowchain */
	if(list_empty(&flow->flowchain)) {
		list_add_tail(&flow->flowchain, &fqcd->new_flows);
		fqcd->new_flow_count++;
		flow->deficit = fqcd->quantum;
		flow->dropped = 0;
	}
	sch->q.qlen++;

	if(q->buffer_used <= q->buffer_limit) {
		return NET_XMIT_SUCCESS;
	} else {
		bool same_flow = false;
		u32  dropped = 0;

		while(q->buffer_used > q->buffer_limit) {
			dropped++;
			if(cake_drop(sch) == idx + (cls << 16))
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
	struct cake_fqcd_sched_data *fqcd = &q->classes[q->cur_class];
	struct cake_fqcd_flow *flow = &fqcd->flows[q->cur_flow];
	struct sk_buff *skb = NULL;
	u32 len;

	/* WARN_ON(flow != container_of(vars, struct cake_fqcd_flow, cvars)); */

	if(flow->head) {
		skb = dequeue_head(flow);
		len = qdisc_pkt_len(skb);
		fqcd->backlogs[q->cur_flow] -= len;
		fqcd->class_backlog         -= len;
		q->buffer_used              -= skb->truesize;
		sch->q.qlen--;
	}
	return skb;
}

/* Discard leftover packets from a class no longer in use. */
static void cake_clear_class(struct Qdisc *sch, u16 class)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_fqcd_sched_data *fqcd = &q->classes[class];

	q->cur_class = class;
	for(q->cur_flow = 0; q->cur_flow < fqcd->flows_cnt; q->cur_flow++)
		while(custom_dequeue(NULL, sch))
			;
}

static struct sk_buff *cake_dequeue(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct cake_fqcd_sched_data *fqcd = &q->classes[q->cur_class];
	struct cake_fqcd_flow *flow;
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
	while(!fqcd->class_backlog || fqcd->class_deficit <= 0)
	{
		/* this is the priority soft-shaper magic */
		if(fqcd->class_deficit <= 0)
			fqcd->class_deficit +=
				fqcd->class_time_next_packet > now ?
					fqcd->class_quantum_band :
					fqcd->class_quantum_prio;

		q->cur_class++;
		fqcd++;
		if(q->cur_class >= q->class_cnt) {
			q->cur_class = 0;
			fqcd = q->classes;
		}
	}

retry:
	/* service this class */
	head = &fqcd->new_flows;
	if(list_empty(head)) {
		head = &fqcd->old_flows;

		if(unlikely(list_empty(head))) {
			/* shouldn't ever happen */
			WARN_ON(fqcd->class_backlog);
			fqcd->class_backlog = 0;
			goto begin;
		}
	}
	flow = list_first_entry(head, struct cake_fqcd_flow, flowchain);
	q->cur_flow = flow - fqcd->flows;

	if(flow->deficit <= 0) {
		flow->deficit += fqcd->quantum;
		list_move_tail(&flow->flowchain, &fqcd->old_flows);
		goto retry;
	}

	prev_drop_count = flow->cvars.drop_count;
	prev_ecn_mark   = flow->cvars.ecn_mark;

	skb = codel_dequeue(sch, &flow->cvars, fqcd->cparams.interval, fqcd->cparams.target,
						q->buffer_used > (q->buffer_limit >> 2) + (q->buffer_limit >> 1));

	fqcd->class_dropped  += flow->cvars.drop_count - prev_drop_count;
	fqcd->class_ecn_mark += flow->cvars.ecn_mark   - prev_ecn_mark;
	flow->dropped        += flow->cvars.drop_count - prev_drop_count;
	flow->dropped        += flow->cvars.ecn_mark   - prev_ecn_mark;

	if(!skb) {
		/* codel dropped our packet; try again */
		if((head == &fqcd->new_flows) && !list_empty(&fqcd->old_flows))
			list_move_tail(&flow->flowchain, &fqcd->old_flows);
		else
			list_del_init(&flow->flowchain);
		goto begin;
	}

	qdisc_bstats_update(sch, skb);
	if(flow->cvars.drop_count && sch->q.qlen) {
		qdisc_tree_decrease_qlen(sch, flow->cvars.drop_count);
		flow->cvars.drop_count = 0;
	}

	len = qdisc_pkt_len(skb);
	if(q->rate_flags & CAKE_FLAG_ATM)
		len = cake_quantise(len, 48, 53);

	flow->deficit       -= len;
	fqcd->class_deficit -= len;

	/* collect delay stats */
	delay = now - codel_get_enqueue_time(skb);
	fqcd->avge_delay = cake_ewma(fqcd->avge_delay, delay, 8);
	fqcd->peak_delay = cake_ewma(fqcd->peak_delay, delay, delay > fqcd->peak_delay ? 2 : 8);
	fqcd->base_delay = cake_ewma(fqcd->base_delay, delay, delay < fqcd->base_delay ? 2 : 8);

	/* charge packet bandwidth to this and all lower classes, and to the global shaper */
	for(i=q->cur_class; i >= 0; i--, fqcd--)
		fqcd->class_time_next_packet +=
			(len * (u64) fqcd->class_rate_ns) >> fqcd->class_rate_shft;
	q->time_next_packet += (len * (u64) q->rate_ns) >> q->rate_shft;

	return skb;
}

static void cake_reset(struct Qdisc *sch)
{
	int c;

	for(c = 0; c < CAKE_MAX_CLASSES; c++)
		cake_clear_class(sch, c);
}

static const struct nla_policy cake_policy[TCA_CAKE_MAX + 1] = {
	[TCA_CAKE_BASE_RATE]	 = { .type = NLA_U32 },
	[TCA_CAKE_DIFFSERV_MODE] = { .type = NLA_U32 },
	[TCA_CAKE_ATM]		 = { .type = NLA_U32 },
	[TCA_CAKE_FLOW_MODE] = { .type = NLA_U32 },
};

static void cake_set_rate(struct cake_fqcd_sched_data *fqcd,
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

	fqcd->class_rate_bps  = rate;
	fqcd->class_rate_ns   = rate_ns;
	fqcd->class_rate_shft = rate_shft;

	byte_target_ns = (byte_target * rate_ns) >> rate_shft;

	fqcd->cparams.target = max(byte_target_ns, ns_target);
	fqcd->cparams.interval = max(MS2TIME(100) + fqcd->cparams.target, fqcd->cparams.target * 8);

	if(rate == 0 || rate > 4000000) {
		fqcd->quantum = 1514;
	} else {
		fqcd->quantum = 300;
	}

}

static void cake_config_besteffort(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_fqcd_sched_data *fqcd = &q->classes[0];
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	unsigned int i;

	q->class_cnt = 1;

	for(i=0; i < 64; i++)
		q->class_index[i] = 0;

	cake_set_rate(fqcd, rate, mtu, MS2TIME(5), MS2TIME(100));
	fqcd->class_quantum_band = fqcd->class_quantum_prio = 65535;
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

	q->class_cnt = 8;

	for(i=0; i < 64; i++)
		q->class_index[i] = min((u32)(i >> 3), (u32)(q->class_cnt));

	for(i=0; i < q->class_cnt; i++) {
		struct cake_fqcd_sched_data *fqcd = &q->classes[i];

		cake_set_rate(fqcd, rate, mtu, MS2TIME(5), MS2TIME(100));

		fqcd->class_quantum_prio = max(1U, quantum1);
		fqcd->class_quantum_band = max(1U, quantum2);

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

/*	List of traffic classes in RFC 4594:
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

	Total 12 traffic classes.
 */

static void cake_config_diffserv8(struct Qdisc *sch)
{
	/*	Pruned list of traffic classes for typical applications:

		Network Control          (CS6, CS7)
		Minimum Latency          (EF, VA, CS5, CS4)
		Interactive Shell        (CS2, TOS1)
		Low Latency Transactions (AF2x, TOS4)
		Video Streaming          (AF4x, AF3x, CS3)
		Bog Standard             (CS0 etc.)
		High Throughput          (AF1x, TOS2)
		Background Traffic       (CS1)

		Total 8 traffic classes.
	 */

	struct cake_sched_data *q = qdisc_priv(sch);
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum1 = 256;
	u32 quantum2 = 256;
	u32 i;

	q->class_cnt = 8;

	/* codepoint to class mapping */
	for(i=0; i < 64; i++)
		q->class_index[i] = 2;	/* default to best-effort */

	q->class_index[0x08] = 0;	/* CS1 */
	q->class_index[0x02] = 1;	/* TOS2 */
	q->class_index[0x18] = 3;	/* CS3 */
	q->class_index[0x04] = 4;	/* TOS4 */
	q->class_index[0x01] = 5;	/* TOS1 */
	q->class_index[0x10] = 5;	/* CS2 */
	q->class_index[0x20] = 6;	/* CS4 */
	q->class_index[0x28] = 6;	/* CS5 */
	q->class_index[0x2c] = 6;	/* VA */
	q->class_index[0x2e] = 6;	/* EF */
	q->class_index[0x30] = 7;	/* CS6 */
	q->class_index[0x38] = 7;	/* CS7 */

	for(i=2; i <= 6; i += 2) {
		q->class_index[0x08 + i] = 1;	/* AF1x */
		q->class_index[0x10 + i] = 4;	/* AF2x */
		q->class_index[0x18 + i] = 3;	/* AF3x */
		q->class_index[0x20 + i] = 3;	/* AF4x */
	}

	/* class characteristics */
	for(i=0; i < q->class_cnt; i++) {
		struct cake_fqcd_sched_data *fqcd = &q->classes[i];

		cake_set_rate(fqcd, rate, mtu, MS2TIME(5), MS2TIME(100));

		fqcd->class_quantum_prio = max(1U, quantum1);
		fqcd->class_quantum_band = max(1U, quantum2);

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
	/*  Further pruned list of traffic classes for four-class system:

	    Latency Sensitive  (CS7, CS6, EF, VA, CS5, CS4)
	    Streaming Media    (AF4x, AF3x, CS3, AF2x, TOS4, CS2, TOS1)
	    Best Effort        (CS0, AF1x, TOS2, and all not otherwise specified)
	    Background Traffic (CS1)

		Total 4 traffic classes.
	 */

	struct cake_sched_data *q = qdisc_priv(sch);
	u64 rate = q->rate_bps;
	u32 mtu = psched_mtu(qdisc_dev(sch));
	u32 quantum = 256;
	u32 i;

	q->class_cnt = 4;

	/* codepoint to class mapping */
	for(i=0; i < 64; i++)
		q->class_index[i] = 1;	/* default to best-effort */

	q->class_index[0x08] = 0;	/* CS1 */

	q->class_index[0x18] = 2;	/* CS3 */
	q->class_index[0x04] = 2;	/* TOS4 */
	q->class_index[0x01] = 2;	/* TOS1 */
	q->class_index[0x10] = 2;	/* CS2 */

	q->class_index[0x20] = 3;	/* CS4 */
	q->class_index[0x28] = 3;	/* CS5 */
	q->class_index[0x2c] = 3;	/* VA */
	q->class_index[0x2e] = 3;	/* EF */
	q->class_index[0x30] = 3;	/* CS6 */
	q->class_index[0x38] = 3;	/* CS7 */

	for(i=2; i <= 6; i += 2) {
		q->class_index[0x10 + i] = 2;	/* AF2x */
		q->class_index[0x18 + i] = 2;	/* AF3x */
		q->class_index[0x20 + i] = 2;	/* AF4x */
	}

	/* class characteristics */
	cake_set_rate(&q->classes[0], rate,               mtu, MS2TIME(5), MS2TIME(100));
	cake_set_rate(&q->classes[1], rate - (rate >> 4), mtu, MS2TIME(5), MS2TIME(100));
	cake_set_rate(&q->classes[2], rate - (rate >> 2), mtu, MS2TIME(5), MS2TIME(100));
	cake_set_rate(&q->classes[3], rate >> 2,          mtu, MS2TIME(5), MS2TIME(100));

	/* priority weights */
	q->classes[0].class_quantum_prio = quantum >> 4;
	q->classes[1].class_quantum_prio = quantum;
	q->classes[2].class_quantum_prio = quantum << 2;
	q->classes[3].class_quantum_prio = quantum << 4;
	/* bandwidth-sharing weights */
	q->classes[0].class_quantum_band = (quantum >> 4);
	q->classes[1].class_quantum_band = (quantum >> 3) + (quantum >> 4);
	q->classes[2].class_quantum_band = (quantum >> 1);
	q->classes[3].class_quantum_band = (quantum >> 2);
}

static void cake_reconfigure(struct Qdisc *sch)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int c;

	switch(q->class_mode) {
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

	BUG_ON(CAKE_MAX_CLASSES < q->class_cnt);
	for(c = q->class_cnt; c < CAKE_MAX_CLASSES; c++)
		cake_clear_class(sch, c);

	q->rate_ns   = q->classes[0].class_rate_ns;
	q->rate_shft = q->classes[0].class_rate_shft;

	if(q->rate_bps)
	{
		u64 t = q->rate_bps * q->classes[0].cparams.interval;
		do_div(t, NSEC_PER_SEC / 4);
		q->buffer_limit = t;

		if(q->buffer_limit < 65536)
			q->buffer_limit = 65536;
	} else {
		q->buffer_limit = 1 << 20;
	}

	if(q->buffer_limit > sch->limit * psched_mtu(qdisc_dev(sch)))
		q->buffer_limit = sch->limit * psched_mtu(qdisc_dev(sch));
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
		q->class_mode = nla_get_u32(tb[TCA_CAKE_DIFFSERV_MODE]);

	if(tb[TCA_CAKE_ATM]) {
		if(!!nla_get_u32(tb[TCA_CAKE_ATM]))
			q->rate_flags |= CAKE_FLAG_ATM;
		else
			q->rate_flags &= ~CAKE_FLAG_ATM;
	}

	if(tb[TCA_CAKE_FLOW_MODE])
		q->flow_mode = nla_get_u32(tb[TCA_CAKE_FLOW_MODE]);

	if(q->classes) {
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

	if(q->classes) {
		u32 i;
		for(i=0; i < CAKE_MAX_CLASSES; i++) {
			cake_free(q->classes[i].tags);
			cake_free(q->classes[i].backlogs);
			cake_free(q->classes[i].flows);
		}
		cake_free(q->classes);
	}
}

static int cake_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	int i,j;

	codel_cache_init();

	sch->limit = 10240;
	q->class_mode = CAKE_MODE_DIFFSERV4;
	q->flow_mode  = CAKE_FLOW_ALL;

	q->rate_bps = 0; /* unlimited by default */

	q->cur_class = 0;
	q->cur_flow  = 0;

	if(opt) {
		int err = cake_change(sch, opt);
		if(err)
			return err;
	}

	qdisc_watchdog_init(&q->watchdog, sch);

	q->classes = cake_zalloc(CAKE_MAX_CLASSES * sizeof(struct cake_fqcd_sched_data));
	if(!q->classes)
		goto nomem;

	for(i=0; i < CAKE_MAX_CLASSES; i++) {
		struct cake_fqcd_sched_data *fqcd = q->classes + i;

		fqcd->flows_cnt = 1024;
		fqcd->perturbation = prandom_u32();
		INIT_LIST_HEAD(&fqcd->new_flows);
		INIT_LIST_HEAD(&fqcd->old_flows);
		/* codel_params_init(&fqcd->cparams); */

		fqcd->flows    = cake_zalloc(fqcd->flows_cnt * sizeof(struct cake_fqcd_flow));
		fqcd->backlogs = cake_zalloc(fqcd->flows_cnt * sizeof(u32));
		fqcd->tags     = cake_zalloc(fqcd->flows_cnt * sizeof(u32));
		if(!fqcd->flows || !fqcd->backlogs || !fqcd->tags)
			goto nomem;

		for(j=0; j < fqcd->flows_cnt; j++) {
			struct cake_fqcd_flow *flow = fqcd->flows + j;

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

	if(nla_put_u32(skb, TCA_CAKE_DIFFSERV_MODE, q->class_mode))
		goto nla_put_failure;

	if(nla_put_u32(skb, TCA_CAKE_ATM, !!(q->rate_flags & CAKE_FLAG_ATM)))
		goto nla_put_failure;

	if(nla_put_u32(skb, TCA_CAKE_FLOW_MODE, q->flow_mode))
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

	BUG_ON(q->class_cnt > (sizeof(st->cls) / sizeof(st->cls[0])));

	st->type = 0xCAFE;
	st->class_cnt = q->class_cnt;

	for(i=0; i < q->class_cnt; i++) {
		struct cake_fqcd_sched_data *fqcd = &q->classes[i];

		st->cls[i].rate          = fqcd->class_rate_bps;
		st->cls[i].target_us     = codel_time_to_us(fqcd->cparams.target);
		st->cls[i].interval_us   = codel_time_to_us(fqcd->cparams.interval);
		st->cls[i].packets       = fqcd->packets;
		st->cls[i].bytes         = fqcd->bytes;
		st->cls[i].dropped       = fqcd->class_dropped;
		st->cls[i].ecn_marked    = fqcd->class_ecn_mark;
		st->cls[i].backlog_bytes = fqcd->class_backlog;

		st->cls[i].peak_delay = codel_time_to_us(fqcd->peak_delay);
		st->cls[i].avge_delay = codel_time_to_us(fqcd->avge_delay);
		st->cls[i].base_delay = codel_time_to_us(fqcd->base_delay);

		st->cls[i].way_indirect_hits = fqcd->way_hits;
		st->cls[i].way_misses        = fqcd->way_misses;
		st->cls[i].way_collisions    = fqcd->way_collisions;
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

static int cake_dump_class(struct Qdisc *sch, unsigned long cl, struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int cake_dump_class_stats(struct Qdisc *sch, unsigned long cl, struct gnet_dump *d)
{
	/* reuse fq_codel stats format */
	struct cake_sched_data *q = qdisc_priv(sch);
	struct cake_fqcd_sched_data *fqcd = q->classes;
	u32 cls=0, idx=cl-1;
	struct gnet_stats_queue qs = {0};
	struct tc_fq_codel_xstats xstats;

	while(cls < q->class_cnt && idx >= fqcd->flows_cnt) {
		idx -= fqcd->flows_cnt;
		cls++;
		fqcd++;
	}

	if(cls < q->class_cnt && idx >= fqcd->flows_cnt) {
		const struct cake_fqcd_flow *flow = &fqcd->flows[idx];
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
	if(cls < q->class_cnt && idx >= fqcd->flows_cnt)
		return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
	return 0;
}

static void cake_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct cake_sched_data *q = qdisc_priv(sch);
	unsigned int i,j,k;

	if(arg->stop)
		return;

	for(j=k=0; j < q->class_cnt; j++) {
		struct cake_fqcd_sched_data *fqcd = &q->classes[j];

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
	.dump		=	cake_dump_class,
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
