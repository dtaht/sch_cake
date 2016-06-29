#ifndef __NET_SCHED_COBALT_H
#define __NET_SCHED_COBALT_H

/*
 * COBALT - Codel-BLUE Alternate AQM algorithm.
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Eric Dumazet <edumazet@google.com>
 *  Copyright (C) 2016 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (c) 2015-2016 Jonathan Morton <chromatix99@gmail.com>
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
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <linux/reciprocal_div.h>

typedef u64 cobalt_time_t;
typedef s64 cobalt_tdiff_t;

#define MS2TIME(a) (a * (u64) NSEC_PER_MSEC)
#define US2TIME(a) (a * (u64) NSEC_PER_USEC)

#define codel_stats_copy_queue(a, b, c, d) gnet_stats_copy_queue(a, b, c, d)
#define codel_watchdog_schedule_ns(a, b, c) qdisc_watchdog_schedule_ns(a, b, c)

static inline cobalt_time_t cobalt_get_time(void)
{
	return ktime_get_ns();
}

static inline u32 cobalt_time_to_us(cobalt_time_t val)
{
	do_div(val, NSEC_PER_USEC);
	return (u32)val;
}

struct cobalt_skb_cb {
	cobalt_time_t enqueue_time;
};

/**
 * struct cobalt_params - contains codel and blue parameters
 * @interval:	codel initial drop rate
 * @target:     maximum persistent sojourn time & blue update rate
 * @threshold:	tolerance for product of sojourn time and time above target
 * @p_inc:      increment of blue drop probability (0.32 fxp)
 * @p_dec:      decrement of blue drop probability (0.32 fxp)
 */
struct cobalt_params {
	cobalt_time_t	interval;
	cobalt_time_t	target;
	u32          	p_inc;
	u32          	p_dec;
};

/**
 * struct cobalt_vars - contains codel and blue variables
 * @count:		  dropping frequency
 * @rec_inv_sqrt: reciprocal value of sqrt(count) >> 1
 * @drop_next:    time to drop next packet, or when we dropped last
 * @drop_count:	  temp count of dropped packets in dequeue()
 * @ecn_mark:     number of packets we ECN marked instead of dropping
 * @p_drop:       BLUE drop probability (0.32 fxp)
 * @dropping:     set if in dropping state
 */
struct cobalt_vars {
	u32		count;
	u32		rec_inv_sqrt;
	cobalt_time_t	drop_next;
	cobalt_time_t	blue_timer;
	u32     p_drop;
	bool	dropping;
	bool    ecn_marked;
};

/* Initialise visible and internal data. */
void cobalt_vars_init(struct cobalt_vars *vars);

struct cobalt_skb_cb *get_cobalt_cb(const struct sk_buff *skb);
cobalt_time_t cobalt_get_enqueue_time(const struct sk_buff *skb);

/* Call this when a packet had to be dropped due to queue overflow. */
bool cobalt_queue_full(struct cobalt_vars *vars, struct cobalt_params *p, cobalt_time_t now);

/* Call this when the queue was serviced but turned out to be empty. */
bool cobalt_queue_empty(struct cobalt_vars *vars, struct cobalt_params *p, cobalt_time_t now);

/* Call this with a freshly dequeued packet for possible congestion marking.
 * Returns true as an instruction to drop the packet, false for delivery.
 */
bool cobalt_should_drop(struct cobalt_vars *vars,
	struct cobalt_params *p,
	cobalt_time_t now,
	struct sk_buff *skb);

#endif
