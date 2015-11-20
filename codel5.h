#ifndef __NET_SCHED_CODEL_H
#define __NET_SCHED_CODEL_H

/*
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012 Eric Dumazet <edumazet@google.com>
 *  Copyright (C) 2015 Jonathan Morton <chromatix99@gmail.com>
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

#include <linux/version.h>
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <linux/reciprocal_div.h>

/* Controlling Queue Delay (CoDel) algorithm
 * =========================================
 * Source : Kathleen Nichols and Van Jacobson
 * http://queue.acm.org/detail.cfm?id=2209336
 *
 * Implemented on linux by Dave Taht and Eric Dumazet
 */

/* Backport some stuff if needed.
 */
#if KERNEL_VERSION(3, 14, 0) > LINUX_VERSION_CODE

static inline u32 reciprocal_scale(u32 val, u32 ep_ro)
{
	return (u32)(((u64) val * ep_ro) >> 32);
}

#endif

#if KERNEL_VERSION(3, 15, 0) > LINUX_VERSION_CODE

static inline void kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}

#endif

#if KERNEL_VERSION(3, 17, 0) > LINUX_VERSION_CODE

#define ktime_get_ns() ktime_to_ns(ktime_get())

#endif

#if KERNEL_VERSION(3, 18, 0) > LINUX_VERSION_CODE
static inline void qdisc_qstats_backlog_dec(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog -= qdisc_pkt_len(skb);
}

static inline void qdisc_qstats_backlog_inc(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog += qdisc_pkt_len(skb);
}

static inline void __qdisc_qstats_drop(struct Qdisc *sch, int count)
{
	sch->qstats.drops += count;
}

static inline void qdisc_qstats_drop(struct Qdisc *sch)
{
	sch->qstats.drops++;
}

#define codel_stats_copy_queue(a, b, c, d) gnet_stats_copy_queue(a, c)
#define codel_watchdog_schedule_ns(a, b, c) qdisc_watchdog_schedule_ns(a, b)
#else
#define codel_stats_copy_queue(a, b, c, d) gnet_stats_copy_queue(a, b, c, d)
#define codel_watchdog_schedule_ns(a, b, c) qdisc_watchdog_schedule_ns(a, b, c)
#endif


/* CoDel5 uses a real clock, unlike codel */

typedef u64 codel_time_t;
typedef s64 codel_tdiff_t;

#define MS2TIME(a) (a * (u64) NSEC_PER_MSEC)
#define US2TIME(a) (a * (u64) NSEC_PER_USEC)

static inline codel_time_t codel_get_time(void)
{
	return ktime_get_ns();
}

/* Qdiscs using codel plugin must use codel_skb_cb in their own cb[] */
struct codel_skb_cb {
	codel_time_t enqueue_time;
};

static struct codel_skb_cb *get_codel_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct codel_skb_cb));
	return (struct codel_skb_cb *)qdisc_skb_cb(skb)->data;
}

static codel_time_t codel_get_enqueue_time(const struct sk_buff *skb)
{
	return get_codel_cb(skb)->enqueue_time;
}

static inline u32 codel_time_to_us(codel_time_t val)
{
	do_div(val, NSEC_PER_USEC);
	return (u32)val;
}

/*
 * struct codel_params - contains codel parameters
 * @interval:	initial drop rate
 * @target:     maximum persistent sojourn time
 * @threshold:	tolerance for product of sojourn time and time above target
 */
struct codel_params {
	codel_time_t	interval;
	codel_time_t	target;
	codel_time_t	threshold;
};

/**
 * struct codel_vars - contains codel variables
 * @count:		how many drops we've done since the last time we
 *			entered dropping state
 * @dropping:		set to > 0 if in dropping state
 * @rec_inv_sqrt:	reciprocal value of sqrt(count) >> 1
 * @first_above_time:	when we went (or will go) continuously above target
 *			for interval
 * @drop_next:		time to drop next packet, or when we dropped last
 * @drop_count:	temp count of dropped packets in dequeue()
 * @ecn_mark:	number of packets we ECN marked instead of dropping
 */

struct codel_vars {
	u32		count;
	u16		dropping;
	u16		rec_inv_sqrt;
	codel_time_t	first_above_time;
	codel_time_t	drop_next;
	u16		drop_count;
	u16		ecn_mark;
};
/* sizeof_in_bits(rec_inv_sqrt) */
#define REC_INV_SQRT_BITS (8 * sizeof(u16))
/* needed shift to get a Q0.32 number from rec_inv_sqrt */
#define REC_INV_SQRT_SHIFT (32 - REC_INV_SQRT_BITS)
#define REC_INV_SQRT_CACHE (16)

/* Newton approximation method needs more iterations at small inputs,
 * so cache them.
 */

static u16 codel_rec_inv_sqrt_cache[REC_INV_SQRT_CACHE] = {0};

static void codel_vars_init(struct codel_vars *vars)
{
	memset(vars, 0, sizeof(*vars));
}

/*
 * http://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Iterative_methods_for_reciprocal_square_roots
 * new_invsqrt = (invsqrt / 2) * (3 - count * invsqrt^2)
 *
 * Here, invsqrt is a fixed point number (< 1.0), 32bit mantissa, aka Q0.32
 */
static void codel_Newton_step(struct codel_vars *vars)
{
	if (vars->count < REC_INV_SQRT_CACHE &&
	   codel_rec_inv_sqrt_cache[vars->count]) {
		vars->rec_inv_sqrt = codel_rec_inv_sqrt_cache[vars->count];
	} else {
		u32 invsqrt = ((u32)vars->rec_inv_sqrt) << REC_INV_SQRT_SHIFT;
		u32 invsqrt2 = ((u64)invsqrt * invsqrt) >> 32;
		u64 val = (3LL << 32) - ((u64)vars->count * invsqrt2);

		val >>= 2; /* avoid overflow in following multiply */
		val = (val * invsqrt) >> (32 - 2 + 1);

		vars->rec_inv_sqrt = val >> REC_INV_SQRT_SHIFT;
	}
}

static void codel_cache_init(void)
{
	struct codel_vars v;

	codel_vars_init(&v);
	v.rec_inv_sqrt = ~0U >> REC_INV_SQRT_SHIFT;
	codel_rec_inv_sqrt_cache[0] = v.rec_inv_sqrt;

	for (v.count = 1; v.count < REC_INV_SQRT_CACHE; v.count++) {
		codel_Newton_step(&v);
		codel_Newton_step(&v);
		codel_Newton_step(&v);
		codel_Newton_step(&v);

		codel_rec_inv_sqrt_cache[v.count] = v.rec_inv_sqrt;
	}
}

/*
 * CoDel control_law is t + interval/sqrt(count)
 * We maintain in rec_inv_sqrt the reciprocal value of sqrt(count) to avoid
 * both sqrt() and divide operation.
 */
static codel_time_t codel_control_law(codel_time_t t,
				      codel_time_t interval,
				      u32 rec_inv_sqrt)
{
	return t + reciprocal_scale(interval, rec_inv_sqrt <<
				    REC_INV_SQRT_SHIFT);
}


static bool codel_should_drop(const struct sk_buff *skb,
			      struct Qdisc *sch,
			      struct codel_vars *vars,
			      codel_time_t interval,
			      codel_time_t target,
			      codel_time_t threshold,
			      codel_time_t now)
{
	if (!skb) {
		vars->first_above_time = 0;
		return false;
	}

	sch->qstats.backlog -= qdisc_pkt_len(skb);

	if (now - codel_get_enqueue_time(skb) < target ||
	    !sch->qstats.backlog) {
		/* went below - stay below for at least interval */
		vars->first_above_time = 0;
		return false;
	} else if (vars->dropping) {
		return true;
	}

	if (vars->first_above_time == 0) {
		/* just went above from below; mark the time */
		vars->first_above_time = now;

	} else if (vars->count > 1 && now - vars->drop_next < 8 * interval) {
		/* we were recently dropping; be more aggressive */
		return now > codel_control_law(
						vars->first_above_time,
						interval,
						vars->rec_inv_sqrt);
	} else if (((now - vars->first_above_time) >> 15) *
		   ((now - codel_get_enqueue_time(skb)) >> 15) > threshold) {
		return true;
	}

	return false;
}

/* Forward declaration of this for use elsewhere */

static inline struct sk_buff *custom_dequeue(struct codel_vars *vars,
					     struct Qdisc *sch);

static struct sk_buff *codel_dequeue(struct Qdisc *sch,
				     struct codel_vars *vars,
				     codel_time_t interval,
				     codel_time_t target,
				     codel_time_t threshold,
				     bool overloaded)
{
	struct sk_buff *skb = custom_dequeue(vars, sch);
	codel_time_t now;
	bool drop;

	if (!skb) {
		vars->dropping = false;
		return skb;
	}
	now = codel_get_time();
	drop = codel_should_drop(skb, sch, vars, interval, target, threshold,
				 now);
	if (vars->dropping) {
		if (!drop) {
			/* sojourn time below target - leave dropping state */
			vars->dropping = false;
		} else if (now >= vars->drop_next) {
			/* It's time for the next drop. Drop the current
			 * packet and dequeue the next. The dequeue might
			 * take us out of dropping state.
			 * If not, schedule the next drop.
			 * A large backlog might result in drop rates so high
			 * that the next drop should happen now,
			 * hence the while loop.
			 */

			/* saturating increment */
			vars->count++;
			if (!vars->count)
				vars->count--;

			codel_Newton_step(vars);
			vars->drop_next = codel_control_law(vars->drop_next,
							    interval,
							    vars->rec_inv_sqrt);
			do {
				if (INET_ECN_set_ce(skb) && !overloaded) {
					vars->ecn_mark++;
					/* and schedule the next drop */
					vars->drop_next = codel_control_law(
						vars->drop_next, interval,
						vars->rec_inv_sqrt);
					goto end;
				}
				qdisc_drop(skb, sch);
				vars->drop_count++;
				skb = custom_dequeue(vars, sch);
				if (skb && !codel_should_drop(skb, sch, vars,
							      interval,
							      target,
							      threshold,
							      now)) {
					/* leave dropping state */
					vars->dropping = false;
				} else {
					/* schedule the next drop */
					vars->drop_next = codel_control_law(vars->drop_next,
								  interval, vars->rec_inv_sqrt);
				}
			} while (skb && vars->dropping && now >=
				 vars->drop_next);

			/* Mark the packet regardless */
			if (skb && INET_ECN_set_ce(skb))
				vars->ecn_mark++;
		}
	} else if (drop) {
		if (INET_ECN_set_ce(skb) && !overloaded) {
			vars->ecn_mark++;
		} else {
			qdisc_drop(skb, sch);
			vars->drop_count++;

			skb = custom_dequeue(vars, sch);
			drop = codel_should_drop(skb, sch, vars,
						 interval, target,
						 threshold, now);
			if (skb && INET_ECN_set_ce(skb))
				vars->ecn_mark++;
		}
		vars->dropping = true;
		/* if min went above target close to when we last went below
		 * assume that the drop rate that controlled the queue on the
		 * last cycle is a good starting point to control it now.
		 */
		if (vars->count > 2 &&
		    now - vars->drop_next < 8 * interval) {
			/* when count is halved, time interval is
			 * multiplied by 1.414...
			 */
			vars->count /= 2;
			vars->rec_inv_sqrt = (vars->rec_inv_sqrt * 92682) >>
			  16;
		} else {
			vars->count = 1;
			vars->rec_inv_sqrt = ~0U >> REC_INV_SQRT_SHIFT;
		}
		codel_Newton_step(vars);
		vars->drop_next = codel_control_law(now, interval,
						    vars->rec_inv_sqrt);
	}
end:
	return skb;
}
#endif
