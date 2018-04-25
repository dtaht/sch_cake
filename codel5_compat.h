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
#endif

#if KERNEL_VERSION(4, 1, 0) > LINUX_VERSION_CODE
#define IS_REACHABLE(option) (config_enabled(option) || \
		 (config_enabled(option##_MODULE) && config_enabled(MODULE)))
#endif

#if KERNEL_VERSION(4, 7, 0) > LINUX_VERSION_CODE
#define nla_put_u64_64bit(skb, attrtype, value, padattr) nla_put_u64(skb, attrtype, value)
#endif
