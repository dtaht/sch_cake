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

#endif

#if !defined(IS_REACHABLE)
#define IS_REACHABLE(option) (IS_BUILTIN(option) ||	\
				(IS_MODULE(option) && __is_defined(MODULE)))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static void *kvzalloc(size_t sz, gfp_t flags)
{
	void *ptr = kzalloc(sz, flags);

	if (!ptr)
		ptr = vzalloc(sz);
	return ptr;
}
#endif
