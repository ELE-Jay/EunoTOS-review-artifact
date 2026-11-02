#include <tn/timer.h>

#if defined(CONFIG_LIBTNTRACE_FORMAT)
void tn_trace_timer_delete_format(struct timer *timer)
{
	printf("%s: %p\n", __func__, timer);
}

void tn_trace_timer_start_format(struct timer *timer)
{
	printf("%s: %p\n", __func__, timer);
}

#elif defined(CONFIG_LIBTNTRACE_CUSTOM)

void __weak tn_trace_timer_delete_custom(struct timer *timer) {}
void __weak tn_trace_timer_start_custom(struct timer *timer) {}

#endif /* CONFIG_LIBTNTRACE_CUSTOM */
