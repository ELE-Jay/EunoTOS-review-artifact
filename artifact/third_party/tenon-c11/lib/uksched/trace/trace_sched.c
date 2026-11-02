#include <uk/plat/time.h>
#include <uk/sched.h>

#if defined(CONFIG_LIBTNTRACE_FORMAT)
void tn_trace_uk_thread_wake_format(struct uk_thread *thread)
{
	printf("%s: %p\n", __func__, thread);
}

void tn_trace_uk_thread_yield_format(struct uk_thread *current)
{
	printf("%s: %p\n", __func__, current);
}

void tn_trace_uk_thread_switch_format(struct uk_thread *next)
{
	struct uk_thread *thread = uk_thread_current();

	printf("%s: switch from %p to %p\n", __func__, thread, next);
}

void tn_trace_uk_thread_switch_exit_format(void)
{
	struct uk_thread *thread = uk_thread_current();

	printf("%s: %p\n", __func__, thread);
}

void tn_trace_uk_thread_set_priority_format(
	struct uk_thread *thread, int32_t priority)
{
	printf("%s: %p %d\n", __func__, thread, priority);
}

void tn_trace_uk_thread_exit_enter_format(struct uk_thread *thread)
{
	printf("%s: %p\n", __func__, thread);
}

void tn_trace_uk_thread_exit_exit_format(struct uk_thread *thread)
{
	printf("%s: %p\n", __func__, thread);
}

void tn_trace_uk_thread_sleep_ns_format(struct uk_thread *thread, __nsec nsec)
{
	printf("%s: %p %lu\n", __func__, thread, nsec);
}

void tn_trace_uk_thread_sleep_tick_format(
	struct uk_thread *thread, systick_t tick)
{
	printf("%s: %p %llu\n", __func__, thread, tick);
}

void tn_trace_uk_thread_add_format(struct uk_thread *thread)
{
	printf("%s: %p\n", __func__, thread);
}

void tn_trace_uk_thread_remove_enter_format(struct uk_thread *thread)
{
	printf("%s: %p\n", __func__, thread);
}

void tn_trace_uk_thread_remove_exit_format(struct uk_thread *thread)
{
	printf("%s: %p\n", __func__, thread);
}

#elif defined(CONFIG_LIBTNTRACE_CUSTOM)

void __weak tn_trace_uk_thread_wake_custom(struct uk_thread *thread) {}
void __weak tn_trace_uk_thread_yield_custom(struct uk_thread *current) {}
void __weak tn_trace_uk_thread_switch_custom(struct uk_thread *next) {}
void __weak tn_trace_uk_thread_set_priority_custom(
	struct uk_thread *thread, int32_t priority)
{}
void __weak tn_trace_uk_thread_exit_enter_custom(struct uk_thread *thread) {}
void __weak tn_trace_uk_thread_exit_exit_custom(struct uk_thread *thread) {}
void __weak tn_trace_uk_thread_sleep_ns_custom(
	struct uk_thread *thread, __nsec nsec)
{}
void __weak tn_trace_uk_thread_sleep_tick_custom(
	struct uk_thread *thread, systick_t tick)
{}
void __weak tn_trace_uk_thread_add_custom(struct uk_thread *thread) {}
void __weak tn_trace_uk_thread_remove_enter_custom(struct uk_thread *thread) {}
void __weak tn_trace_uk_thread_remove_exit_custom(struct uk_thread *thread) {}

#endif /* CONFIG_LIBTNTRACE_CUSTOM */
