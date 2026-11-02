#include <tn/timer.h>

#if defined(CONFIG_LIBTNTRACE_FORMAT)
void tn_trace_uk_semaphore_up_enter_format(struct uk_semaphore *semaphore)
{
	printf("%s: %p\n", __func__, semaphore);
}

void tn_trace_uk_semaphore_up_exit_format(struct uk_semaphore *semaphore)
{
	printf("%s: %p\n", __func__, semaphore);
}

void tn_trace_uk_semaphore_down_enter_format(struct uk_semaphore *semaphore)
{
	printf("%s: %p\n", __func__, semaphore);
}

void tn_trace_uk_semaphore_down_exit_format(struct uk_semaphore *semaphore)
{
	printf("%s: %p\n", __func__, semaphore);
}

void tn_trace_uk_semaphore_down_try_enter_format(struct uk_semaphore *semaphore)
{
	printf("%s: %p\n", __func__, semaphore);
}

void tn_trace_uk_semaphore_down_try_exit_format(struct uk_semaphore *semaphore,
								int ret)
{
	printf("%s: %p %d\n", __func__, semaphore, ret);
}

void tn_trace_uk_semaphore_down_to_enter_format(struct uk_semaphore *semaphore,
								__nsec timeout)
{
	printf("%s: %p %lu\n", __func__, semaphore, timeout);
}

void tn_trace_uk_semaphore_down_to_exit_format(struct uk_semaphore *semaphore,
								__nsec timeout)
{
	printf("%s: %p %lu\n", __func__, semaphore, timeout);
}

void tn_trace_uk_mutex_lock_enter_format(struct uk_mutex *mutex)
{
	printf("%s: %p\n", __func__, mutex);
}

void tn_trace_uk_mutex_lock_exit_format(struct uk_mutex *mutex)
{
	printf("%s: %p\n", __func__, mutex);
}

void tn_trace_uk_mutex_trylock_enter_format(struct uk_mutex *mutex)
{
	printf("%s: %p\n", __func__, mutex);
}

void tn_trace_uk_mutex_trylock_exit_format(struct uk_mutex *mutex)
{
	printf("%s: %p\n", __func__, mutex);
}

void tn_trace_uk_mutex_unlock_enter_format(struct uk_mutex *mutex)
{
	printf("%s: %p\n", __func__, mutex);
}

void tn_trace_uk_mutex_unlock_exit_format(struct uk_mutex *mutex)
{
	printf("%s: %p\n", __func__, mutex);
}

#elif defined(CONFIG_LIBTNTRACE_CUSTOM)

void __weak tn_trace_uk_semaphore_up_enter_custom(
	struct uk_semaphore *semaphore)
{}
void __weak tn_trace_uk_semaphore_up_exit_custom(
	struct uk_semaphore *semaphore)
{}
void __weak tn_trace_uk_semaphore_down_enter_custom(
	struct uk_semaphore *semaphore)
{}
void __weak tn_trace_uk_semaphore_down_exit_custom(
	struct uk_semaphore *semaphore)
{}
void __weak tn_trace_uk_semaphore_down_try_enter_custom(
	struct uk_semaphore *semaphore)
{}
void __weak tn_trace_uk_semaphore_down_try_exit_custom(
	struct uk_semaphore *semaphore, int ret)
{}
void __weak tn_trace_uk_semaphore_down_to_enter_custom(
	struct uk_semaphore *semaphore, __nsec timeout)
{}
void __weak tn_trace_uk_semaphore_down_to_exit_custom(
	struct uk_semaphore *semaphore, __nsec timeout)
{}
void __weak tn_trace_uk_mutex_lock_enter_custom(struct uk_mutex *mutex) {}
void __weak tn_trace_uk_mutex_lock_exit_custom(struct uk_mutex *mutex) {}
void __weak tn_trace_uk_mutex_trylock_enter_custom(struct uk_mutex *mutex) {}
void __weak tn_trace_uk_mutex_trylock_exit_custom(struct uk_mutex *mutex) {}
void __weak tn_trace_uk_mutex_unlock_enter_custom(struct uk_mutex *mutex) {}
void __weak tn_trace_uk_mutex_unlock_exit_custom(struct uk_mutex *mutex) {}

#endif /* CONFIG_LIBTNTRACE_CUSTOM */
