/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */
#ifndef __UK_SCHED_THREAD_ISR_H__
#define __UK_SCHED_THREAD_ISR_H__

#include <uk/thread.h>

/* ISR variant of Macro `uk_thread_wake()`
 * to wake a thread as long as it is not runnable
 * @param thread
 *   Thread that is blocked
 */
#define uk_thread_wake_isr(thread) \
do { \
	TN_TRACE_OBJ_FUNC(uk_thread, wake, thread);		\
	if (!uk_thread_is_runnable(thread))			\
		uk_thread_set_runnable(thread);			\
} while (0)

#endif /* __UK_SCHED_THREAD_ISR_H__ */
