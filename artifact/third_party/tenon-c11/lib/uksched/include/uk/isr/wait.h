/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */
#ifndef __UK_SCHED_WAIT_ISR_H__
#define __UK_SCHED_WAIT_ISR_H__

#include <uk/isr/thread.h>
#include <uk/wait.h>
#include <uk/isr/sched.h>

/* ISR variant of `uk_waitq_wake_up()` */
static inline void uk_waitq_wake_up_isr(struct uk_waitq *wq)
{
	struct uk_waitq_entry *curr, *tmp;
	unsigned long flags;

	ukplat_spin_lock_irqsave(&wq->sl, flags);
	_waitq_foreach_safe(curr, &wq->wait_list, thread_list, tmp)
		uk_sched_thread_woken_isr(curr->thread);
	ukplat_spin_unlock_irqrestore(&wq->sl, flags);

	// TODO: Uncomment the following line when scheduler know whether in isr
	// context.
	// uk_sched_reschedule();
}

#endif /* __UK_SCHED_WAIT_ISR_H__ */
