/* SPDX-License-Identifier: MIT */
/*
 * Authors: Grzegorz Milos
 *          Robert Kaiser
 *          Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2005, Intel Research Cambridge
 * Copyright (c) 2017, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
/*
 * The scheduler is non-preemptive (cooperative), and schedules according
 * to Round Robin algorithm.
 */
#include "schedcoop.h"

#include <tn/systick.h>
#include <uk/essentials.h>
#include <uk/plat/config.h>
#include <uk/plat/lcpu.h>
#include <uk/plat/memory.h>
#include <uk/plat/time.h>
#include <uk/sched_impl.h>
#include <uk/schedcoop.h>
#include <uk/thread.h>

static struct schedcoop *c;

static inline struct uk_thread *tn_schedcoop_select_next(struct uk_thread *prev)
{
	struct uk_thread *next;
	struct lcpu		 *this_lcpu;

	this_lcpu = lcpu_get_current();

	next = UK_TAILQ_FIRST(&c->run_queue);

	if (next)
		return next;
	if (prev && uk_thread_is_runnable(prev))
		return prev;

	return this_lcpu->idle_thread;
}

static inline void tn_schedcoop_update_queue_and_switch(struct uk_thread *prev,
														struct uk_thread *next,
														bool irq_flag)
{
	struct lcpu *this_lcpu = lcpu_get_current();

	UK_ASSERT(next);
	UK_ASSERT(uk_thread_is_runnable(next));

	if (next != this_lcpu->idle_thread)
		UK_TAILQ_REMOVE(&c->run_queue, next, queue);

	/* Put previous thread on the end of the list */
	if (prev && (prev != this_lcpu->idle_thread) && uk_thread_is_runnable(prev))
		UK_TAILQ_INSERT_TAIL(&c->run_queue, prev, queue);

	uk_thread_ctx_switch(prev, next, irq_flag);
}

static inline void schedcoop_schedule(bool yield)
{
	struct uk_thread *prev, *next;
	__snsec now;
	unsigned long flags;

	now	 = ukplat_monotonic_clock();
	prev = uk_thread_current();

	if (!yield && prev && uk_thread_is_runnable(prev))
		return;

	flags = ukplat_lcpu_save_irqf();

	/* Update execution time of current thread */
	if (prev)
		prev->exec_time += now - c->ts_prev_switch;

	c->ts_prev_switch = now;

	next = tn_schedcoop_select_next(prev);
	if (next != prev)
		tn_schedcoop_update_queue_and_switch(prev, next, false);
	ukplat_lcpu_restore_irqf(flags);
}

static void schedcoop_reschedule(void)
{
	schedcoop_schedule(false);
}

static void schedcoop_yield(void)
{
	schedcoop_schedule(true);
}

static int schedcoop_thread_add(struct uk_thread *t)
{
	UK_ASSERT(t);
	UK_ASSERT(!uk_thread_is_exited(t));

	/* Add to run queue if runnable */
	if (uk_thread_is_runnable(t) && t != uk_thread_current())
		UK_TAILQ_INSERT_TAIL(&c->run_queue, t, queue);

	return 0;
}

static void schedcoop_thread_remove(struct uk_thread *t)
{
	/* Remove from run_queue */
	if (t != uk_thread_current()
	    && uk_thread_is_runnable(t))
		UK_TAILQ_REMOVE(&c->run_queue, t, queue);
}

static void schedcoop_thread_blocked(struct uk_thread *t)
{
	UK_ASSERT(ukplat_lcpu_irqs_disabled());

	if (t != uk_thread_current())
		UK_TAILQ_REMOVE(&c->run_queue, t, queue);
}

static void schedcoop_start(void)
{
	/* Since we are now starting to schedule, we save the current timestamp
	 * as the start time for the first time slice.
	 */
	c->ts_prev_switch = ukplat_monotonic_clock();

	return;
}

static void schedcoop_thread_woken_isr(struct uk_thread *t)
{
	UK_ASSERT(ukplat_lcpu_irqs_disabled());

	if (uk_thread_is_runnable(t) && t != uk_thread_current())
		UK_TAILQ_INSERT_TAIL(&c->run_queue, t, queue);
}

struct uk_sched *uk_schedcoop_create(struct uk_alloc *a)
{
	uk_pr_info("Initializing cooperative scheduler\n");
	c = uk_zalloc(a, sizeof(struct schedcoop));
	if (!c)
		return NULL;

	UK_TAILQ_INIT(&c->run_queue);

	uk_sched_init(&c->sched, schedcoop_start, schedcoop_yield,
				  schedcoop_reschedule, schedcoop_thread_add,
				  schedcoop_thread_remove, schedcoop_thread_blocked,
				  schedcoop_thread_woken_isr, schedcoop_thread_woken_isr,
				  schedcoop_prio_cmp, tn_schedcoop_select_next,
				  tn_schedcoop_update_queue_and_switch, a);

	return &c->sched;
}
