/* Copyright 2023 Hangzhou Yingyi Technology Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "schedprio.h"

#include <tn/schedprio.h>
#include <tn/systick.h>
#include <uk/essentials.h>
#include <uk/plat/config.h>
#include <uk/plat/lcpu.h>
#include <uk/plat/memory.h>
#include <uk/plat/time.h>
#include <uk/sched_impl.h>
#include <uk/thread.h>

static struct schedprio *c;

static inline struct uk_thread *tn_schedprio_select_next(struct uk_thread *prev)
{
	struct uk_thread *next;
	struct lcpu		 *this_lcpu;
	bool			  prev_is_runnable;

	this_lcpu		 = lcpu_get_current();
	next			 = _runq_best(c);
	prev_is_runnable = prev && uk_thread_is_runnable(prev);

	if (next && prev_is_runnable) {
#ifdef CONFIG_LIBTNSCHEDPRIO_ENABLE_PREEMTIVE
		return (schedprio_prio_cmp(prev, next) <= 0) ? next : prev;
#else
		return (schedprio_prio_cmp(prev, next) < 0) ? next : prev;
#endif
	} else if (!next) {
		return prev_is_runnable ? prev : this_lcpu->idle_thread;
	} else
		return next;
}

static inline void tn_schedprio_update_queue_and_switch(struct uk_thread *prev,
														struct uk_thread *next,
														bool irq_flag)
{
	/* We do not put idle thread of the lcpu into the queue */
	if (prev && uk_thread_is_runnable(prev) &&
		prev != lcpu_get_current()->idle_thread) {
		_runq_add(c, prev);
	}

	if (next != lcpu_get_current()->idle_thread)
		_runq_remove(c, next);

	uk_thread_ctx_switch(prev, next, irq_flag);
}

static inline void schedprio_schedule(bool yield __unused)
{
	struct uk_thread *prev, *next;
	unsigned long	  flags;

	prev = uk_thread_current();

	flags = ukplat_lcpu_save_irqf();
	next  = tn_schedprio_select_next(prev);
	if (next != prev)
		tn_schedprio_update_queue_and_switch(prev, next, false);
	ukplat_lcpu_restore_irqf(flags);
}

static void schedprio_yield(void)
{
	schedprio_schedule(true);
}

static void schedprio_reschedule(void)
{
	schedprio_schedule(false);
}

static int schedprio_thread_add(struct uk_thread *t)
{
	UK_ASSERT(t);
	UK_ASSERT(!uk_thread_is_exited(t));

	if (t->prio < UK_THREADF_LOWEST_PRIO
	    || t->prio > UK_THREADF_HIGHEST_PRIO) {
		uk_pr_err("Thread %s has invalid priority %d\n", t->name,
			  t->prio);
		return -EINVAL;
	}

	/* Add to run queue in priority ascending order if runnable */
	if (uk_thread_is_runnable(t) && t != uk_thread_current())
		_runq_add(c, t);

	return 0;
}

static void schedprio_thread_remove(struct uk_thread *t)
{
	/* Remove from run_queue */
	if (t != uk_thread_current() && uk_thread_is_runnable(t))
		_runq_remove(c, t);
}

static void schedprio_thread_blocked(struct uk_thread *t)
{
	UK_ASSERT(ukplat_lcpu_irqs_disabled());

	if (t != uk_thread_current())
		_runq_remove(c, t);
}

static void schedprio_start(void)
{
	return;
}

static inline void schedprio_set_priority(struct uk_thread *thread,
										  int32_t			priority)
{
	struct uk_thread *prev = uk_thread_current();
	unsigned long	  flags;
	int				  prio_cmp_value;

	UK_ASSERT(thread);
	UK_ASSERT(uk_thread_is_runnable(thread));
	UK_ASSERT(priority >= UK_THREADF_LOWEST_PRIO &&
			  priority <= UK_THREADF_HIGHEST_PRIO);

	flags = ukplat_lcpu_save_irqf();

	prio_cmp_value = priority - thread->prio;

	if (prio_cmp_value == 0) {
		ukplat_lcpu_restore_irqf(flags);
		return;
	}

	thread->prio = priority;

	if (thread != prev) {
		_runq_remove(c, thread);
		_runq_add(c, thread);
#ifdef CONFIG_LIBTNSCHEDPRIO_ENABLE_PREEMTIVE
		if (schedprio_prio_cmp(prev, thread) <= 0)
#else
		if (schedprio_prio_cmp(prev, thread) < 0)
#endif
			schedprio_schedule(false);

	} else if (prio_cmp_value < 0)
		schedprio_schedule(false);

	ukplat_lcpu_restore_irqf(flags);
}

void tn_sched_thread_set_priority(struct uk_thread *thread, int32_t priority)
{
	schedprio_set_priority(thread, priority);
}

static void schedprio_thread_woken_isr(struct uk_thread *t)
{
	UK_ASSERT(ukplat_lcpu_irqs_disabled());

	if (uk_thread_is_runnable(t) && t != uk_thread_current())
		_runq_add(c, t);
}

struct uk_thread *
tn_sched_thread_create_prio(struct uk_sched *s, uk_thread_fn1_t fn, void *argp,
							size_t stack_len, size_t auxstack_len,
							bool no_uktls, bool no_ectx, const char *name,
							int32_t prio, void *priv, uk_thread_dtor_t dtor)
{
	struct uk_thread *t;
	int				  rc;

	UK_ASSERT(s);
	UK_ASSERT(s->a_stack);
	UK_ASSERT(s->a_auxstack);

	if (!no_uktls && !s->a_uktls)
		return NULL;

	t = uk_thread_create_prio_fn1(s->a, fn, argp, s->a_stack, stack_len,
								  s->a_auxstack, auxstack_len,
								  no_uktls ? NULL : s->a_uktls, no_ectx, name,
								  prio, priv, dtor);

	if (!t)
		return NULL;

	rc = uk_sched_thread_add(s, t);
	if (rc < 0)
		return NULL;

	return t;
}

struct uk_sched *tn_schedprio_create(struct uk_alloc *a)
{
	uk_pr_info("Initializing priority scheduler\n");
	c = uk_zalloc(a, sizeof(struct schedprio));
	if (!c)
		return NULL;

	_runq_init(c);

	uk_sched_init(&c->sched, schedprio_start, schedprio_yield,
				  schedprio_reschedule, schedprio_thread_add,
				  schedprio_thread_remove, schedprio_thread_blocked,
				  schedprio_thread_woken_isr, schedprio_thread_woken_isr,
				  schedprio_prio_cmp, tn_schedprio_select_next,
				  tn_schedprio_update_queue_and_switch, a);

	return &c->sched;
}
