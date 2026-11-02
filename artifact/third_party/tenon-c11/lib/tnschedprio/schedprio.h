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
#ifndef __TN_SCHEDPRIO_SCHEDPRIO_H__
#define __TN_SCHEDPRIO_SCHEDPRIO_H__

#include <tn/schedprio.h>
#include <uk/list.h>

struct schedprio {
	struct uk_sched sched;
#if defined(CONFIG_LIBTNSCHEDPRIO_RUNQ_TAILQ)
	UK_TAILQ_HEAD(run_queue, struct uk_thread) run_queue;
#elif defined(CONFIG_LIBTNSCHEDPRIO_RUNQ_LIST)
	struct uk_list_head run_queue;
#endif
};

#if defined(CONFIG_LIBTNSCHEDPRIO_RUNQ_TAILQ)
#define _runq_init runq_tailq_init
#define _is_runq_empty runq_tailq_is_empty
#define _runq_add runq_tailq_add
#define _runq_remove runq_tailq_remove
#define _runq_best runq_tailq_best

#define _runq_foreach UK_TAILQ_FOREACH
#define _runq_foreach_safe UK_TAILQ_FOREACH_SAFE

#elif defined(CONFIG_LIBTNSCHEDPRIO_RUNQ_LIST)
#define _runq_init runq_list_init
#define _is_runq_empty runq_list_is_empty
#define _runq_add runq_list_add
#define _runq_remove runq_list_remove
#define _runq_best runq_list_best

#define _runq_foreach uk_list_for_each_entry
#define _runq_foreach_safe(var, head, field, tvar)                             \
	uk_list_for_each_entry_safe(var, tvar, head, field)
#endif

static inline int schedprio_prio_cmp(struct uk_thread *t1, struct uk_thread *t2)
{
	return t1->prio - t2->prio;
}

static inline void dump_run_queue(struct schedprio *c)
{
	struct uk_thread *t = NULL;

	uk_pr_info("Run queue: ");
	_runq_foreach(t, &c->run_queue, queue) {
		uk_pr_info("%s(%d) ", t->name, t->prio);
	}
	uk_pr_info("\n");
}

#if defined(CONFIG_LIBTNSCHEDPRIO_RUNQ_TAILQ)
static inline void runq_tailq_init(struct schedprio *c)
{
	UK_TAILQ_INIT(&c->run_queue);
}

static inline bool runq_tailq_is_empty(struct schedprio *c)
{
	return UK_TAILQ_EMPTY(&c->run_queue);
}

static inline void runq_tailq_add(struct schedprio *c, struct uk_thread *t)
{
	struct uk_thread *tmp = NULL;

	UK_TAILQ_FOREACH(tmp, &c->run_queue, queue) {
		if (schedprio_prio_cmp(t, tmp) > 0)
			break;
	}
	if (tmp)
		UK_TAILQ_INSERT_BEFORE(tmp, t, queue);
	else
		UK_TAILQ_INSERT_TAIL(&c->run_queue, t, queue);
}

static inline struct uk_thread *runq_tailq_best(struct schedprio *c)
{
	return UK_TAILQ_FIRST(&c->run_queue);
}

static inline void runq_tailq_remove(struct schedprio *c, struct uk_thread *t)
{
	UK_TAILQ_REMOVE(&c->run_queue, t, queue);
}
#endif

#if defined(CONFIG_LIBTNSCHEDPRIO_RUNQ_LIST)
static inline void runq_list_init(struct schedprio *c)
{
	UK_INIT_LIST_HEAD(&c->run_queue);
}

static inline bool runq_list_is_empty(struct schedprio *c)
{
	return uk_list_empty(&(c->run_queue));
}

static inline void runq_list_add(struct schedprio *c, struct uk_thread *t)
{
	struct uk_thread *tmp = NULL;

	uk_list_for_each_entry(tmp, &c->run_queue, queue) {
		if (schedprio_prio_cmp(t, tmp) > 0) {
			uk_list_add_before(&t->queue, &tmp->queue);
			break;
		}
	}
	if (&tmp->queue == &c->run_queue)
		uk_list_add_tail(&t->queue, &c->run_queue);
}

static inline void runq_list_remove(struct schedprio *c __unused,
				    struct uk_thread *t)
{
	uk_list_del(&t->queue);
}

static inline struct uk_thread *runq_list_best(struct schedprio *c)
{
	return uk_list_first_entry_or_null(&c->run_queue, struct uk_thread,
					   queue);
}
#endif

static inline struct schedprio *uksched2schedprio(struct uk_sched *s)
{
	UK_ASSERT(s);

	return __containerof(s, struct schedprio, sched);
}

#endif /* __TN_SCHEDPRIO_SCHEDPRIO_H__ */
