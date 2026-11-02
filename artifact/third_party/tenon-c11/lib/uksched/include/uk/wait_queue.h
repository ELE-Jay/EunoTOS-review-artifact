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

#ifndef __UK_SCHED_WAIT_QUEUE_H__
#define __UK_SCHED_WAIT_QUEUE_H__

#include <uk/list.h>
#include <uk/wait_types.h>
#include <uk/sched.h>

/**
 * _is_waitq_empty - check if the wait queue is empty
 * _waitq_add - add a waiter to the wait queue
 * _waitq_remove - remove a waiter from the wait queue
 * __waitq_first - get the first waiter from the wait queue
 */

#if defined(CONFIG_LIBUKSCHED_WAITQ_STAILQ)
#define _is_waitq_empty waitq_stailq_is_empty
#define _waitq_add waitq_stailq_add
#define _waitq_remove waitq_stailq_remove
#define _waitq_best waitq_stailq_first

#define _waitq_foreach_safe UK_STAILQ_FOREACH_SAFE

#elif defined(CONFIG_LIBUKSCHED_WAITQ_LIST)
#define _is_waitq_empty waitq_list_is_empty
#define _waitq_add waitq_list_add
#define _waitq_remove waitq_list_remove
#define _waitq_best waitq_list_best

#define _waitq_foreach_safe(var, head, field, tvar)                            \
	uk_list_for_each_entry_safe(var, tvar, head, field)
#endif

#ifdef CONFIG_LIBUKSCHED_WAITQ_STAILQ
static inline int waitq_stailq_is_empty(struct uk_waitq *wq)
{
	return UK_STAILQ_EMPTY(&(wq->wait_list));
}

static inline void waitq_stailq_add(struct uk_waitq *wq,
				    struct uk_waitq_entry *entry)
{
	UK_STAILQ_INSERT_TAIL(&(wq->wait_list), entry, thread_list);
}

static inline void waitq_stailq_remove(struct uk_waitq *wq,
				       struct uk_waitq_entry *entry)
{
	UK_STAILQ_REMOVE(&(wq->wait_list), entry, struct uk_waitq_entry,
			 thread_list);
}

static inline struct uk_waitq_entry *waitq_stailq_first(struct uk_waitq *wq)
{
	return UK_STAILQ_FIRST(&(wq->wait_list));
}

#elif defined(CONFIG_LIBUKSCHED_WAITQ_LIST)

static inline int waitq_list_is_empty(struct uk_waitq *wq)
{
	return uk_list_empty(&(wq->wait_list));
}

static inline void waitq_list_add(struct uk_waitq *wq,
				  struct uk_waitq_entry *entry)
{
	struct uk_waitq_entry *tmp = NULL;

	uk_list_for_each_entry(tmp, &wq->wait_list, thread_list) {
		if (uk_sched_thread_compare(entry->thread, tmp->thread) > 0) {
			uk_list_add_before(&entry->thread_list,
					   &tmp->thread_list);
			break;
		}
	}
	if (&tmp->thread_list == &wq->wait_list)
		uk_list_add_tail(&entry->thread_list, &wq->wait_list);
}

static inline void waitq_list_remove(struct uk_waitq *wq __unused,
				     struct uk_waitq_entry *entry)
{
	uk_list_del(&entry->thread_list);
}

static inline struct uk_waitq_entry *waitq_list_best(struct uk_waitq *wq)
{
	return uk_list_first_entry_or_null(&wq->wait_list,
					   struct uk_waitq_entry, thread_list);
}
#endif

// Dump non-priority wait queue
#ifdef CONFIG_LIBUKSCHED_WAITQ_STAILQ
static inline void dump_wait_queue(struct uk_waitq *wq)
{
	struct uk_waitq_entry *t = NULL, *tmp = NULL;

	uk_pr_info("Wait queue: ");
	_waitq_foreach_safe(t, &(wq->wait_list), thread_list, tmp) {
		uk_pr_info("%s ", t->thread->name);
	}
	uk_pr_info("\n");
}

// Dump priority wait queue
#else
static inline void dump_wait_queue(struct uk_waitq *wq)
{
	struct uk_waitq_entry *t = NULL, *tmp = NULL;

	uk_pr_info("Wait queue: ");
	_waitq_foreach_safe(t, &(wq->wait_list), thread_list, tmp) {
		uk_pr_info("%s(%d) ", t->thread->name, t->thread->prio);
	}
	uk_pr_info("\n");
}
#endif

#endif /* __UK_SCHED_WAIT_QUEUE_H__ */
