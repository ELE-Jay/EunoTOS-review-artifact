/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* Ported from Mini-OS */

#ifndef __UK_SCHED_WAIT_H__
#define __UK_SCHED_WAIT_H__

#include <uk/essentials.h>
#include <uk/plat/lcpu.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#include <uk/wait_types.h>
#include <uk/wait_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline
void uk_waitq_init(struct uk_waitq *wq)
{
	ukarch_spin_init(&(wq->sl));
	__WAIT_QUEUE_INIT(wq);
}

static inline
void uk_waitq_entry_init(struct uk_waitq_entry *entry,
		struct uk_thread *thread)
{
	entry->thread = thread;
	entry->waiting = 0;
}

static inline
int uk_waitq_empty(struct uk_waitq *wq)
{
	return _is_waitq_empty(wq);
}

static inline
void uk_waitq_add(struct uk_waitq *wq,
		struct uk_waitq_entry *entry)
{
	if (!entry->waiting) {
		_waitq_add(wq, entry);
		entry->waiting = 1;
	}
}

static inline
void uk_waitq_remove(struct uk_waitq *wq,
		struct uk_waitq_entry *entry)
{
	if (entry->waiting) {
		_waitq_remove(wq, entry);
		entry->waiting = 0;
	}
}

#define uk_waitq_add_waiter(wq, w) \
do { \
	unsigned long flags; \
	ukplat_spin_lock_irqsave(&((wq)->sl), flags); \
	uk_waitq_add(wq, w); \
	ukplat_spin_unlock_irqrestore(&((wq)->sl), flags); \
	uk_sched_thread_blocked(uk_thread_current(), NULL);	\
} while (0)

#define uk_waitq_remove_waiter(wq, w) \
do { \
	unsigned long flags; \
	ukplat_spin_lock_irqsave(&((wq)->sl), flags); \
	uk_waitq_remove(wq, w); \
	ukplat_spin_unlock_irqrestore(&((wq)->sl), flags); \
} while (0)

#define __wq_wait_event_deadline(wq, condition, deadline, deadline_condition, \
								 lock_fn, unlock_fn, lock)                    \
	({                                                                        \
		struct uk_thread *__current;                                          \
		unsigned long	  flags;                                              \
		int				  timedout = 0;                                       \
		DEFINE_WAIT(__wait);                                                  \
		if (!(condition)) {                                                   \
			__current = uk_thread_current();                                  \
			for (;;) {                                                        \
				/* protect the list */                                        \
				ukplat_spin_lock_irqsave(&((wq)->sl), flags);                 \
				if (condition) {                                              \
					ukplat_spin_unlock_irqrestore(&((wq)->sl), flags);        \
					break;                                                    \
				}                                                             \
				uk_waitq_add(wq, &__wait);                                    \
				if (deadline)                                                 \
					TN_THREAD_TIMER_START(                                    \
						__current,                                            \
						ns_to_ticks(deadline - ukplat_monotonic_clock()));    \
				uk_thread_set_blocked(__current);                             \
				(__current)->sched->thread_blocked((__current));              \
				ukplat_spin_unlock_irqrestore(&((wq)->sl), flags);            \
				if (lock)                                                     \
					unlock_fn(lock);                                          \
				uk_sched_yield();                                             \
				if (lock)                                                     \
					lock_fn(lock);                                            \
				if (condition)                                                \
					break;                                                    \
				if (deadline_condition) {                                     \
					timedout = 1;                                             \
					break;                                                    \
				}                                                             \
			}                                                                 \
			ukplat_spin_lock_irqsave(&((wq)->sl), flags);                     \
			uk_waitq_remove(wq, &__wait);                                     \
			ukplat_spin_unlock_irqrestore(&((wq)->sl), flags);                \
		}                                                                     \
		timedout;                                                             \
	})

#define uk_waitq_wait_deadline(wq, lock_fn, unlock_fn, lock, deadline,        \
							   deadline_condition)                            \
	({                                                                        \
		struct uk_thread *__current;                                          \
		unsigned long	  flags;                                              \
		int				  timedout = 0;                                       \
		DEFINE_WAIT(__wait);                                                  \
		__current = uk_thread_current();                                      \
		ukplat_spin_lock_irqsave(&((wq)->sl), flags);                         \
		uk_waitq_add(wq, &__wait);                                            \
		if (deadline)                                                         \
			TN_THREAD_TIMER_START(                                            \
				__current, ns_to_ticks(deadline - ukplat_monotonic_clock())); \
		uk_thread_set_blocked(__current);                                     \
		(__current)->sched->thread_blocked((__current));                      \
		ukplat_spin_unlock_irqrestore(&((wq)->sl), flags);                    \
		if (lock)                                                             \
			unlock_fn(lock);                                                  \
		uk_sched_yield();                                                     \
		if (lock)                                                             \
			lock_fn(lock);                                                    \
		if (deadline_condition)                                               \
			timedout = 1;                                                     \
		ukplat_spin_lock_irqsave(&((wq)->sl), flags);                         \
		uk_waitq_remove(wq, &__wait);                                         \
		ukplat_spin_unlock_irqrestore(&((wq)->sl), flags);                    \
		timedout;                                                             \
	})

#define uk_waitq_wait_locked(wq, lock_fn, unlock_fn, lock) \
	uk_waitq_wait_deadline(wq, lock_fn, unlock_fn, lock, 0, 0)

static inline void __lock_dummy(void *lock __unused) {}

#define uk_waitq_wait_event(wq, condition) \
	__wq_wait_event_deadline(wq, (condition), 0, 0, \
				 __lock_dummy, __lock_dummy, NULL)

#define uk_waitq_wait_event_locked(wq, condition, lock_fn, unlock_fn, lock) \
	__wq_wait_event_deadline(wq, (condition), 0, 0, \
				 lock_fn, unlock_fn, lock)

#define uk_waitq_wait_event_deadline(wq, condition, deadline) \
	__wq_wait_event_deadline(wq, (condition), \
		(deadline), \
		(deadline) && ukplat_monotonic_clock() >= (deadline), \
		__lock_dummy, __lock_dummy, NULL)

#define uk_waitq_wait_event_deadline_locked(wq, condition, deadline, \
					    lock_fn, unlock_fn, lock) \
	__wq_wait_event_deadline(wq, (condition), \
		(deadline), \
		(deadline) && ukplat_monotonic_clock() >= (deadline), \
		lock_fn, unlock_fn, lock)

static inline
void uk_waitq_wake_up(struct uk_waitq *wq)
{
	struct uk_waitq_entry *curr, *tmp;
	unsigned long flags;

	/* TODO: Optimize lock range */
	ukplat_spin_lock_irqsave(&(wq->sl), flags);
	_waitq_foreach_safe(curr, &(wq->wait_list), thread_list, tmp)
	{
		uk_sched_thread_woken(curr->thread);
		tn_timer_delete(&curr->thread->timer);
	}
	ukplat_spin_unlock_irqrestore(&(wq->sl), flags);

	uk_sched_reschedule();
}

static inline
void uk_waitq_wake_up_one(struct uk_waitq *wq)
{
	struct uk_waitq_entry *head;
	unsigned long flags;

	ukplat_spin_lock_irqsave(&(wq->sl), flags);
	head = _waitq_best(wq);
	if (head) {
		tn_timer_delete(&head->thread->timer);
		uk_sched_thread_woken(head->thread);
	}
	ukplat_spin_unlock_irqrestore(&(wq->sl), flags);
}

#ifdef __cplusplus
}
#endif

#endif /* __UK_SCHED_WAIT_H__ */
