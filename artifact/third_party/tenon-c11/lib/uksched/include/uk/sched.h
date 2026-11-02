/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *          Simon Kuenzer <simon@unikraft.io>
 *
 * Copyright (c) 2017, NEC Europe Ltd., NEC Corporation. All rights reserved.
 * Copyright (c) 2022, NEC Laboratories GmbH, NEC Corrporation.
 *                     All rights reserved.
 * Copyright (c) 2022, Unikraft GmbH. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __UK_SCHED_H__
#define __UK_SCHED_H__

#include <uk/plat/tls.h>
#include <uk/alloc.h>
#include <uk/thread.h>
#include <uk/assert.h>
#include <uk/arch/types.h>
#include <uk/essentials.h>
#include <uk/trace_macros.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uk_sched;
extern struct uk_sched *uk_sched_head;

/**
 * Get the pointer to the first scheduler instance in the list
 *
 * @return
 *   Pointer to the first scheduler instance (head of the scheduler list).
 *   Returns NULL if no scheduler has been registered.
 *
 */

__attribute__((always_inline)) static inline struct uk_sched *uk_sched_get(void)
{
	return uk_sched_head;
}

typedef void (*uk_sched_yield_func_t)(void);

typedef void (*uk_sched_reschedule_func_t)(void);
typedef int (*uk_sched_thread_add_func_t)(struct uk_thread *t);
typedef void (*uk_sched_thread_remove_func_t)(struct uk_thread *t);
typedef void (*uk_sched_thread_blocked_func_t)(struct uk_thread *t);
typedef void (*uk_sched_thread_woken_func_t)(struct uk_thread *t);
typedef struct uk_thread *(*tn_sched_thread_next_to_run_func_t)(
	struct uk_thread *prev);
typedef void (*tn_sched_thread_switch_func_t)(struct uk_thread *prev,
											  struct uk_thread *next,
											  bool				irq_flag);
typedef int (*uk_sched_thread_compare_func_t)(struct uk_thread *thread_1,
											  struct uk_thread *thread_2);

typedef void (*uk_sched_start_t)(void);

struct uk_sched {
	uk_sched_yield_func_t yield;
	uk_sched_reschedule_func_t reschedule;

	uk_sched_thread_add_func_t      thread_add;
	uk_sched_thread_remove_func_t   thread_remove;
	uk_sched_thread_blocked_func_t  thread_blocked;
	uk_sched_thread_woken_func_t    thread_woken;
	uk_sched_thread_woken_func_t    thread_woken_isr;
	tn_sched_thread_next_to_run_func_t thread_next_to_run;
	tn_sched_thread_switch_func_t	   thread_switch;
	uk_sched_thread_compare_func_t	   thread_compare;

	uk_sched_start_t sched_start;

	/* internal */
	bool is_started;
	struct uk_thread_list thread_list;
	struct uk_thread_list exited_threads;
	struct uk_alloc *a;       /**< default allocator for struct uk_thread */
	struct uk_alloc *a_stack; /**< default allocator for stacks */
	struct uk_alloc *a_auxstack; /**< default allocator for aux stacks */
	struct uk_alloc *a_uktls; /**< default allocator for TLS+ectx */
	struct uk_sched *next;
};

/**
 * uk_sched_yield - Yield the processor to allow other threads to run.
 *
 * This function requests the scheduler to yield the processor, allowing
 * other threads to run. However, it is important to note that calling
 * this function does not guarantee that a context switch will occur,
 * or that a different thread will be scheduled. The actual behavior
 * depends on the scheduler's implementation and current system state.
 *
 * Calling `uk_sched_yield()` should not be relied upon to enforce any
 * specific thread execution order. The caller must not assume that
 * execution will be transferred to another thread immediately, and
 * the code logic must not depend on such behavior.
 */
static inline void uk_sched_yield(void)
{
	/* TODO: update trace */
	unsigned long	 flags;
	struct uk_sched *s = uk_sched_get();
	struct lcpu		*this_lcpu = lcpu_get_current();

	UK_ASSERT(s);

	flags = ukplat_lcpu_save_irqf();
	if (this_lcpu->interrupt_nested) {
		this_lcpu->pending_switch = 1;
		ukplat_lcpu_restore_irqf(flags);
		return;
	}

	this_lcpu->pending_switch = 0;
	ukplat_lcpu_restore_irqf(flags);

	s->yield();
}

/**
 * Tell the scheduler may need to reschedule.
 * The scheduler will decide if a reschedule is needed.
 * This is only wrapper functions over scheduler callbacks
 */
static inline void uk_sched_reschedule(void)
{
	unsigned long	 flags;
	struct uk_sched *s = uk_sched_get();
	struct lcpu		*this_lcpu = lcpu_get_current();

	UK_ASSERT(s);

	flags = ukplat_lcpu_save_irqf();
	if (this_lcpu->interrupt_nested) {
		this_lcpu->pending_switch = 1;
		ukplat_lcpu_restore_irqf(flags);
		return;
	}

	this_lcpu->pending_switch = 0;
	ukplat_lcpu_restore_irqf(flags);

	s->reschedule();
}

/**
 * Add thread to a scheduler
 *
 * @param s
 *   Destination scheduler (required)
 * @param t
 *   Thread to be added (required)
 * @return
 *   - (=0): Successfully added
 *   - (>0): Failed added
 */
int uk_sched_thread_add(struct uk_sched *s, struct uk_thread *t);

/**
 * Remove a thread from the scheduler
 *
 * @param t
 *   thread to remove (required)
 * @return
 *   - (0): Successfully removed
 */
int uk_sched_thread_remove(struct uk_thread *t);

/* Set the thread as blocked and assign a timeout
 *
 * @param thread
 *   Thread to be blocked
 * @param tick
 *   Period to be blocked
 * @return
 *   NULL
 */
void uk_sched_thread_blocked(struct uk_thread *t, systick_t tick);

/* Set the thread as woken
 *
 * @param thread
 *   Thread to be woken
 *
 * @return
 *   NULL
 */
void uk_sched_thread_woken(struct uk_thread *t);

/**
 * call scheduler starter function
 * @param s
 *   Scheduler to be started (required)
 */
void uk_sched_start(struct uk_sched *sched);

/**
 * Allocates a uk_thread and assigns it to a scheduler.
 * Similar to `uk_thread_create_fn0()`, general-purpose registers are reset
 * on thread start.
 *
 * @param s
 *   Reference to scheduler that will execute the thread after creation
 *   (required)
 * @param fn0
 *   Thread entry function (required)
 * @param stack_len
 *   Size of the thread stack. If set to 0, a default stack size is used
 *   for the stack allocation.
 * @param auxstack_len
 *   Size of the thread auxiliary stack. If set to 0, a default stack size is
 *   used for the stack allocation.
 * @param no_uktls
 *   If set, no memory is allocated for a TLS. Functions must not use
 *   any TLS variables.
 * @param no_ectx
 *   If set, no memory is allocated for saving/restoring extended CPU
 *   context state (e.g., floating point, vector registers). In such a
 *   case, no extended context is saved nor restored on thread switches.
 *   Executed functions must be ISR-safe.
 * @param name
 *   Optional name for the thread
 * @param priv
 *   Reference to external data that corresponds to this thread
 * @param dtor
 *   Destructor that is called when this thread is released
 * @return
 *   - (NULL): Allocation failed
 *   - Reference to created uk_thread
 */
struct uk_thread *uk_sched_thread_create_fn0(struct uk_sched *s,
					     uk_thread_fn0_t fn0,
					     size_t stack_len,
					     size_t auxstack_len,
					     bool no_uktls,
					     bool no_ectx,
					     const char *name,
					     void *priv,
					     uk_thread_dtor_t dtor);

/**
 * Allocates a uk_thread and assigns it to a scheduler.
 * Similar to `uk_thread_create_fn0()`, general-purpose registers are reset
 * on thread start.
 *
 * @param s
 *   Reference to scheduler that will execute the thread after creation
 *   (required)
 * @param fn1
 *   Thread entry function (required)
 * @param argp
 *   Args for thread entry function
 * @param stack_len
 *   Size of the thread stack. If set to 0, a default stack size is used
 *   for the stack allocation.
 * @param no_uktls
 *   If set, no memory is allocated for a TLS. Functions must not use
 *   any TLS variables.
 * @param no_ectx
 *   If set, no memory is allocated for saving/restoring extended CPU
 *   context state (e.g., floating point, vector registers). In such a
 *   case, no extended context is saved nor restored on thread switches.
 *   Executed functions must be ISR-safe.
 * @param name
 *   Optional name for the thread
 * @param priv
 *   Reference to external data that corresponds to this thread
 * @param dtor
 *   Destructor that is called when this thread is released
 * @return
 *   - (NULL): Allocation failed
 *   - Reference to created uk_thread
 */
struct uk_thread *uk_sched_thread_create_fn1(struct uk_sched *s,
					     uk_thread_fn1_t fn1,
					     void *argp,
					     size_t stack_len,
					     size_t auxstack_len,
					     bool no_uktls,
					     bool no_ectx,
					     const char *name,
					     void *priv,
					     uk_thread_dtor_t dtor);

/**
 * Allocates a uk_thread and assigns it to a scheduler.
 * Similar to `uk_thread_create_fn0()`, general-purpose registers are reset
 * on thread start.
 *
 * @param s
 *   Reference to scheduler that will execute the thread after creation
 *   (required)
 * @param fn1
 *   Thread entry function (required)
 * @param argp
 *   Args for thread entry function
 * @param argp1
 *   Second args for thread entry function
 * @param stack_len
 *   Size of the thread stack. If set to 0, a default stack size is used
 *   for the stack allocation.
 * @param no_uktls
 *   If set, no memory is allocated for a TLS. Functions must not use
 *   any TLS variables.
 * @param no_ectx
 *   If set, no memory is allocated for saving/restoring extended CPU
 *   context state (e.g., floating point, vector registers). In such a
 *   case, no extended context is saved nor restored on thread switches.
 *   Executed functions must be ISR-safe.
 * @param name
 *   Optional name for the thread
 * @param priv
 *   Reference to external data that corresponds to this thread
 * @param dtor
 *   Destructor that is called when this thread is released
 * @return
 *   - (NULL): Allocation failed
 *   - Reference to created uk_thread
 */
struct uk_thread *uk_sched_thread_create_fn2(struct uk_sched *s,
					     uk_thread_fn2_t fn2,
					     void *argp0, void *argp1,
					     size_t stack_len,
					     size_t auxstack_len,
					     bool no_uktls,
					     bool no_ectx,
					     const char *name,
					     void *priv,
					     uk_thread_dtor_t dtor);

/* Shortcut for creating a thread with default settings */
#define uk_sched_thread_create(s, fn1, argp, name)		\
	uk_sched_thread_create_fn1((s), (fn1), (void *) (argp),	\
				   0x0, 0x0, false, false,	\
				   (name), NULL, NULL)

#define uk_sched_foreach_thread(sched, itr)				\
	UK_TAILQ_FOREACH((itr), &(sched)->thread_list, thread_list)
#define uk_sched_foreach_thread_safe(sched, itr, tmp)			\
	UK_TAILQ_FOREACH_SAFE((itr), &(sched)->thread_list, thread_list, (tmp))

/**
 * Dump all threads from the scheduler
 *
 * @param klvl
 *   Output level
 * @param s
 *   Scheduler from where threads are dumped
 * @return
 *   NULL
 */
void uk_sched_dumpk_threads(int klvl, struct uk_sched *s);

/* used to maintain forward compatibility */
#define uk_sched_thread_sleep uk_sched_thread_sleep_ns
/**
 * Sleep current thread
 *
 * @param nsec
 *   Time period to sleep
 * @return
 *   NULL
 */
void uk_sched_thread_sleep_ns(__nsec nsec);

/**
 * Sleep current thread
 *
 * @param tick
 *   tick period to sleep
 * @return
 *   NULL
 */
void uk_sched_thread_sleep_tick(systick_t tick);

/* Set the thread as blocked and assign a wake-up time
 * @param thread
 *   Thread to be blocked
 * @param until
 *   Wake-up time
 * @return
 *   NULL
 */
void uk_sched_thread_block_until(struct uk_thread *thread, __nsec until);

/**
 * Exits the current thread context
 * @return
 *   NULL
 */
void uk_sched_thread_exit(void) __noreturn;

/* The callback of thread timeout
 * @param thread
 *   Thread to be blocked
 * @return
 *   NULL
 */
void uk_sched_thread_timeout(void *thread);

/**
 * Exits the current thread and runs the given routine when releasing the
 * thread from garbage collection context.
 * @param gc_fn
 *   Gc function to be excuted when the thread is collected
 * @param gc_argp
 *   Input args for gc function
 * @return
 *   NULL
 */
void uk_sched_thread_exit2(uk_thread_gc_t gc_fn, void *gc_argp) __noreturn;

/**
 * Terminates another thread
 * @param thread
 *   Thread to be terminated (required)
 * @return
 *   NULL
 */
void uk_sched_thread_terminate(struct uk_thread *thread);

/**
 * Select the most suitable thread from the queue.
 *
 * @param prev
 *   current thread
 *
 * @return
 *   pointer to most suitable thread
 */
struct uk_thread *tn_sched_next_to_run(struct uk_thread *prev);

/**
 * Execute thread switch.
 *
 * @param prev
 *   Thread to be switch out, could be NULL.
 * @param next
 *   Thread to be switch in.
 * @param irq_flag
 *   Flag indicates switch request whether from irq.
 * @return
 *   NULL
 */
void tn_sched_thread_switch(struct uk_thread *prev, struct uk_thread *next,
							bool irq_flag);

#define TN_THREAD_TIMER_START(thread, init_tick)			\
	do {								\
		tn_timer_init(&(thread->timer),	init_tick,		\
		     uk_sched_thread_timeout, thread, TN_TIMER_FLAG_ONE_SHOT);\
		tn_timer_start(&(thread->timer));			\
	} while (0)

/**
 * Compares the priority of two threads
 * @param thread_1
 * First thread to be compared
 * @param thread_2
 * Second thread to be compared
 * @return
 * - (0): The two threads have the same priority
 * - (>0): The first thread has a higher priority
 * - (<0): The second thread has a higher priority
 */
static inline int uk_sched_thread_compare(struct uk_thread *thread_1,
										  struct uk_thread *thread_2)
{
	struct uk_sched *s;

	s = thread_1->sched;

	UK_ASSERT(s && s == thread_2->sched);

	return s->thread_compare(thread_1, thread_2);
}

/**
 * Create idle thread for each logical cpu
 *
 * @return
 * - (NULL): Allocation failed
 * - Reference to created uk_thread
 * @note
 * This interface can only be invoked
 * after the default scheduler instance is registered via "uk_sched_register"
 */
struct uk_thread *tn_sched_create_idle(void);

#ifdef __cplusplus
}
#endif

#endif /* __UK_SCHED_H__ */
