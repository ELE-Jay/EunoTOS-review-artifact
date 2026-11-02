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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <uk/alloc.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/intctlr.h>
#include <uk/plat/config.h>
#include <uk/plat/lcpu.h>
#include <uk/plat/time.h>
#include <uk/sched.h>
#include <uk/sched_impl.h>
#include <uk/syscall.h>
#include <uk/test.h>
#include <uk/thread.h>
#ifdef CONFIG_LIBUKSCHEDCOOP
#include <uk/schedcoop.h>
#elif CONFIG_LIBTNSCHEDPRIO
#include <tn/schedprio.h>
#endif
#if CONFIG_LIBUKBOOT_INITBBUDDY
#include <uk/allocbbuddy.h>
#define uk_alloc_init uk_allocbbuddy_init
#elif CONFIG_LIBUKBOOT_INITREGION
#include <uk/allocregion.h>
#define uk_alloc_init uk_allocregion_init
#elif CONFIG_LIBUKBOOT_INITMIMALLOC
#include <uk/mimalloc.h>
#define uk_alloc_init uk_mimalloc_init
#elif CONFIG_LIBUKBOOT_INITTLSF
#include <uk/tlsf.h>
#define uk_alloc_init uk_tlsf_init
#elif CONFIG_LIBUKBOOT_INITTINYALLOC
#include <uk/tinyalloc.h>
#define uk_alloc_init uk_tinyalloc_init
#endif

#ifdef CONFIG_HAVE_SCHED
#define max_tick_error 20
static uint8_t		 switch_flag;
__volatile__ uint8_t isr_handler_flag;

UK_TESTCASE(uksched, test_sched_thread_sleep)
{
	systick_t begin_t, end_t;

	/* Switch to idle, waiting for init thread woken */
	begin_t = tn_systick_get_tick();
	uk_sched_thread_sleep_tick(100);
	end_t = tn_systick_get_tick();

	UK_TEST_EXPECT_SNUM_LE(end_t-begin_t, 100 + max_tick_error);

	begin_t = tn_systick_get_tick();
	uk_sched_thread_sleep_ns(10000);
	end_t = tn_systick_get_tick();

	UK_TEST_EXPECT_SNUM_LE(end_t - begin_t,
						   ns_to_ticks(10000) + max_tick_error);
}

UK_TESTCASE_DESC(uksched, test_tn_sched_next_to_run,
				 "Create thread and select it from the ready queue")
{
	uintptr_t		  tlsp;
	struct uk_thread *thread_not_run, *next;
	struct uk_alloc	 *a = uk_alloc_get_default();
	struct uk_sched	 *s = uk_sched_get();
	unsigned long	  flags;

	tlsp		   = ukplat_tlsp_get();
	thread_not_run = uk_thread_create_bare(a, 0x0, 0x0, 0x0, tlsp, !(!tlsp),
										   true, "TASK_NOT_RUN", NULL, NULL);
#ifdef CONFIG_LIBUKSCHED_THREAD_PRIORITY
	thread_not_run->prio = UK_THREADF_DEFAULT_PRIO + 1;
#endif

	flags = ukplat_lcpu_save_irqf();
	uk_thread_set_runnable(thread_not_run);
	/* manually add new task to run_q */
	s->thread_add(thread_not_run);
	next = tn_sched_next_to_run(uk_thread_current());
	s->thread_remove(thread_not_run);
	ukplat_lcpu_restore_irqf(flags);

	UK_TEST_EXPECT_PTR_EQ(next, thread_not_run);
	uk_thread_release(thread_not_run);
}

static void set_switch_flag(void *args __unused)
{
	switch_flag = 1;
}

UK_TESTCASE_DESC(uksched, test_tn_sched_thread_switch,
				 "Create thread and switch to it")
{
	struct uk_thread *thread_run, *current, *next;
	struct uk_alloc	 *a = uk_alloc_get_default();
	struct uk_sched	 *s = uk_sched_get();
	unsigned long	  flags;

	switch_flag = 0;
	current		= uk_thread_current();
	thread_run	= uk_thread_create_fn1(a, set_switch_flag, NULL, a, 0x0, a, 0x0,
									   a, false, "TASK_RUN", NULL, NULL);

	flags = ukplat_lcpu_save_irqf();
#ifdef CONFIG_LIBUKSCHED_THREAD_PRIORITY
	thread_run->prio = UK_THREADF_DEFAULT_PRIO + 1;
#endif
	thread_run->sched = s;
	UK_TAILQ_INSERT_TAIL(&s->thread_list, thread_run, thread_list);
	s->thread_add(thread_run);
	next = tn_sched_next_to_run(current);
	UK_TEST_EXPECT_PTR_EQ(next, thread_run);
	tn_sched_thread_switch(current, next, false);
	ukplat_lcpu_restore_irqf(flags);
	UK_TEST_EXPECT_SNUM_EQ(switch_flag, 1);
	switch_flag = 0;
}

UK_TESTCASE_DESC(uksched, test_uk_sched_compare,
				 "Create threads and compare their priorities")
{
	struct uk_thread *thread_A, *thread_B;
	struct uk_alloc	 *a = uk_alloc_get_default();
	struct uk_sched	 *s = uk_sched_get();
	uintptr_t		  tlsp;
	int				  rc;

	tlsp	 = ukplat_tlsp_get();
	thread_A = uk_thread_create_bare(a, 0x0, 0x0, 0x0, tlsp, !(!tlsp), true,
									 "TASK_A", NULL, NULL);
	thread_B = uk_thread_create_bare(a, 0x0, 0x0, 0x0, tlsp, !(!tlsp), true,
									 "TASK_B", NULL, NULL);

	thread_A->sched = s;
	thread_B->sched = s;
#ifdef CONFIG_LIBUKSCHED_THREAD_PRIORITY
	thread_A->prio = UK_THREADF_DEFAULT_PRIO + 1;
	thread_B->prio = UK_THREADF_DEFAULT_PRIO + 2;
#endif

	rc = uk_sched_thread_compare(thread_A, thread_B);

#ifdef CONFIG_LIBUKSCHED_THREAD_PRIORITY
	UK_TEST_EXPECT_SNUM_LE(rc, 0);
#else
	UK_TEST_EXPECT_SNUM_EQ(rc, 0);
#endif

	thread_A->sched = NULL;
	thread_B->sched = NULL;
	uk_thread_release(thread_A);
	uk_thread_release(thread_B);
}

static int sgi_handler_wake_blocked_thread(void *args)
{
	isr_handler_flag				  = 1;
	struct uk_thread *thread_to_woken = (struct uk_thread *)args;

	uk_sched_thread_woken(thread_to_woken);
	return 0;
}

UK_TESTCASE_DESC(uksched, test_sched_thread_blockd_and_woken,
				 "woken thread in isr")
{
	struct uk_thread *thread_to_woken_in_isr;
	struct uk_alloc	 *a = uk_alloc_get_default();
	struct uk_sched	 *s = uk_sched_get();

	switch_flag		 = 0;
	isr_handler_flag = 0;

	thread_to_woken_in_isr = uk_thread_create_fn1(a, set_switch_flag, NULL, a,
												  0x0, a, 0x0, a, false,
												  "TASK_TO_WOKEN", NULL, NULL);
#ifdef CONFIG_LIBUKSCHED_THREAD_PRIORITY
	thread_to_woken_in_isr->prio = UK_THREADF_DEFAULT_PRIO + 1;
#endif
	uk_thread_set_blocked(thread_to_woken_in_isr);
	/* Reschedule will not happen cause new task is blocked */
	uk_sched_thread_add(s, thread_to_woken_in_isr);
	UK_TEST_EXPECT_SNUM_EQ(switch_flag, 0);
	uk_intctlr_irq_register(4, sgi_handler_wake_blocked_thread,
							(void *)thread_to_woken_in_isr);
	uk_intctlr_sgi_op(4, false, 0);
	/* waiting for isr woke TASK_TO_WOKEN */
	while (!isr_handler_flag)
		;
	uk_sched_yield();
	UK_TEST_EXPECT_SNUM_EQ(switch_flag, 1);
	switch_flag		 = 0;
	isr_handler_flag = 0;
	uk_intctlr_irq_unregister(4, sgi_handler_wake_blocked_thread);
}

uk_testsuite_register(uksched, NULL, NULL);
#endif /* CONFIG_HAVE_SCHED */
