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

#include <uk/test.h>
#include <uk/intctlr.h>
#include <uk/plat/lcpu.h>
#ifdef CONFIG_LIBTNSCHEDPRIO
#include <tn/sysclock.h>
#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/sched.h>
#include <uk/thread.h>
#endif /* CONFIG_LIBTNSCHEDPRIO */
#ifdef CONFIG_LIBUKINTCTLR_GICV3
#include <uk/intctlr/gic-v3.h>
#endif

__volatile__ uint8_t isr_handler_flag;
#ifdef CONFIG_LIBTNSCHEDPRIO
static uint8_t reschedule_flag;
static uint8_t no_reschedule_flag;
static uint8_t resume_after_interrupt_flag;
static uint8_t function_call_nest_flag;

static struct uk_thread *thread_A;
static struct uk_thread *thread_B;
#endif /* CONFIG_LIBTNSCHEDPRIO */

#ifdef CONFIG_LIBUKINTCTLR_GIC
#ifdef CONFIG_LIBUKINTCTLR_GICV3
static uint32_t global_current_cpu;

static int spi_handler(void *args __unused)
{
	uint64_t mpidr = SYSREG_READ64(MPIDR_EL1);
	uint64_t aff = ((mpidr & MPIDR_AFF3_MASK) >> 8) |
				(mpidr & MPIDR_AFF2_MASK) |
				(mpidr & MPIDR_AFF1_MASK) |
				(mpidr & MPIDR_AFF0_MASK);

	global_current_cpu = (uint32_t)aff;
	return 0;
}

UK_TESTCASE_DESC(ukintctlr, set_spi_pendings_test_affx_api,
	"Affinity irq40 to the current cpu")
{
	/* 中断号40，亲和至当前cpu */
	uint32_t original_cpu_affinity = uk_intctlr_spi_get_affinity(40);

	uint64_t current_cpu = SYSREG_READ64(MPIDR_EL1);
	uint64_t aff = ((current_cpu & MPIDR_AFF3_MASK) >> 8) |
					(current_cpu & MPIDR_AFF2_MASK) |
					(current_cpu & MPIDR_AFF1_MASK) |
					(current_cpu & MPIDR_AFF0_MASK);

	uk_intctlr_irq_set_affinity(40, (uint32_t)aff);
	uk_intctlr_irq_register(40, spi_handler, NULL);
	isb();

	uk_intctlr_simulate_spi(40);

	UK_TEST_EXPECT_SNUM_EQ((uint32_t)aff, global_current_cpu);

	/* 恢复现场 */
	uk_intctlr_irq_unregister(40, spi_handler);
	uk_intctlr_irq_set_affinity(40, original_cpu_affinity);
}

UK_TESTCASE_DESC(ukintctlr, verify_spi_priority_level_setting,
				 "Compare the priority of interrupt 60/70")
{
	uint8_t irq60_original_prio_level = uk_intctlr_irq_get_priority(60) >>
										TRANS_PRIORITY_SHIFT;
	uint8_t irq70_original_prio_level = uk_intctlr_irq_get_priority(70) >>
										TRANS_PRIORITY_SHIFT;

#if defined(CONFIG_PRIORITY_MAX_16)
	uk_intctlr_irq_set_priority(60, 15);
	uk_intctlr_irq_set_priority(70, 14);
	isb();
	UK_TEST_EXPECT_SNUM_GT(uk_intctlr_irq_get_priority(60),
						   uk_intctlr_irq_get_priority(70));
#elif defined(CONFIG_PRIORITY_MAX_32)
	uk_intctlr_irq_set_priority(60, 30);
	uk_intctlr_irq_set_priority(70, 31);
	isb();
	UK_TEST_EXPECT_SNUM_GT(uk_intctlr_irq_get_priority(60),
						   uk_intctlr_irq_get_priority(70));
#elif defined(CONFIG_PRIORITY_MAX_64)
	uk_intctlr_irq_set_priority(60, 62);
	uk_intctlr_irq_set_priority(70, 63);
	isb();
	UK_TEST_EXPECT_SNUM_GT(uk_intctlr_irq_get_priority(60),
						   uk_intctlr_irq_get_priority(70));
#elif defined(CONFIG_PRIORITY_MAX_128)
	uk_intctlr_irq_set_priority(60, 126);
	uk_intctlr_irq_set_priority(70, 127);
	isb();
	UK_TEST_EXPECT_SNUM_GT(uk_intctlr_irq_get_priority(60),
						   uk_intctlr_irq_get_priority(70));
#endif

	/*恢复现场*/
	uk_intctlr_irq_set_priority(60, irq60_original_prio_level);
	uk_intctlr_irq_set_priority(70, irq70_original_prio_level);
}
#endif /* CONFIG_LIBUKINTCTLR_GICV3 */

static int sgi_handler_noop(void *args __unused)
{
	isr_handler_flag++;

	/* just make sure flag modified */
	wmb();
	return 0;
}

static int sgi_handler_trigger_another_sgi(void *args __unused)
{
	int r = 0;

	r = uk_intctlr_sgi_op(2, false, 0);
	while (isr_handler_flag == 0) /* just make sure flag modified */
		wmb();
	isr_handler_flag++;
	return r;
}

UK_TESTCASE_DESC(ukintctlr, send_sgi_in_isr, "send SGI 2 in SGI 4 handler")
{
	int r = 0;

	isr_handler_flag = 0;
	uk_intctlr_irq_register(4, sgi_handler_trigger_another_sgi, NULL);
	uk_intctlr_irq_set_priority(4, 8);
	uk_intctlr_irq_register(2, sgi_handler_noop, NULL);
	uk_intctlr_irq_set_priority(2, 2);

	r = uk_intctlr_sgi_op(4, false, 0);
	/* wait for isr done */
	while (!isr_handler_flag);
	UK_TEST_EXPECT_ZERO(r);
	UK_TEST_EXPECT_SNUM_EQ(isr_handler_flag, 2);

	/* 恢复现场 */
	uk_intctlr_irq_unregister(4, sgi_handler_trigger_another_sgi);
	uk_intctlr_irq_unregister(2, sgi_handler_noop);
	isr_handler_flag = 0;
}

/* 测试sgi生成接口uk_intctlr_sgi_op
 * 场景: 向当前cpu发送/向除自己外的所有cpu发送
 */
UK_TESTCASE_DESC(ukintctlr, send_sgi_to_bsp_or_all,
	"Send a SGI to current cpu/all cpu excluding self")
{
	int r;

	uint64_t current_cpu = SYSREG_READ64(MPIDR_EL1);
	uint64_t aff = ((current_cpu & MPIDR_AFF3_MASK) >> 8) |
					(current_cpu & MPIDR_AFF2_MASK) |
					(current_cpu & MPIDR_AFF1_MASK) |
					(current_cpu & MPIDR_AFF0_MASK);

	/* 将sgi亲和到当前cpu */
	r = uk_intctlr_sgi_op(4, false, (uint32_t)aff);

	UK_TEST_EXPECT_ZERO(r);

	/* 将sgi亲和到除自己外的所有cpu */
	r = uk_intctlr_sgi_op(4, true, 0);

	UK_TEST_EXPECT_ZERO(r);
}

uk_testsuite_register(ukintctlr, NULL, NULL);
#endif /* CONFIG_LIBUKINTCTLR_GIC */

#ifdef CONFIG_LIBTNSCHEDPRIO
static int sgi_handler_with_reschedule_request(void *args __unused)
{
	uk_pr_info("entry irq handler: %s\n", __func__);
	/* wake up thread A */
	isr_handler_flag++;
	/* make sure flag set */
	mb();
	uk_sched_thread_woken(thread_A);
	/* This reschedule request is delayed until isr finished */
	uk_sched_reschedule();
	uk_pr_info("exit irq handler: %s\n", __func__);
	return 1;
}

static int sgi_handler_without_reschedule_request(void *args __unused)
{
	uk_pr_info("entry irq handler: %s\n", __func__);
	isr_handler_flag++;
	/* make sure flag set */
	mb();
	uk_pr_info("exit irq handler: %s\n", __func__);
	return 1;
}

static void thread_entry_wrapper(void *entryfn)
{
	uk_pr_info("Entry thread: %s\n", uk_thread_current()->name);
	((uk_thread_fn1_t)entryfn)(NULL);
	uk_pr_info("Exit thread: %s\n", uk_thread_current()->name);
}

static void add_reschedule_flag(void *args __unused)
{
	/* Thread_A was switched indicates that
	 * reschedule request delayed is executed
	 */
	reschedule_flag++;
}

static void add_reschedule_flag_and_reschedule(void *args __unused)
{
	reschedule_flag++;
	/* before rescheduling, block self */
	uk_thread_block(thread_A);
	/* we should switch to B now */
	uk_sched_reschedule();
	reschedule_flag++;
}

static void trigger_sgi_and_wait_to_be_interrupted(void *args __unused)
{
	uk_intctlr_sgi_op(4, false, 0);
	/* If there is no reschedule request in isr,
	 * or request was rejected,
	 * we turn back thread_B from exception,
	 * then switch back to main thread from thread_B.
	 */
	while (!isr_handler_flag);
	resume_after_interrupt_flag++;
}

static int send_sgi_and_wait(uint8_t *flag)
{
	*flag += 1;
	trigger_sgi_and_wait_to_be_interrupted(NULL);

	return *flag;
}

/* This entry function designed to verify that
 * old x30 (LR) register can be correctly restored
 * when a function call interrupted
 */
static void
trigger_sgi_and_wait_to_be_interrupted_with_wrap(void *args __unused)
{
	function_call_nest_flag += send_sgi_and_wait(&function_call_nest_flag);
}

static void add_no_reschedule_flag(void *args __unused)
{
	no_reschedule_flag++;
}

int reschedule_after_isr_env_init(struct uk_testsuite *suite __unused)
{
	/* mask system timer interrupt */
	tn_sysclock_mask_irq();
	return 0;
}

int reschedule_after_isr_env_restore(struct uk_testsuite *suite __unused)
{
	/* unmask system timer interrupt */
	tn_sysclock_unmask_irq();
	return 0;
}

static void create_blocked_task_and_add_to_sched(struct uk_thread **thread,
												 int32_t			prio,
												 uk_thread_fn1_t	entry,
												 const char		   *name)
{
	struct uk_alloc *a = uk_alloc_get_default();
	struct uk_sched *s = uk_sched_get();

	UK_ASSERT(a);
	UK_ASSERT(s);
	*thread = uk_thread_create_prio_fn1(a, thread_entry_wrapper, entry, a, 0x0,
										a, 0x0, a, true, name, prio, NULL,
										NULL);
	uk_sched_thread_blocked(*thread, 0);
	uk_sched_thread_add(s, *thread);
}

static void reset_flags(void)
{
	isr_handler_flag			= 0;
	no_reschedule_flag			= 0;
	reschedule_flag				= 0;
	resume_after_interrupt_flag = 0;
	function_call_nest_flag		= 0;
	/* make sure flags reset */
	mb();
}

UK_TESTCASE_DESC(
	reschedule_after_isr, execute_reschedule_after_isr,
	"check if scheduler act normally after the previous isr with reschedule.")
{
	reset_flags();
	uk_intctlr_irq_register(4, sgi_handler_with_reschedule_request, NULL);
	create_blocked_task_and_add_to_sched(&thread_A, UK_THREADF_DEFAULT_PRIO + 2,
										 add_reschedule_flag, "TASK_A");
	create_blocked_task_and_add_to_sched(&thread_B, UK_THREADF_DEFAULT_PRIO + 1,
										 trigger_sgi_and_wait_to_be_interrupted,
										 "TASK_B");

	/* wake up the thread to be interrupted and reschedule*/
	uk_sched_thread_woken(thread_B);
	uk_sched_reschedule();
	/*
	 * the schedule sequence is:
	 * |   |interrupt and schedule |   |terminated |   |terminated|
	 * | B |  ->                   | A | ->        | B | ->       |Main
	 *
	 * check flags
	 */
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 1);
	UK_TEST_EXPECT_SNUM_EQ(resume_after_interrupt_flag, 1);
	/* 恢复现场 */
	reset_flags();
	uk_intctlr_irq_unregister(4, sgi_handler_with_reschedule_request);
}

UK_TESTCASE_DESC(reschedule_after_isr, no_reschedule_request_in_isr,
				 "ISR for SGI 4 does not trigger a reschedule request.\n")
{
	reset_flags();
	uk_intctlr_irq_register(4, sgi_handler_without_reschedule_request, NULL);
	create_blocked_task_and_add_to_sched(&thread_A, UK_THREADF_DEFAULT_PRIO + 2,
										 add_reschedule_flag, "TASK_A");
	create_blocked_task_and_add_to_sched(&thread_B, UK_THREADF_DEFAULT_PRIO + 1,
										 trigger_sgi_and_wait_to_be_interrupted,
										 "TASK_B");
	uk_sched_thread_woken(thread_B);
	uk_sched_reschedule();
	/*
	 * the schedule sequence is:
	 * |   |interrupt and no schedule |   |terminated |
	 * | B |  ->                      | B | ->        |Main
	 *
	 * check flags
	 */
	UK_TEST_EXPECT_SNUM_EQ(resume_after_interrupt_flag, 1);
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 0);

	/* thread A doesn't ever run, it needs to be terminated */
	uk_sched_thread_terminate(thread_A);
	reset_flags();
	uk_intctlr_irq_unregister(4, sgi_handler_without_reschedule_request);
}

UK_TESTCASE_DESC(
	reschedule_after_isr, reschedule_request_denied_after_isr,
	"reschedule request is denied because woken thread has lower priority.\n")
{
	reset_flags();
	uk_intctlr_irq_register(4, sgi_handler_with_reschedule_request, NULL);
	create_blocked_task_and_add_to_sched(&thread_A, UK_THREADF_DEFAULT_PRIO,
										 add_reschedule_flag, "TASK_A");
	create_blocked_task_and_add_to_sched(&thread_B, UK_THREADF_DEFAULT_PRIO + 1,
										 trigger_sgi_and_wait_to_be_interrupted,
										 "TASK_B");
	uk_sched_thread_woken(thread_B);
	uk_sched_reschedule();
	/*
	 * the schedule sequence is:
	 * |   |interrupt and reschedule no switch |   |terminated|
	 * | B |  ->                               | B | ->       |Main
	 *
	 * check flags
	 */
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 0);
	UK_TEST_EXPECT_SNUM_EQ(resume_after_interrupt_flag, 1);
	/* thread A doesn't ever run, it needs to be ternimated*/
	uk_sched_thread_terminate(thread_A);
	reset_flags();
	uk_intctlr_irq_unregister(4, sgi_handler_with_reschedule_request);
}

UK_TESTCASE_DESC(
	reschedule_after_isr, reschedule_executed_and_interrupt,
	"check if isr act normally after the previous isr with reschedule")
{
	reset_flags();
	uk_intctlr_irq_register(4, sgi_handler_with_reschedule_request, NULL);
	uk_intctlr_irq_register(3, sgi_handler_without_reschedule_request, NULL);
	create_blocked_task_and_add_to_sched(&thread_A, UK_THREADF_DEFAULT_PRIO + 2,
										 add_reschedule_flag, "TASK_A");
	create_blocked_task_and_add_to_sched(&thread_B, UK_THREADF_DEFAULT_PRIO + 1,
										 trigger_sgi_and_wait_to_be_interrupted,
										 "TASK_B");
	uk_sched_thread_woken(thread_B);
	uk_sched_reschedule();
	/*
	 * the schedule sequence is:
	 * |   |interrupt and reschedule|   |terminated| B |terminated|
	 * | B |  ->                    | A | ->       | B | ->       |Main
	 *
	 * check flags
	 */
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 1);
	UK_TEST_EXPECT_SNUM_EQ(resume_after_interrupt_flag, 1);
	UK_TEST_EXPECT_SNUM_EQ(isr_handler_flag, 1);
	isr_handler_flag = 0;
	uk_intctlr_sgi_op(3, false, 0);
	while (!isr_handler_flag);
	UK_TEST_EXPECT_SNUM_EQ(isr_handler_flag, 1);
	reset_flags();
	uk_intctlr_irq_unregister(4, sgi_handler_with_reschedule_request);
	uk_intctlr_irq_unregister(3, sgi_handler_without_reschedule_request);
}

UK_TESTCASE_DESC(
	reschedule_after_isr, reschedule_executed_and_switch_threads,
	"check if scheduler act normally after the previous isr with reschedule")
{
	struct uk_thread *thread_C;

	reset_flags();
	uk_intctlr_irq_register(4, sgi_handler_with_reschedule_request, NULL);
	create_blocked_task_and_add_to_sched(&thread_A, UK_THREADF_DEFAULT_PRIO + 2,
										 add_reschedule_flag, "TASK_A");
	create_blocked_task_and_add_to_sched(&thread_B, UK_THREADF_DEFAULT_PRIO + 1,
										 trigger_sgi_and_wait_to_be_interrupted,
										 "TASK_B");
	create_blocked_task_and_add_to_sched(&thread_C, UK_THREADF_DEFAULT_PRIO + 1,
										 add_no_reschedule_flag, "TASK_C");
	uk_sched_thread_woken(thread_B);
	uk_sched_reschedule();
	/*
	 * the schedule sequence is:
	 * |   |interrupt and reschedule|   |terminated| B |terminated|
	 * | B |  ->                    | A | ->       | B | ->       |Main
	 *
	 * check flags
	 */
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 1);
	UK_TEST_EXPECT_SNUM_EQ(resume_after_interrupt_flag, 1);

	/* We come back from B, now switch to thread C */
	uk_sched_thread_woken(thread_C);
	uk_sched_reschedule();
	UK_TEST_EXPECT_SNUM_EQ(no_reschedule_flag, 1);

	/* Thread A/B/C all already exited */
	reset_flags();
	uk_intctlr_irq_unregister(4, sgi_handler_with_reschedule_request);
}

UK_TESTCASE_DESC(
	reschedule_after_isr, reschedule_executed_and_switch_back_alive_thread,
	"check if scheduler act normally after the previous isr with reschedule")
{
	reset_flags();
	uk_intctlr_irq_register(4, sgi_handler_with_reschedule_request, NULL);
	create_blocked_task_and_add_to_sched(&thread_A, UK_THREADF_DEFAULT_PRIO + 2,
										 add_reschedule_flag_and_reschedule,
										 "TASK_A");
	create_blocked_task_and_add_to_sched(&thread_B, UK_THREADF_DEFAULT_PRIO + 1,
										 trigger_sgi_and_wait_to_be_interrupted,
										 "TASK_B");

	uk_sched_thread_woken(thread_B);
	uk_sched_reschedule();
	/*
	 * the schedule sequence is:
	 * |   |interrupt and reschedule|   |reschedule| B |terminated|
	 * | B |  ->                    | A | ->       | B | ->       |Main
	 *
	 * check flags
	 */
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 1);
	UK_TEST_EXPECT_SNUM_EQ(resume_after_interrupt_flag, 1);

	/* We come back from B, now switch back to thread A */
	uk_sched_thread_woken(thread_A);
	uk_sched_reschedule();
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 2);

	reset_flags();
	uk_intctlr_irq_unregister(4, sgi_handler_with_reschedule_request);
}

UK_TESTCASE_DESC(reschedule_after_isr,
				 reschedule_executed_and_switch_interrupted_thread,
				 "check if the interrupted thread resumed with correct lr")
{
	reset_flags();
	uk_intctlr_irq_register(4, sgi_handler_with_reschedule_request, NULL);
	create_blocked_task_and_add_to_sched(&thread_A, UK_THREADF_DEFAULT_PRIO + 2,
										 add_reschedule_flag, "TASK_A");
	create_blocked_task_and_add_to_sched(
		&thread_B, UK_THREADF_DEFAULT_PRIO + 1,
		trigger_sgi_and_wait_to_be_interrupted_with_wrap, "TASK_B");

	uk_sched_thread_woken(thread_B);
	uk_sched_reschedule();

	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 1);
	UK_TEST_EXPECT_SNUM_EQ(resume_after_interrupt_flag, 1);
	/* function_call_nest_flag has been increased in the wrap*/
	UK_TEST_EXPECT_SNUM_EQ(function_call_nest_flag, 2);

	reset_flags();
	uk_intctlr_irq_unregister(4, sgi_handler_with_reschedule_request);
}

uk_testsuite_lib_prio(reschedule_after_isr, reschedule_after_isr_env_init,
					  reschedule_after_isr_env_restore, __UK_PRIO_AFTER_0);
#endif /* CONFIG_LIBTNSCHEDPRIO */
