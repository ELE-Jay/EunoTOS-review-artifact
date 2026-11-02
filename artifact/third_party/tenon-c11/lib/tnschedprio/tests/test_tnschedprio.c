/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */
#include <tn/schedprio.h>
#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/sched.h>
#include <uk/test.h>
#include <uk/thread.h>

static int reschedule_flag;

static void set_reschedule_flag(void *args __unused)
{
	reschedule_flag = 1;
}

static void set_curr_thread_prio(void *args __unused)
{
	reschedule_flag = 1;
	/* Lower current thread priority, back to init thread */
	tn_sched_thread_set_priority(uk_thread_current(),
								 UK_THREADF_DEFAULT_PRIO - 1);
	/* flag won't be set to 2 */
	reschedule_flag = 2;
}

UK_TESTCASE_DESC(
	tnschedprio, test_tn_sched_thread_set_priority,
	"check if scheduler act normally after thread priority is updated")
{
	struct uk_thread *thread_prio_to_change;
	struct uk_sched	 *s = uk_sched_get();

	reschedule_flag = 0;

	/* Temporarily increase the priority of init thread */
	tn_sched_thread_set_priority(uk_thread_current(),
								 UK_THREADF_DEFAULT_PRIO + 1);

	thread_prio_to_change = tn_sched_thread_create_prio(
		s, set_reschedule_flag, NULL, 0x0, 0x0, false, false,
		"TASK_PRIO_CHANGE", UK_THREADF_DEFAULT_PRIO, NULL, NULL);

	/* TASK_PRIO_CHANGE has lower priority, will not be switched */
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 0);

	/* Decrease priority, not trigger reschedule request. */
	tn_sched_thread_set_priority(thread_prio_to_change,
								 UK_THREADF_DEFAULT_PRIO - 1);
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 0);

	/* Increase priority, trigger reschedule request. */
	tn_sched_thread_set_priority(thread_prio_to_change,
								 UK_THREADF_DEFAULT_PRIO + 2);
	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 1);

	reschedule_flag = 0;
	/* Restore priority of init thread, no other thread available now */
	tn_sched_thread_set_priority(uk_thread_current(), UK_THREADF_DEFAULT_PRIO);
}

UK_TESTCASE_DESC(
	tnschedprio, test_set_prio_lower_current_thread_priority,
	"check if scheduler act normally after current thread priority is updated")
{
	struct uk_thread *thread_set_curr_prio;
	struct uk_sched	 *s = uk_sched_get();

	reschedule_flag = 0;

	/* Switch to TASK_SET_CURR_PRIO */
	thread_set_curr_prio = tn_sched_thread_create_prio(
		s, set_curr_thread_prio, NULL, 0x0, 0x0, false, false,
		"TASK_SET_CURR_PRIO", UK_THREADF_DEFAULT_PRIO + 1, NULL, NULL);

	UK_TEST_EXPECT_SNUM_EQ(reschedule_flag, 1);
	uk_sched_thread_terminate(thread_set_curr_prio);
	reschedule_flag = 0;
}

uk_testsuite_register(tnschedprio, NULL, NULL);
