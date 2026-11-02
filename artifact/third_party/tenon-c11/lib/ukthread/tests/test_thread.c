/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#include <uk/alloc.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/test.h>
#include <uk/thread.h>

#include "thread_internal.h"

UK_TESTCASE(ukthread, test_thread_release)
{
	struct uk_alloc *a = uk_alloc_get_default();
	uintptr_t tlsp;

	tlsp = ukplat_tlsp_get();
	struct uk_thread *main_thread = uk_thread_create_bare(
		a, 0x0, 0x0, 0x0, tlsp, !(!tlsp),
		false, "init", NULL, NULL);
	uk_thread_release(main_thread);
	UK_TEST_EXPECT_SNUM_EQ(uk_thread_is_exited(main_thread),
		UK_THREADF_EXITED);
	UK_TEST_EXPECT_NULL(main_thread->_mem.stack_a);
	UK_TEST_EXPECT_NULL(main_thread->_mem.uktls);
	UK_TEST_EXPECT_NULL(main_thread->_mem.uktls_a);
}

UK_TESTCASE(uksched, test_thread_block_no_timeout_then_wake)
{
	struct uk_alloc *a = uk_alloc_get_default();
	uintptr_t tlsp;

	tlsp = ukplat_tlsp_get();
	struct uk_thread *main_thread = uk_thread_create_bare(
		a, 0x0, 0x0, 0x0, tlsp, !(!tlsp),
		false, "init", NULL, NULL);
	uk_thread_set_runnable(main_thread);
	uk_thread_block(main_thread);
	UK_TEST_EXPECT_SNUM_EQ(uk_thread_is_runnable(main_thread), 0);
	uk_thread_wake(main_thread);
	// TODO：add test for irq-safe operation。
	UK_TEST_EXPECT_SNUM_EQ(uk_thread_is_runnable(main_thread), 1);
	UK_TEST_EXPECT_SNUM_EQ(main_thread->timer.init_tick, 0LL);
}

UK_TESTCASE(uksched, test_thread_set_exited)
{
	struct uk_alloc *a = uk_alloc_get_default();
	uintptr_t tlsp;

	tlsp = ukplat_tlsp_get();
	struct uk_thread *main_thread = uk_thread_create_bare(
		a, 0x0, 0x0, 0x0, tlsp, !(!tlsp),
		false, "init", NULL, NULL);
	uk_thread_set_exited(main_thread);
	UK_TEST_EXPECT_SNUM_EQ(uk_thread_is_exited(main_thread),
		UK_THREADF_EXITED);
}

static __noreturn void entry_fn(void)
{
	uk_thread_exit();
}
static __noreturn void entry_fn1(void *)
{
	uk_thread_exit();
}
static __noreturn void entry_fn2(void *, void *)
{
	uk_thread_exit();
}

UK_TESTCASE(uksched, test_uk_thread_create)
{
	//these threads are created by threads
	struct uk_thread *thread3, *thread4, *thread5;
	struct uk_alloc *a = uk_alloc_get_default();

	thread3 = uk_thread_create_fn0(a,
		(entry_fn), a, 0x0, a, 0x0, 0 ? NULL : a, 0,
		("Waiter"), ((void *)0), ((void *)0));
	thread4 = uk_thread_create_fn1(a, (entry_fn1), (void *)(((void *)0)), a,
				       0x0, a, 0x0, 0 ? NULL : a, 0, ("Waiter"),
				       ((void *)0), ((void *)0));
	thread5 = uk_thread_create_fn2(
	    a, (entry_fn2), (void *)(((void *)0)), (void *)(((void *)0)), a,
	    0x0, a, 0x0, 0 ? NULL : a, 0, ("Waiter"), ((void *)0), ((void *)0));

	UK_TEST_EXPECT_NOT_NULL(thread3);
	UK_TEST_EXPECT_NOT_NULL(thread4);
	UK_TEST_EXPECT_NOT_NULL(thread5);
}

UK_TESTCASE(uksched, test_uk_thread_create_and_init)
{
	struct uk_alloc *a = uk_alloc_get_default();
	struct uk_thread *t0 = uk_thread_create_container(a, a, 0x0,
		a, 0x0, a, 0, ("Waiter"), ((void *)0), ((void *)0));
	struct uk_thread *t1 = uk_thread_create_container(a, a, 0x0,
		a, 0x0, a, 0, ("Waiter"), ((void *)0), ((void *)0));
	struct uk_thread *t2 = uk_thread_create_container(a, a, 0x0,
		a, 0x0, a, 0, ("Waiter"), ((void *)0), ((void *)0));
	struct uk_thread *t3 = uk_thread_create_container2(a, 1, 1, 1,
		0, 0, ("Waiter"), ((void *)0), ((void *)0));
	UK_TEST_EXPECT_NOT_NULL(t0);
	uk_thread_container_init_fn1(t1, entry_fn1, (void *)(((void *)0)));
	UK_TEST_EXPECT_SNUM_NQ(uk_thread_is_runnable(t1), 0);
	uk_thread_container_init_fn0(t0, entry_fn);
	UK_TEST_EXPECT_SNUM_NQ(uk_thread_is_runnable(t0), 0);
	uk_thread_container_init_fn2(t2, entry_fn2, (void *)(((void *)0)),
				     (void *)(((void *)0)));
	UK_TEST_EXPECT_SNUM_NQ(uk_thread_is_runnable(t2), 0);
	uk_thread_container_init_bare(t3, 1);
	UK_TEST_EXPECT_SNUM_NQ(uk_thread_is_runnable(t3), 0);
}

uk_testsuite_register(ukthread, NULL, NULL);

