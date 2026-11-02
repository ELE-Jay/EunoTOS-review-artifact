/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/prio.h>
#include <uk/process.h>
#include <uk/sched.h>
#include <uk/syscall.h>
#include <uk/test.h>

#if defined(CONFIG_LIBPOSIX_PROCESS_PIDS) && \
	defined(CONFIG_LIBPOSIX_PROCESS_INIT_PIDS)
extern pid_t getpid(void);
extern long	 do_syscall(long sysnum);

UK_TESTCASE_DESC(posix_process_syscall_at_sys_testsuite, test_getpid_syscall,
				 "return -ENOTSUP because pthread_self is uninitialized")
{
	/* initialize with some meaningless value */
	long ret_s = -100001, ret_r = -100002, ret_e = -100003, old_errno = errno;

	/* return value of syscall and function call must be the same */
	ret_s = uk_syscall6_r(SYS_getpid, 0, 0, 0, 0, 0, 0);
	ret_r = uk_syscall_r_getpid();
	UK_TEST_EXPECT_SNUM_EQ(ret_s, -ENOTSUP);
	UK_TEST_EXPECT_SNUM_EQ(ret_s, ret_r);

	/* uk_syscall_e_x set the errno */
	ret_e = uk_syscall_e_getpid();
	UK_TEST_EXPECT_SNUM_EQ(ret_e, -1);
	UK_TEST_EXPECT_SNUM_EQ(-errno, ret_s);
	/* clear errno */
	errno = old_errno;
}

UK_TESTCASE_DESC(posix_process_syscall_at_latest_testsuite, test_getpid_syscall,
				 "return real pid")
{
	/* initialize with some meaningless value */
	long ret = -100000, ret_s = -100001, ret_r = -100002, ret_e = -100003;

	/* return value of syscall and function call must be same */
	ret_s = uk_syscall6_r(SYS_getpid, 0, 0, 0, 0, 0, 0);
	ret_r = uk_syscall_r_getpid();
	UK_TEST_EXPECT_SNUM_EQ(ret_s, ret_r);
	UK_TEST_EXPECT(ret_s != -ENOTSUP);


	/* We don't check 'getpid' at sys initialization phase, because
	 * that its implementation in musl is a real syscall, it returns -1
	 * when error occurs(because the init-thread is not initialized).
	 * While using nolibc, the libc-style wrapper is provide by the tenon
	 * raw implementation(defined by UK_SYSCALL_R_DEFINE macro) and returns
	 * -errno. it sucks, to be improved.
	 */
	ret = getpid();
	ret_e = uk_syscall_e_getpid();
	UK_TEST_EXPECT_SNUM_EQ(ret, ret_e);
	UK_TEST_EXPECT_SNUM_EQ(ret_s, ret_e);
}

UK_TESTCASE_DESC(posix_process_syscall_at_latest_testsuite, test_getpid_svc,
				 "get real pid by svc")
{
	/* initialize with some meaningless value */
	long ret = -100000, ret_r = -100002;

	/* return value of svc and function call must be same */
	ret	  = do_syscall(SYS_getpid);
	ret_r = uk_syscall_r_getpid();
	UK_TEST_EXPECT_SNUM_EQ(ret, ret_r);
	UK_TEST_EXPECT(ret != -ENOTSUP);
}
#endif /* CONFIG_LIBPOSIX_PROCESS_PIDS && CONFIG_LIBPOSIX_PROCESS_INIT_PIDS */

#ifdef CONFIG_LIBPOSIX_PROCESS_CLONE
extern int clone(int (*)(void *), void *, int, void *, ...);
extern struct uk_thread *tid2ukthread(pid_t tid);
extern pid_t ukthread2tid(struct uk_thread *thread);
extern pid_t ukthread2pid(struct uk_thread *thread);

#define CLONE_FLAGS                                           \
	(CLONE_FS | CLONE_FILES | CLONE_VM | CLONE_CHILD_SETTID | \
	 CLONE_PARENT_SETTID)

int child_run_flag;
int childFunc(void *)
{
	uk_pr_info("this is child function\n");
	child_run_flag = 1;
	return 0;
}

UK_TESTCASE(posix_process_syscall_at_latest_testsuite, test_uk_syscall6_r_clone)
{
	int parent_saved_tid = -1, child_tid = -2, ret = -1;
	void *stack;

	child_run_flag = 0;
	stack = uk_memalign(uk_alloc_get_default(), UKARCH_SP_ALIGN, __STACK_SIZE);
	UK_TEST_EXPECT_NOT_NULL(stack);
	/* user space syscall, use parent thread's auxsp to save context */
	ret = uk_syscall6_r(SYS_clone, CLONE_FLAGS,
						ukarch_gen_sp(stack, __STACK_SIZE),
						(long)&parent_saved_tid, 0, (long)&child_tid, 0);
	if (ret == 0) {
		uk_pr_info("this is the child thread\n");
		child_run_flag = 1;
		uk_syscall_r_exit(0);
	}

	/* check the thread has already been created */
	UK_TEST_EXPECT(parent_saved_tid != -1);
	UK_TEST_EXPECT(child_tid != -2);
	UK_TEST_EXPECT_SNUM_EQ(parent_saved_tid, child_tid);
#ifdef CONFIG_LIBTNSCHEDPRIO_ENABLE_PREEMTIVE
	/* check if the child thread has been scheduled */
	UK_TEST_EXPECT(child_run_flag == 1);
	child_run_flag = 0;
#endif
	if (tid2ukthread(ret))
		uk_posix_process_kill_thread(parent_saved_tid);
	uk_free(uk_alloc_get_default(), stack);
}

UK_TESTCASE(posix_process_syscall_at_latest_testsuite, test_uk_syscall_r_clone)
{
	int parent_saved_tid = -1, child_tid = -2, ret = -1;
	void *stack;

	/*
	 * this is a function call, but clone is a special interface,
	 * uk save context in the parent thread's auxsp and the 'clone'
	 * implementation is compatible with linux abi.
	 * For other syscall, there's no context saving
	 */
	child_run_flag = 0;
	stack = uk_memalign(uk_alloc_get_default(), UKARCH_SP_ALIGN, __STACK_SIZE);
	UK_TEST_EXPECT_NOT_NULL(stack);
	ret = uk_syscall_r_clone(CLONE_FLAGS, ukarch_gen_sp(stack, __STACK_SIZE),
							 (long)&parent_saved_tid, 0, (long)&child_tid);
	if (ret == 0) {
		uk_pr_info("this is the child thread\n");
		child_run_flag = 1;
		uk_syscall_r_exit(0);
	}

	/* check the thread has already been created */
	UK_TEST_EXPECT(parent_saved_tid != -1);
	UK_TEST_EXPECT(child_tid != -2);
	UK_TEST_EXPECT_SNUM_EQ(parent_saved_tid, child_tid);
#ifdef CONFIG_LIBTNSCHEDPRIO_ENABLE_PREEMTIVE
	/* check if the child thread has been scheduled */
	UK_TEST_EXPECT(child_run_flag == 1);
	child_run_flag = 0;
#endif
	if (tid2ukthread(ret))
		uk_posix_process_kill_thread(parent_saved_tid);
	uk_free(uk_alloc_get_default(), stack);
}

/* When UK_LIBC_SYSCALLS is 1, the libc-style function 'clone' is provided by
 * Tenon, and must return EINVAL. Musl set UK_LIBC_SYSCALLS to 0.
 */
#if defined(CONFIG_HAVE_SCHED) && !UK_LIBC_SYSCALLS
UK_TESTCASE(posix_process_syscall_at_latest_testsuite, test_libc_style_clone)
{
	int parent_saved_tid = -1, child_tid = -2, ret = -1;
	void *stack;

	/* this is a libc wapper, implement by musl in this test.
	 * For aarch64, musl (uk adaption) will remap reg according to linux abi
	 * and call uk_syscall_r_clone
	 */
	child_run_flag = 0;
	stack = uk_memalign(uk_alloc_get_default(), UKARCH_SP_ALIGN, __STACK_SIZE);
	UK_TEST_EXPECT_NOT_NULL(stack);
	ret = clone(childFunc, (void *)ukarch_gen_sp(stack, __STACK_SIZE),
				CLONE_FLAGS, NULL, &parent_saved_tid, NULL, &child_tid);

	/* check the thread has already been created */
	UK_TEST_EXPECT(parent_saved_tid != -1);
	UK_TEST_EXPECT(child_tid != -2);
	UK_TEST_EXPECT_SNUM_EQ(parent_saved_tid, child_tid);
#ifdef CONFIG_LIBTNSCHEDPRIO_ENABLE_PREEMTIVE
	/* check if the child thread has been scheduled */
	UK_TEST_EXPECT(child_run_flag == 1);
	child_run_flag = 0;
#endif
	if (tid2ukthread(ret))
		uk_posix_process_kill_thread(parent_saved_tid);
	uk_free(uk_alloc_get_default(), stack);
}
#endif /* CONFIG_HAVE_SCHED */
#endif /* CONFIG_LIBPOSIX_PROCESS_CLONE */

uk_testsuite_sys_prio(posix_process_syscall_at_sys_testsuite,
					  NULL, NULL, UK_PRIO_LATEST);
uk_testsuite_register(posix_process_syscall_at_latest_testsuite, NULL, NULL);
