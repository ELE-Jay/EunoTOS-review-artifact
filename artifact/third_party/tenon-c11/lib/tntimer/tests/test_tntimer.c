/* Copyright 2024 Hangzhou Yingyi Technology Co., Ltd
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
#include <uk/list.h>
#include <uk/print.h>
#include <uk/arch/lcpu.h>
#include <tn/timer.h>
#include <tn/systick.h>

extern struct uk_list_head *tn_timer_get_list(void);

void timeout_func1(void *)
{
	uk_pr_info("timeout func1\n");
}

void timeout_func2(void *tick_to_save)
{
	/* record wake up time
	 * we don't mask irq here, because the next systick interrupt(or some other
	 * irq, low possibility) may occur during this irq handler running, and we
	 * want to record this.
	 */
	*(systick_t *)tick_to_save = tn_systick_get_tick();
}

void dump_timer(void)
{
	struct timer *node;
	struct uk_list_head *timer_list_head;

	timer_list_head = tn_timer_get_list();
	UK_ASSERT(timer_list_head != NULL);
	uk_list_for_each_entry(node, timer_list_head, list) {
		uk_pr_info("node timeout is %lx,flag is %ld\n",
			   node->timeout_tick, node->flag);
	};
}

UK_TESTCASE(tntimer, test_timer_order_by_tick)
{
	systick_t ticks[5] = {0x100000, 0x200000, 0x300000, 0x260000, 0x50000};
	// order in timer list by the value of tick
	int order_idx[5] = {4, 0, 1, 3, 2};
	struct timer *timers[5], *temp;
	struct uk_list_head *timer_list_head;

	// create test timers
	for (int i = 0; i < 5; i++) {
		timers[i] = tn_timer_create(
					ticks[i], *timeout_func1, NULL, TN_TIMER_FLAG_ONE_SHOT);
		UK_TEST_EXPECT_NOT_NULL(timers[i]);
	}

	// start all the timers
	for (int i = 0; i < 5; i++)
		tn_timer_start(timers[i]);

	// check order
	timer_list_head = tn_timer_get_list();
	for (int i = 0; i < 5; i++) {
		temp = uk_list_first_entry_or_null(timer_list_head, struct timer, list);
		UK_TEST_EXPECT_PTR_EQ(temp, timers[order_idx[i]]);
		tn_timer_delete(temp);
	}

	// the timer list must be empty
	UK_TEST_EXPECT(uk_list_empty(timer_list_head));
}

UK_TESTCASE(tntimer, test_tn_timer_announce)
{

	systick_t ticks[5] = {100, 200, 200, 300, 302};
	int longest_tick_index = 4;
	systick_t diff, cur, wake_up, timer_timeout;
	struct timer *timers[5];
	systick_t timer_wake_up_ticks[5] = {0};

	// create test timers
	for (int i = 0; i < 5; i++) {
		timers[i] = tn_timer_create(ticks[i], *timeout_func2,
									&timer_wake_up_ticks[i],
									TN_TIMER_FLAG_ONE_SHOT);
		UK_TEST_EXPECT_NOT_NULL(timers[i]);
	}

	// caculate dry-run diff
	cur = tn_systick_get_tick();
	timeout_func2(&wake_up);
	diff = tn_systick_get_tick() - cur;
	// start all the timers
	for (int i = 0; i < 5; i++)
		tn_timer_start(timers[i]);

	// wait for all timer waking up
	while (timer_wake_up_ticks[longest_tick_index] == 0)
		dmb(ish);

	// check wake up ticks
	for (int i = 0; i < 5; i++) {
		timer_timeout = timers[i]->timeout_tick;
		wake_up = timer_wake_up_ticks[i];
		// tick has been updated
		UK_TEST_EXPECT_NOT_ZERO(wake_up);
		// check accuracy
		UK_TEST_EXPECT_SNUM_LT((wake_up - diff - timer_timeout), 20);
	}
	// the timer list must be empty
	UK_TEST_EXPECT(uk_list_empty(tn_timer_get_list()));
}

/*
 * We want check timer accuracy before any unnecessary driver interrupt
 * registed. Maybe we could use init and fini function to mask and unmask
 * unnecessary irq.
 */
UK_TESTSUITE_AT_INITCALL_PRIO(tntimer, NULL, NULL,
							  UK_INIT_CLASS_EARLY,
							  UK_PRIO_EARLIEST);
