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
 * WITHOUT WARRANTIES OR CONDITIONS OF ssANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <tn/timer.h>
#include <uk/list.h>
#include <uk/essentials.h>
#include <uk/alloc.h>
#include <uk/trace_macros.h>

static UK_LIST_HEAD(timer_list_head);
static UK_LIST_HEAD(overflow_timer_list_head);
static uint8_t timoutListsOverflowed;

static systick_t last_tick;
/*
 * tn_timer_get_list - Retrieves the global timer list.
 *
 * Returns a pointer to the head of the timer list.
 */
struct uk_list_head *tn_timer_get_list(void)
{
	return &timer_list_head;
}

struct uk_list_head *tn_timer_get_overflow_list(void)
{
	return &overflow_timer_list_head;
}

struct timer *tn_timer_create(systick_t init_tick,
			      void (*timeout_func)(void *parameter),
			      void *parameter, unsigned long flag)
{
	struct timer *t;

	t = uk_malloc(uk_alloc_get_default(), sizeof(struct timer));
	if (!t)
		return NULL;

	t->timeout_func = timeout_func;
	t->parameter = parameter;
	t->init_tick = init_tick;
	t->flag = flag;

	return t;
}

void tn_timer_init(struct timer *t, systick_t init_tick,
		   void (*timeout_func)(void *parameter), void *parameter,
		   unsigned long flag)
{
	UK_ASSERT(t);

	t->timeout_func = timeout_func;
	t->parameter = parameter;
	t->init_tick = init_tick;
	t->flag = flag;
}

static inline struct timer *get_next_timer(void)
{
	struct timer *t;

	t = uk_list_first_entry_or_null(&timer_list_head, struct timer, list);
	if (!t && timoutListsOverflowed)
		t = uk_list_first_entry(&overflow_timer_list_head, struct timer,
					list);
	return t;
}

systick_t tn_timer_next_tick(void)
{
	struct timer *t;
	systick_t cur;

	cur = tn_systick_get_tick();

	t = get_next_timer();

	if (t) {
		if (t->timeout_tick <= cur) {
			return timoutListsOverflowed ? t->timeout_tick - cur
						     : 0;
		}
		return t->timeout_tick - cur;
	}
	return TICK_MAX;
}

/*
 * tn_timer_list_switch
 * Handles timer list overflow by switching the active list.
 *
 * This function is called when the timer list has overflowed
 *  and needs to switch to the overflow list to maintain
 *  correct ordering of timers.
 */
void tn_timer_list_switch(void)
{
	UK_ASSERT(!uk_list_empty(&overflow_timer_list_head));

	timer_list_head.next = overflow_timer_list_head.next;
	overflow_timer_list_head.next->prev = &timer_list_head;
	UK_INIT_LIST_HEAD(&overflow_timer_list_head);
	timoutListsOverflowed = 0;
}

void tn_timer_delete(struct timer *t)
{
	TN_TRACE_OBJ_FUNC(timer, delete, t);

	UK_ASSERT(t);

	uk_list_del_init(&t->list);
	if (timoutListsOverflowed && uk_list_empty(&timer_list_head))
		tn_timer_list_switch();
}

void tn_timer_start(struct timer *t)
{
	TN_TRACE_OBJ_FUNC(timer, start, t);

	systick_t cur;
	systick_t sum;

	cur = tn_systick_get_tick();
	sum = cur + MAX((systick_t)1, t->init_tick);
	t->timeout_tick = sum;
	if (sum < cur || sum < t->init_tick) {
		// 发生了溢出
		tn_timer_add(t, &overflow_timer_list_head);
		timoutListsOverflowed = 1;
	} else {
		tn_timer_add(t, &timer_list_head);
	}
	last_tick = cur;
}

void tn_timer_add(struct timer *in, struct uk_list_head *head)
{
	struct timer *t;

	uk_list_for_each_entry(t, head, list) {
		if (t->timeout_tick <= in->timeout_tick)
			continue;

		uk_list_add(&(in)->list, t->list.prev);
		goto update_next_tick;
	}
	uk_list_add_tail(&in->list, head);

update_next_tick:;
#ifdef CONFIG_LIBTNSYSTICK_TICKLESS
	if (in == get_next_timer())
		tn_systick_set_timeout(tn_timer_next_tick());
#endif /* CONFIG_LIBTNSYSTICK_TICKLESS */
}

void tn_timer_announce(void)
{
	struct timer *t;
	systick_t cur;

	cur = tn_systick_get_tick();

	//current tick overflowed,clean the first list
	if (cur < last_tick) {
		while (!uk_list_empty(&timer_list_head)) {
			t = uk_list_first_entry(
				&timer_list_head, struct timer, list);

			uk_list_del_init(&t->list);
			t->timeout_func(t->parameter);
			if (t->flag & TN_TIMER_FLAG_PERIODIC)
				tn_timer_start(t);
		}
		if (uk_list_empty(&timer_list_head) && timoutListsOverflowed)
			tn_timer_list_switch();
	}

	while (!uk_list_empty(&timer_list_head)) {
		t = uk_list_first_entry(
			&timer_list_head, struct timer, list);
		if (t->timeout_tick <= cur) {
			uk_list_del_init(&t->list);
			t->timeout_func(t->parameter);
			if (t->flag & TN_TIMER_FLAG_PERIODIC)
				tn_timer_start(t);
		} else{
			break;
		}
	}

	tn_systick_set_timeout(tn_timer_next_tick());
	last_tick = cur;
}
