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

#ifndef __TN_TIMER_H__
#define __TN_TIMER_H__

#include <stdint.h>
#include <uk/list.h>
#include <tn/systick.h>


#define TN_TIMER_FLAG_PERIODIC 0x01
#define TN_TIMER_FLAG_ONE_SHOT 0x02



struct timer {
	/*List node which contains pointers for traversing prev and next*/
	struct uk_list_head list;

	/*
	 * The relative difference in timeout occurs.
	 * The tick passed as a parameter when the external component is
	 * invoked for creation will modify this value
	 */
	systick_t init_tick;
	/*
	 * an absolute time and is not subject to external modification;
	 * it can only be altered during 'start' (added to the list).
	 */
	systick_t timeout_tick;
	/*
	 * Timeout callback function.
	 * When this timeout expires, this function will be executed.
	 */
	void (*timeout_func)(void *parameter);
	/*Parameters of the timeout callback function.*/
	void *parameter;
	/*Timer flag*/
	unsigned long flag;
};

/**
 * tn_timer_create - Creates a new timer object.
 *
 * @param init_tick The initial tick count for the timer.
 * @param timeout_func: The function to be called upon timer timeout.
 * @param parameter: The parameter to be passed to the timeout function.
 * @param flag Timer flags (e.g., periodic or one-shot).
 * @return timer a pointer to the newly created timer
 * Allocates memory for a new timer and initializes its members.
 * Returns a pointer to the newly created timer or NULL
 * if memory allocation fails.
 */
struct timer *tn_timer_create(
	systick_t init_tick,
	void (*timeout_func)(void *parameter),
	void *parameter,
	unsigned long flag);


/**
 * tn_timer_start - Starts a timer and schedules it in the active timer list.
 * @param t: The timer object to start.
 *
 * Calculates the timeout tick based on the current systick
 * value and the timer's initial tick.Adds the timer to the appropriate
 * list based on whether an overflow has occurred.
 */
void tn_timer_start(struct timer *timer);


/**
 * tn_timer_delete - Removes a timer from the active timer list.
 * @param t: The timer object to be removed.
 *
 * Removes the specified timer from the list and handles cleanup if necessary.
 */
void tn_timer_delete(struct timer *timer);

/**
 * tn_timer_init - Initializes a timer object.
 * @param t The timer object to initialize.
 * @param init_tick: The initial tick count for the timer.
 * @param timeout_func: The function to be called upon timer timeout.
 * @param parameter: The parameter to be passed to the timeout function.
 * @param flag: Timer flags (e.g., periodic or one-shot).
 *
 * Initializes the members of a timer object.
 */
void tn_timer_init(
	struct timer *t,
	systick_t init_tick,
	void (*timeout_func)(void *parameter),
	void *parameter,
	unsigned long flag);

/**
 * tn_timer_add - Adds a timer to the specified list based on its timeout tick.
 * @param in: The timer object to be added.
 * @param head: The list head where the timer will be added.
 *
 * Iterates through the specified list and inserts
 * the timer in the correct position
 * based on its timeout tick value.
 */
void tn_timer_add(struct timer *in, struct uk_list_head *head);

/*
 * tn_timer_next_tick - Retrieves the tick value of the soonest expiring timer.
 *
 * Returns the tick value of the soonest expiring timer or
 * TICK_MAX if no timers are active.
 */
systick_t tn_timer_next_tick(void);


/*
 * tn_timer_announce - Handles timer timeouts and executes associated functions.
 *
 * Retrieves the current systick value and iterates through
 * the active timer list.For each timer with a timeout tick
 * less than or equal to the current systick,the associated
 * timeout function is called, and the timer is removed from the list.
 * If the timer is periodic, it is restarted.
 */
void tn_timer_announce(void);

#endif /* __TN_TIMER_H__ */
