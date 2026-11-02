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

#ifndef __TN_LIBTNSYSTICK_H__
#define __TN_LIBTNSYSTICK_H__

#include <stdint.h>
#include <uk/intctlr.h>
#include <uk/arch/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**< Maximum number of UINT32 */
#define TICK_UINT32_MAX     0xffffffff
/**< Maximum number of UINT64 */
#define TICK_UINT64_MAX     0xffffffffffffffff
#define TICK_MAX TICK_UINT64_MAX

typedef uint64_t systick_t;

/* sysclock oprations */
struct sysclock_desc {
	/* Name of the system timer */
	const char *name;
	uint32_t freq;
	struct uk_intctlr_irq *irq;
};

/**
 * Initialise system tick
 *
 * This function initialises the system clock driver and systick.
 *
 */
int tn_systick_init(void);

/**
 * Get current systick value
 *
 * @return current systick value
 */
systick_t tn_systick_get_tick(void);

/**
 * Get systick irq number
 *
 * Irq number was initialised during tn_systick_init.
 *
 * @return systick irq number
 */
uint32_t tn_systick_get_irq(void);

/**
 * Start systick irq
 *
 * This function does only one thing: unmasks the interrupt of systick.
 *
 */
void tn_systick_start(void);

/**
 * Set the timeout as the next systick irq.
 * @param ticks: The ticks need to set.
 */
void tn_systick_set_timeout(systick_t ticks);

/**
 * Wait and halt until the specified systick.
 */
void tn_systick_block_until(systick_t ticks);

/**
 * ticks_to_ns - Convert systicks to ns.
 * @param ticks: The ticks need to convert.
 */
__nsec ticks_to_ns(systick_t ticks);

/**
 * ticks_to_ns - Convert ns to systicks.
 * @param ns: The ns need to convert.
 */
systick_t ns_to_ticks(__nsec ns);

__nsec tn_systick_get_monotonic(void);

#ifdef __cplusplus
}
#endif

#endif /* __TN_LIBTNSYSTICK_H__ */
