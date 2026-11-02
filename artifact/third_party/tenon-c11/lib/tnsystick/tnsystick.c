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

#include <tn/systick.h>
#include <uk/arch/time.h>
#include <tn/sysclock.h>
#include <tn/systick_impl.h>
#include <tn/timer.h>
#include <uk/plat/common/cpu.h>

/* current tick value */
static systick_t cur_systick;
/* Last count recoreded when systick is updated*/
static uint64_t last_count;
/* Number of system clock counts per tick */
static uint32_t counts_per_tick;
/* Flag indicating systick library initialized */
static uint8_t initialized;

struct sysclock_desc sysclock;
static uint32_t systick_freq;

/* Shift factor for converting ticks to ns */
static uint8_t shift_tick_to_ns;
/* Shift factor for converting ns to ticks */
static uint8_t shift_ns_to_tick;
/* Multiplier for converting ticks to nsecs */
static uint32_t ns_per_tick;
/* Multiplier for converting nsecs to ticks */
static uint32_t tick_per_ns;
/* Total (absolute) number of nanoseconds per tick */
static uint64_t tot_ns_per_tick;

static uint64_t max_convert_ticks;

/* elapsed_tick returns ticks elasped from last tick interrupt occurred */
static inline uint32_t elapsed_tick(void)
{
	return (unsigned long)(tn_sysclock_get_counts() - last_count)
	       / counts_per_tick;
}

static inline void systick_update(void)
{
	uint32_t diff_tick = elapsed_tick();

	cur_systick += diff_tick;
	last_count += diff_tick * counts_per_tick;
}

int sys_timer_irq_handler(void *arg __unused)
{
	/* 1. Let sysclock do per isr ops */
	tn_sysclock_isr_notify();

	/* 2. Update cur_systick and last_count */
	systick_update();

	/* 3. Set next tick for non-tickless mode */
#ifdef CONFIG_LIBTNSYSTICK_TICKLESS
	/* Let set_timeout call from timer unmask clock irq. */
	tn_sysclock_mask_irq();
#else
	tn_sysclock_set_next(last_count + counts_per_tick, 0);
	tn_sysclock_unmask_irq();
#endif	/* CONFIG_LIBTNSYSTICK_TICKLESS */

	/* 4. Check timer */
	tn_timer_announce();

	/* 5. TODO: schedprio to check timeout threads */

	/* todo: Interrupt processing temporarily returns 0 */
	return 0;
}

systick_t tn_systick_get_tick(void)
{
#ifdef CONFIG_LIBTNSYSTICK_TICKLESS
	/* It's hard to restrict other library(such as logger) not to call this
	 * method before init is called, althrough other RTOS did this.
	 */
	if (unlikely(!initialized))
		return 0;
	return cur_systick + elapsed_tick();
#else
	return cur_systick;
#endif /* CONFIG_LIBTNSYSTICK_TICKLESS */
}

static void systick_convert_init(void)
{
	/* Absolute number of ns per tick */
	tot_ns_per_tick = ukarch_time_sec_to_nsec(1) / CONFIG_LIBTNSYSTICK_FREQ;

	/* Absolute number of counts per tick */
	counts_per_tick = sysclock.freq / CONFIG_LIBTNSYSTICK_FREQ;

	/*
	 * Calculate the shift factor and scaling multiplier for
	 * converting ticks to ns.
	 */
	calculate_mult_shift(&ns_per_tick, &shift_tick_to_ns,
			     CONFIG_LIBTNSYSTICK_FREQ,
			     ukarch_time_sec_to_nsec(1));

	/* We disallow zero ns_per_tick */
	UK_BUGON(!ns_per_tick);

	/*
	 * Calculate the shift factor and scaling multiplier for
	 * converting ns to ticks.
	 */
	calculate_mult_shift(&tick_per_ns, &shift_ns_to_tick,
			     ukarch_time_sec_to_nsec(1),
			     CONFIG_LIBTNSYSTICK_FREQ);

	/* We disallow zero tick_per_ns */
	UK_BUGON(!tick_per_ns);

	max_convert_ticks = TICK_MAX / 2 / counts_per_tick;
}

int tn_systick_init(void)
{
	int ret;

	ret = tn_sysclock_probe();
	if (ret != 0)
		return ret;

	systick_freq = CONFIG_LIBTNSYSTICK_FREQ;
	if ((systick_freq == 0) || (systick_freq > sysclock.freq)) {
		uk_pr_err(
		    "invalid system tick frequency, set it default : %d\n",
		    sysclock.freq);
		systick_freq = sysclock.freq;
	}
	counts_per_tick = sysclock.freq / CONFIG_LIBTNSYSTICK_FREQ;

	/* initialize cur_systick convert value */
	systick_convert_init();
	/* register time base irq */
	uk_pr_debug("sysclock.irq->id : %d\n", sysclock.irq->id);
	uk_intctlr_irq_register(sysclock.irq->id, sys_timer_irq_handler, NULL);

	tn_sysclock_mask_irq();
	systick_update();
	tn_sysclock_set_next(last_count + counts_per_tick, 1);

	initialized = 1;
	return 0;
}

void tn_systick_start(void)
{
	tn_sysclock_unmask_irq();
}

uint32_t tn_systick_get_irq(void)
{
	return sysclock.irq->id;
}

void tn_systick_set_timeout(systick_t ticks __maybe_unused)
{
#ifdef CONFIG_LIBTNSYSTICK_TICKLESS
	ticks = MIN(ticks, max_convert_ticks);
	ticks = MIN(ticks, TICK_UINT32_MAX / 2);
	uint64_t next_count =
	    (cur_systick + elapsed_tick() + ticks) * counts_per_tick;

	tn_sysclock_set_next(next_count, 0);
	tn_sysclock_unmask_irq();
#endif /* CONFIG_LIBTNSYSTICK_TICKLESS */
}

void tn_systick_register(const char *name,
			 uint32_t freq,
			 struct uk_intctlr_irq *irq)
{
	sysclock.name = name;
	sysclock.freq = freq;
	sysclock.irq = irq;
}

__nsec ticks_to_ns(systick_t ticks)
{
	if (ticks > max_convert_ticks) {
		/* We have reached the maximum number of ticks to convert using
		 * the shift factor
		 */
		return (ticks * tot_ns_per_tick);
	} else {
		return (ns_per_tick * ticks) >> shift_tick_to_ns;
	}
}

systick_t ns_to_ticks(__nsec ns)
{
	systick_t isceil = 0;

	if (ns % tot_ns_per_tick)
		isceil = 1;
	if (ns > __MAX_CONVERT_NS) {
		/* We have reached the maximum number of ns to convert using the
		 * shift factor
		 */
		return (ns / tot_ns_per_tick + isceil);
	} else {
		return ((tick_per_ns * ns) >> shift_ns_to_tick) + isceil;
	}
}

/* return ns which based on ticks */
__nsec tn_systick_get_monotonic(void)
{
	return ticks_to_ns((uint64_t)tn_systick_get_tick());
}

void tn_systick_block_until(systick_t until)
{
	unsigned long flags;

	while (tn_systick_get_tick() < until) {
		flags = ukplat_lcpu_save_irqf();

		ukplat_lcpu_halt_irq();

		ukplat_lcpu_restore_irqf(flags);
		ukplat_lcpu_enable_irq();
	}
}
