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

#include <stdlib.h>
#include <uk/assert.h>
#include <uk/plat/time.h>
#include <uk/plat/lcpu.h>
#include <uk/bitops.h>
#include <uk/ofw/fdt.h>
#include <uk/plat/common/cpu.h>
#include <arm/time.h>
#include <tn/systick_impl.h>
#include <uk/plat/common/bootinfo.h>

static const char *sysclock_name = "arm generic timer";
struct uk_intctlr_irq irq;
uint32_t freq;

/* Bits definition of cntv_ctl register */
#define ARM_GENERIC_TIMER_ENABLE 0x01
#define ARM_GENERIC_TIMER_MASK_IRQ 0x02
#define ARM_GENERIC_TIMER_IRQ_STATUS 0x04

static const char *const sysclock_list[] = {"arm,armv8-timer",
					    "arm,armv7-timer", NULL};

static inline void gtimer_enable(void)
{
	set_el0(cntv_ctl, get_el0(cntv_ctl) | GT_TIMER_ENABLE);

	/* Ensure the write of sys register is visible */
	isb();
}

static inline void gtimer_disable(void)
{
	set_el0(cntv_ctl, get_el0(cntv_ctl) & ~GT_TIMER_ENABLE);

	isb();
}

static inline void gtimer_clear_status(void)
{
	set_el0(cntv_ctl, get_el0(cntv_ctl) & ~GT_TIMER_IRQ_STATUS);

	isb();
}

static inline void gtimer_update_compare_value(uint64_t new_val)
{
	set_el0(cntv_cval, new_val);

	isb();
}

static inline void gtimer_update_timer_value(uint64_t new_val)
{
	set_el0(cntv_tval, new_val);

	isb();
}

static inline void gtimer_mask_irq(void)
{
	set_el0(cntv_ctl, get_el0(cntv_ctl) | GT_TIMER_MASK_IRQ);

	isb();
}

static inline void gtimer_unmask_irq(void)
{
	set_el0(cntv_ctl, get_el0(cntv_ctl) & ~GT_TIMER_MASK_IRQ);

	isb();
}

/*
 * arm generic timer has a 64bit counter reg, we don't need do anything else.
 */
void tn_sysclock_isr_notify(void) {}

void tn_sysclock_mask_irq(void)
{
	gtimer_mask_irq();
}

void tn_sysclock_unmask_irq(void)
{
	gtimer_unmask_irq();
}

#ifdef CONFIG_ARM64_ERRATUM_858921
/*
 * The errata #858921 describes that Cortex-A73 (r0p0 - r0p2) counter
 * read can return a wrong value when the counter crosses a 32bit boundary.
 * But newer Cortex-A73 are not affected.
 *
 * The workaround involves performing the read twice, compare bit[32] of
 * the two read values. If bit[32] is different, keep the first value,
 * otherwise keep the second value.
 */
uint64_t tn_sysclock_get_counts(void)
{
	uint64_t val_1st, val_2nd;

	val_1st = get_el0(cntvct);
	val_2nd = get_el0(cntvct);
	return (((val_1st ^ val_2nd) >> 32) & 1) ? val_1st : val_2nd;
}
#else
uint64_t tn_sysclock_get_counts(void)
{
	return get_el0(cntvct);
}
#endif

void tn_sysclock_set_next(uint64_t set_counts, uint8_t is_start __unused)
{
	gtimer_clear_status();

	gtimer_update_compare_value(set_counts);
}

static inline uint32_t sysclock_get_frequency(int fdt_timer)
{
	int len;
	const uint64_t *fdt_freq;

	/*
	 * On a few platforms the frequency is not configured correctly
	 * by the firmware. A property in the DT (clock-frequency) has
	 * been introduced to workaround those firmware.
	 */
	fdt_freq = fdt_getprop((void *)ukplat_bootinfo_get()->dtb, fdt_timer,
			       "clock-frequency", &len);
	if (!fdt_freq || (len <= 0)) {
		uk_pr_info(
		    "No clock-frequency found, reading from register.\n");

		/* No workaround, get from register directly */
		return get_el0(cntfrq);
	}

	return fdt32_to_cpu(fdt_freq[0]);
}

int tn_sysclock_probe(void)
{
	int ret, offs;

	/* Currently, we only support 1 timer per system */
	offs = fdt_node_offset_by_compatible_list(
	    (void *)ukplat_bootinfo_get()->dtb, -1, sysclock_list);
	if (unlikely(offs < 0)) {
		uk_pr_crit("Could not find arch timer (%d)\n", offs);
		return 1;
	}

	/* Get counter frequency from DTB or register (in Hz) */
	freq = sysclock_get_frequency(offs);

	ret = uk_intctlr_irq_fdt_xlat((void *)ukplat_bootinfo_get()->dtb, offs,
				      2, &irq);
	if (unlikely(ret < 0)) {
		uk_pr_crit("Could not get IRQ from dtb (%d)\n", ret);
		return 1;
	}
	uk_intctlr_irq_set_trigger(&irq);
	irq.id = irq.id;
	irq.trigger = UK_INTCTLR_IRQ_TRIGGER_LEVEL;

	/*
	 * Mask IRQ before scheduler start working. Otherwise we will get
	 * unexpected timer interrupts when system is booting.
	 */
	gtimer_mask_irq();

	tn_systick_register(sysclock_name, freq, &irq);
	gtimer_enable();

	return 0;
}
