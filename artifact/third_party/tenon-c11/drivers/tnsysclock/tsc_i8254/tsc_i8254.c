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

#include <uk/plat/common/cpu.h>
#include <uk/intctlr.h>
#include <tn/systick_impl.h>

#define TIMER_CNTR 0x40
#define TIMER_MODE 0x43
#define TIMER_SEL0 0x00
#define TIMER_LATCH 0x00
#define TIMER_RATEGEN 0x04
#define TIMER_ONESHOT 0x08
#define TIMER_16BIT 0x30
#define TIMER_HZ 1193182
#define TIMER_DIVISOR_HZ 100
#define i8254_MAX_COUNT 65535

static const char *sysclock_name = "tsc-i8254";
uint64_t tsc_freq;
uint64_t i8254_set_threshold;
struct uk_intctlr_irq irq;

static void sysclock_enable(void)
{
	outb(TIMER_MODE, TIMER_SEL0 | TIMER_ONESHOT | TIMER_16BIT);
	outb(TIMER_CNTR, 0);
	outb(TIMER_CNTR, 0);
}

void tn_sysclock_isr_notify(void){}

void tn_sysclock_mask_irq(void)
{
	uk_intctlr_irq_mask(irq.id);
}

void tn_sysclock_unmask_irq(void)
{
	uk_intctlr_irq_unmask(irq.id);
}

uint64_t tn_sysclock_get_counts(void)
{
	return rdtsc();
}

void tn_sysclock_set_next(uint64_t set_counts, uint8_t set_auto_reload __unused)
{
	uint64_t conuts;
	set_counts = MIN(i8254_set_threshold, set_counts - rdtsc());
	conuts = (set_counts * TIMER_HZ) / tsc_freq;
	outb(TIMER_MODE, TIMER_SEL0 | TIMER_ONESHOT | TIMER_16BIT);
	outb(TIMER_CNTR, (conuts & 0xFF));
	outb(TIMER_CNTR, ((conuts >> 8) & 0xFF));
}

/*
 * Read the current i8254 channel 0 tick count.
 */
static unsigned int i8254_gettick(void)
{
	__u16 rdval;

	outb(TIMER_MODE, TIMER_SEL0 | TIMER_LATCH);
	rdval = inb(TIMER_CNTR);
	rdval |= (inb(TIMER_CNTR) << 8);
	return rdval;
}

/*
 * Delay for approximately n microseconds using the i8254 channel 0 counter.
 * Timer must be programmed appropriately before calling this function.
 */
static void i8254_delay(unsigned int n)
{
	unsigned int cur_tick, initial_tick;
	int remaining;
	const unsigned long timer_rval = TIMER_HZ / TIMER_DIVISOR_HZ;

	initial_tick = i8254_gettick();

	remaining = (unsigned long long)n * TIMER_HZ / 1000000;

	while (remaining > 1) {
		cur_tick = i8254_gettick();
		if (cur_tick > initial_tick)
			remaining -= timer_rval - (cur_tick - initial_tick);
		else
			remaining -= initial_tick - cur_tick;
		initial_tick = cur_tick;
	}
}

uint32_t sysclock_get_frequency(void)
{
	uint64_t freq = 0, base;
	uint32_t eax, ebx, ecx, edx;

	/*
	 * Attempt to retrieve TSC frequency via the hypervisor generic cpuid
	 * timing information leaf. 0x40000010 returns the (virtual) TSC
	 * frequency in kHz, or 0 if the feature is not supported by the
	 * hypervisor.
	 */
	cpuid(0x40000000, 0, &eax, &ebx, &ecx, &edx);
	if (eax >= 0x40000010) {
		uk_pr_info("Retrieving TSC clock frequency from hypervisor\n");
		base = rdtsc();
		cpuid(0x40000010, 0, &eax, &ebx, &ecx, &edx);
		freq = eax * 1000;
	}

	/*
	 * If we could not retrieve the TSC frequency from the hypervisor,
	 * calibrate against an 0.1s delay using the i8254 timer. This is
	 * undesirable as it delays the boot sequence.
	 */
	if (!freq) {
		uk_pr_info("Calibrating TSC clock against i8254 timer\n");

		/*
		 * Initialise i8254 timer channel 0 to mode 2 at
		 * TIMER_DIVISOR_HZ frequency
		 */
		outb(TIMER_MODE, TIMER_SEL0 | TIMER_RATEGEN | TIMER_16BIT);
		outb(TIMER_CNTR, (TIMER_HZ / TIMER_DIVISOR_HZ) & 0xff);
		outb(TIMER_CNTR, (TIMER_HZ / TIMER_DIVISOR_HZ) >> 8);

		base = rdtsc();
		i8254_delay(100000);
		freq = (rdtsc() - base) * 10;
	}

	return freq;
}

int tn_sysclock_probe(void)
{
	irq.id = 0;
	irq.trigger = UK_INTCTLR_IRQ_TRIGGER_LEVEL;
	uk_intctlr_irq_set_trigger(&irq);

	tsc_freq = sysclock_get_frequency();
	i8254_set_threshold =
	    (MIN(i8254_MAX_COUNT * tsc_freq, UINT64_MAX)) / TIMER_HZ;
	/*
	 * Mask IRQ before scheduler start working. Otherwise we will get
	 * unexpected timer interrupts when system is booting.
	 */
	tn_sysclock_mask_irq();

	tn_systick_register(sysclock_name, tsc_freq, &irq);

	sysclock_enable();
	return 0;
}
