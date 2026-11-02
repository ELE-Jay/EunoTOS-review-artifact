/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *          Marc Rittinghaus <marc.rittinghaus@kit.edu>
 *          Răzvan Vîrtan <virtanrazvan@gmail.com>
 *          Cristian Vijelie <cristianvijelie@gmail.com>
 *
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation. All rights reserved.
 * Copyright (c) 2022, Karlsruhe Institute of Technology (KIT)
 *                     All rights reserved.
 * Copyright (c) 2022, University Politehnica of Bucharest.
 *                     All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <uk/essentials.h>
#include <uk/atomic.h>
#if CONFIG_HAVE_SMP
#include <uk/intctlr.h>
#ifdef CONFIG_HAVE_SCHED
#include <uk/sched.h>
#endif
#endif /* CONFIG_HAVE_SMP */
#include <uk/plat/lcpu.h>
#include <uk/plat/time.h>
#include <uk/plat/common/cpu.h>
#include <uk/plat/common/_time.h>
#include <uk/print.h>
#include <uk/bitops.h>
#ifndef CONFIG_HAVE_SCHED
#include <uk/thread.h>
#endif
#include <limits.h>
#include <errno.h>

static unsigned long lcpu_affinity_bitmap[UK_BITS_TO_LONGS(CONFIG_UKPLAT_PCPU_MAXCOUNT)];

/**
 * Array of LCPUs, one for every CPU in the system.
 *
 * TODO: Preferably have a more flexible solution that does not waste memory
 * for non-present CPUs and does not force us to configure the maximum number
 * of CPUs beforehand.
 */
UKPLAT_PER_LCPU_DEFINE(struct lcpu, lcpus);

/*
 * Array of CPU startup parameters, one for every CPU
 * Only used when secondary cpus starting
 */
UKPLAT_PER_LCPU_DEFINE(struct lcpu_boot_args, boot_args);

struct tn_bootstrap_cpu bootstrap_cpu_record = {
	.physical_id = 0,
};

/**
 * Number of allocated logical CPUs in the system.
 *
 */
static __u32 lcpu_count;

struct lcpu *lcpu_alloc(__lcpuid_p physical_id)
{
	struct lcpu *lcpu;
	int index;

	if (lcpu_count == CONFIG_UKPLAT_LCPU_MAXCOUNT) {
		uk_pr_err("Configured maximum number of cores exceeded(%d).\n",
				CONFIG_UKPLAT_LCPU_MAXCOUNT);
		return NULL;
	}

	index = tnplat_lcpu_physical_index(physical_id);

	if (uk_test_bit(index, lcpu_affinity_bitmap)) {
		uk_pr_err(
			"Allocate logical lcpu failed: \r\n"
			"Duplicate CPU node : (CPU@%lx)", physical_id);
		return NULL;
	}

	uk_set_bit(index, lcpu_affinity_bitmap);

	lcpu = &lcpus[lcpu_count];
	lcpu->state = LCPU_STATE_OFFLINE;
	lcpu->id    = lcpu_count;
	lcpu->physical_id = physical_id;
	lcpu_count++;

	return lcpu;
}

__u32 ukplat_lcpu_count(void)
{
	return lcpu_count;
}

struct lcpu *lcpu_get(__lcpuid id)
{
	UK_ASSERT(id < lcpu_count);

	return &lcpus[id];
}

struct lcpu *lcpu_get_current(void)
{
	return ukarch_lcpu_current();
}

int lcpu_init(struct lcpu *this_lcpu)
{
	int rc;

	/*
	 * NOTE: Do not use anything that might need initialized exception
	 * traps until after lcpu_arch_init(), as traps might not be
	 * initialized for this CPU yet!
	 */

	/* Initialize the bootstrap CPU */
	if (lcpu_is_bsp(this_lcpu)) {
		if (unlikely(lcpu_count > 1))
			return -EPERM;

		this_lcpu->state = LCPU_STATE_INIT;
	} else {
		/* We should already be in INIT state for secondary CPUs */
		UK_ASSERT(this_lcpu->state == LCPU_STATE_INIT);
	}

	/* Not in interrupt process, interrupt nesting level is 0. */
	this_lcpu->interrupt_nested = 0;
	this_lcpu->critical_nested = 0;

	/* Do architecture-specific initialization */
	rc = lcpu_arch_init(this_lcpu);
	if (unlikely(rc))
		return rc;

	UK_ASSERT(ukplat_lcpu_irqs_disabled());

	/* Put the CPU in busy state. This will mark it as online. After this
	 * point, functions may be queued to the CPU. However, IRQs are still
	 * disabled.
	 */
	uk_store_n(&this_lcpu->state, LCPU_STATE_BUSY0);

	/* Write back changes before marking CPU as online */
	wmb();

	return 0;
}

static void __noreturn lcpu_halt(int error_code)
{
	ukplat_lcpu_disable_irq();

	uk_pr_info("CPU%x into Halt state, error code (%d)\n",
			lcpu_get_current()->id, error_code);
	lcpu_get_current()->state = LCPU_STATE_HALTED;
	ukplat_per_lcpu_current(boot_args).error_code = error_code;

	while (1) {
		/* Although we should not be able to recover via regular
		 * interrupts, we might receive NMIs so loop to be safe.
		 */
		halt();
	}
}

void __noreturn ukplat_lcpu_halt(void)
{
	lcpu_halt(0);
}

void ukplat_lcpu_halt_irq_until(__nsec until)
{
	time_block_until(until);
}

#ifndef CONFIG_HAVE_SCHED
void lcpu_switch_to(void)
{
	struct lcpu		 *this_lcpu;
	struct uk_thread *next;
	unsigned long	  flags;

	this_lcpu = lcpu_get_current();

	flags = ukplat_lcpu_save_irqf();
	if (this_lcpu->interrupt_nested) {
		this_lcpu->pending_switch = 1;
		ukplat_lcpu_restore_irqf(flags);
		return;
	}

	/* lcpu->switch_back/switch_to is a union type */
	next = this_lcpu->switch_to;
	/* Writing to switch_back will overwrite switch_to */
	this_lcpu->switch_back = this_lcpu->current_thread;
	/* Secondary cores wake up and switch to
	 * user-defined threads in isr.
	 */
	uk_thread_ctx_switch(this_lcpu->current_thread, next, true);
	ukplat_lcpu_restore_irqf(flags);
}
#endif

#ifdef CONFIG_HAVE_SMP
int lcpu_fn_enqueue(struct lcpu *lcpu, const struct ukplat_lcpu_func *fn,
			unsigned long cpuidx)
{
	int old_state;

	UK_ASSERT(fn->fn);

	old_state = uk_load_n(&lcpu->state);
	/* We expect secondary cpus initialization done,
	 * and in the idle state.
	 */
	if (old_state != LCPU_STATE_IDLE)
		return -EAGAIN;

	/* When the secondary cpu state is IDLE, it means that
	 * the initialization has been completed,
	 * and secondary cpu is in wfi, no interruptions until the startup done.
	 */
	ukplat_per_lcpu(boot_args, cpuidx).fn.fn = fn->fn;

	/* We have acquired the slot! Also store the user argument.
	 * It is safe to do it afterwards, because the RUN IRQ handler will
	 * only take one function and return afterwards. And we only raise the
	 * IRQ after finishing setup.
	 */
	ukplat_per_lcpu(boot_args, cpuidx).fn.user  = fn->user;

	/* Ensure everything is written back when we return and the arch
	 * support code will raise the IRQ
	 */
	wmb();

	return 0;
}

static void lcpu_fn_dequeue(struct ukplat_lcpu_func *fn)
{
	*fn = ukplat_per_lcpu_current(boot_args).fn;

	/* Ensure that we have captured the whole function object */
	rmb();

	UK_ASSERT(fn->fn);

	/* Free the slot. Another function object can be queued afterwards */
	ukplat_per_lcpu_current(boot_args).fn.fn = NULL;
}

static int lcpu_ipi_run_handler(void *args __unused)
{
	struct lcpu *this_lcpu = lcpu_get_current();
	struct ukplat_lcpu_func fn;

	lcpu_fn_dequeue(&fn);

	/* TODO: Provide the register snapshot from the trap frame */
	fn.fn(NULL, fn.user);

	/* secondary cores' state changed into busy by
	 * bootstrap cpu, so just wait here.
	 */
	while (!(lcpu_state_is_busy(uk_load_n(&this_lcpu->state))));

	/* If we had a transition from BUSY to HALTED in fn, we would
	 * not reach this code but sit in the error halt loop. We can
	 * thus safely just decrement without worrying about the HALTED
	 * state.
	 */
	uk_dec(&this_lcpu->state);

	return 1;
}

static int lcpu_ipi_wakeup_handler(void *args __unused)
{
	/* Nothing to do */
	return 1;
}

/* We want these to be externally defined as const to clarify that the vectors
 * cannot be changed after initialization. However, we still need them non-const
 * so we can still set them here. While we can do a DECONST and force allocation
 * in .bss, we enter undefined behavior territory. So we just export a const
 * pointer as proxy. This is still faster than calling a getter function and
 * with LTO this will be optimized to a direct access.
 */
static unsigned long _lcpu_run_irqv;
static unsigned long _lcpu_wakeup_irqv;

const unsigned long * const lcpu_run_irqv = &_lcpu_run_irqv;
const unsigned long * const lcpu_wakeup_irqv = &_lcpu_wakeup_irqv;

int lcpu_mp_init(unsigned long run_irq, unsigned long wakeup_irq, void *arg)
{
	int rc;

	/* Make sure this is run on the BSP only */
	UK_ASSERT(lcpu_count == 1);
	UK_ASSERT(lcpu_current_is_bsp());

	/* Initialize architecture-dependent functionality. This will also do
	 * CPU discovery and allocation
	 */
	rc = lcpu_arch_mp_init(arg);
	if (unlikely(rc))
		return rc;

	/* Register the lcpu_run and lcpu_wakeup interrupt handlers */
	rc = uk_intctlr_irq_register(run_irq, lcpu_ipi_run_handler, NULL);
	if (unlikely(rc)) {
		uk_pr_crit("Could not register handler for IPI IRQ %ld\n",
			   run_irq);
		return rc;
	}

	rc = uk_intctlr_irq_register(wakeup_irq, lcpu_ipi_wakeup_handler, NULL);
	if (unlikely(rc)) {
		uk_pr_crit("Could not register handler for wakeup IRQ %ld\n",
			   wakeup_irq);
		return rc;
	}

	_lcpu_run_irqv = run_irq;
	_lcpu_wakeup_irqv = wakeup_irq;

	return 0;
}

void __noreturn lcpu_entry_default(struct lcpu *this_lcpu)
{
	int rc;
	UK_ASSERT(!lcpu_is_bsp(this_lcpu));

	/* Finish initialization. As there is nothing to return to, we
	 * just enter halted state if an error occurs.
	 */
	rc = lcpu_init(this_lcpu);
	if (unlikely(rc))
		lcpu_halt(rc);

	/* We are coming from BUSY0 state and want to transition to
	 * IDLE state. However, there can be functions queued already
	 * so we have to use a decrement here.
	 */
	uk_dec(&this_lcpu->state);

	/* Enable IRQs. If there are functions queued we will
	 * immediately jump to the IRQ handler.
	 */
	ukplat_lcpu_enable_irq();

	/* Besides interrupts in general, the halt can be
	 * interrupted by calls to ukplat_lcpu_run_x().
	 */
	while (1)
		halt();
}

int ukplat_lcpu_start(const __lcpuid lcpuid[],
		      unsigned int *num,
		      void *sp[],
		      const ukplat_lcpu_entry_t entry[],
		      unsigned long flags)
{
	__lcpuid this_cpu_id = lcpu_get_current()->id;
	struct lcpu *lcpu;
	unsigned int i, n, argi = 0;
	const int new = LCPU_STATE_INIT;
	int old;
	int rc = 0;
#ifdef LCPU_ARCH_MULTI_PHASE_STARTUP
	int rc2;
#endif /* LCPU_ARCH_MULTI_PHASE_STARTUP */

	UK_ASSERT(((lcpuid) && (num)) || ((!lcpuid) && (!num)));
	UK_ASSERT(sp);

	lcpu_lcpuid_list_foreach(lcpuid, num, n, i, lcpu)
	{
		if (lcpu->id == this_cpu_id) {
			/* If the caller did not supply an index array, we
			 * assume that we do not have parameters and a stack
			 * for the executing CPU. Otherwise, i.e., if the
			 * caller explicitly put the executing CPU in, we still
			 * ignore it but need to skip the parameters.
			 */
			if (lcpuid)
				argi++;

			continue;
		}

retry:
		old = uk_load_n(&lcpu->state);

		/* We ignore CPUs that are already started */
		if (unlikely(old != LCPU_STATE_OFFLINE)) {
			uk_pr_warn("Failed to start CPU 0x%x: not offline\n", lcpu->id);

			/* Skip CPU and its arguments*/
			argi++;
			continue;
		}

		/* Try to acquire the CPU for initialization. If another thread
		 * was faster, we will return to the state comparison and
		 * report that the CPU is not offline.
		 */
		if (uk_compare_exchange_sync((int *)&lcpu->state, old,
						 new) != new)
			goto retry;

		UK_ASSERT(lcpu->state == LCPU_STATE_INIT);

		/* Setup startup arguments. */

		ukplat_per_lcpu(boot_args, i).s_args.entry =
		(entry && entry[argi]) ? entry[argi] : lcpu_entry_default;
		ukplat_per_lcpu(boot_args, i).s_args.stackp = sp[argi];
		ukplat_per_lcpu(boot_args, i).s_args.secondary_lcpu =
			&ukplat_per_lcpu(lcpus, i);

		/* Ensure that the startup arguments have been written back
		 * before issuing the startup call
		 */
		wmb();

		rc = lcpu_arch_start(lcpu, flags, &ukplat_per_lcpu(boot_args, i));
		if (unlikely(rc)) {
			lcpu->state = LCPU_STATE_HALTED;
			ukplat_per_lcpu(boot_args, i).error_code = rc;

			/* There is a serious problem. Stop here. The caller
			 * can skip the CPU by using the value of *num.
			 */
			uk_pr_err("Failed to start CPU%x with affinity 0x%lx \r\n"
					  "System halt.\n",
					  lcpu->id, lcpu->physical_id);
			break;
		}

		/* Move to next argument */
		argi++;
}

#ifdef LCPU_ARCH_MULTI_PHASE_STARTUP
	/* At this point, i has been set to the number of successfully
	 * started CPUs. So if there has been an error, we won't touch
	 * any CPUs not started.
	 */
	rc2 = lcpu_arch_post_start(lcpuid, &i);
	if (unlikely(rc2)) {
		if (num) {
			UK_ASSERT(i <= *num);
			*num = i;
		}

		/* Return the first error */
		return (rc) ? rc : rc2;
	}
#endif /* LCPU_ARCH_MULTI_PHASE_STARTUP */

	UK_ASSERT(num == NULL || *num == i);
	return rc;
}

static inline int lcpu_transition_safe(struct lcpu *lcpu, int incr)
{
	int old, new;

	/* Transition the CPU to a different busy level. The CPU could not be
	 * online or fall into a halted state at any moment, we thus cannot
	 * just atomically in-/decrement the state. Otherwise, we might corrupt
	 * the non-online state.
	 */
	do {
		old = uk_load_n(&lcpu->state);

		/* We must not change the state if the CPU is not online */
		if (!lcpu_state_is_online(old))
			return 0;

		UK_ASSERT(old <= INT_MAX - incr);
		UK_ASSERT(old >= INT_MIN + incr);
		new = old + incr;

		UK_ASSERT(lcpu_state_is_online(new));
	} while (uk_compare_exchange_sync((int *)&lcpu->state, old,
					      new) != new);

	return 1;
}

int ukplat_lcpu_run_core(__lcpuid id, const struct ukplat_lcpu_func *fn,
						 unsigned long flags)
{
	struct lcpu *lcpu;
	int rc;

	UK_ASSERT(fn);
	UK_ASSERT(id < ukplat_lcpu_count());

	lcpu = &lcpus[id];
	if (!lcpu)
		return -EINVAL;

	/* queue the function and trigger its execution */
	while (1) {
		rc = lcpu_arch_run(lcpu, fn, flags);
		if (unlikely(rc)) {
			/* Retry if function enqueue fails and blocking is allowed */
			if ((rc == -EAGAIN) && (!(flags & UKPLAT_LCPU_RFLG_DONOTBLOCK)))
				continue;

			/* Attempt to transition back one busy level */
			lcpu_transition_safe(lcpu, -1);

			return rc;
		}

		/* Transition state to a higher busy level */
		lcpu_transition_safe(lcpu, 1);

		/* Ensure state transition visibility */
		mb();
		break;
	}

	return 0;
}

int ukplat_lcpu_run_all(const struct ukplat_lcpu_func *fn, unsigned long flags)
{
	__lcpuid	 this_cpu_id = lcpu_get_current()->id;
	unsigned int n, i;
	int			 rc;

	UK_ASSERT(fn);

	n = ukplat_lcpu_count();

	for (i = 0; i < n; i++) {
		if (i == this_cpu_id)
			continue;

		rc = ukplat_lcpu_run_core(i, fn, flags);
		if (rc)
			return rc;
	}

	return 0;
}

int ukplat_lcpu_wait(const __lcpuid lcpuid[],
		     unsigned int *num,
		     __nsec timeout)
{
	__lcpuid this_cpu_id = lcpu_get_current()->id;
	struct lcpu *lcpu;
	unsigned int n, i;
	int state;
	__nsec end;

	UK_ASSERT(((lcpuid) && (num)) || ((!lcpuid) && (!num)));

	if (timeout > 0)
		end = ukplat_monotonic_clock() + timeout;

	lcpu_lcpuid_list_foreach(lcpuid, num, n, i, lcpu)
	{
		if (lcpu->id == this_cpu_id)
			continue;

		/* Perform a busy wait until we reach IDLE state. However, we
		 * do not want to wait on HALTED or OFFLINE CPUs. So we are
		 * continuing while the LCPU is in INIT or BUSY state and the
		 * timeout has not been reached.
		 */
		while (1) {
			state = UK_READ_ONCE(lcpu->state);

			if ((state == LCPU_STATE_OFFLINE) ||
			    (state == LCPU_STATE_HALTED))
				break;

			if (state == LCPU_STATE_IDLE)
				break;

			if (timeout && (ukplat_monotonic_clock() >= end))
				return -ETIMEDOUT; /* Timed out */
		}
	}

	return 0;
}

int ukplat_lcpu_wakeup(const __lcpuid lcpuid[], unsigned int *num)
{
	__lcpuid this_cpu_id = lcpu_get_current()->id;
	struct lcpu *lcpu;
	unsigned int n, i;
	int rc;

	UK_ASSERT(((lcpuid) && (num)) || ((!lcpuid) && (!num)));

	lcpu_lcpuid_list_foreach(lcpuid, num, n, i, lcpu)
	{
		if (lcpu->id == this_cpu_id)
			continue;

		/* We ignore CPUs that are not online. Note that the CPU may
		 * change to HALTED state afterwards. However, that is not a
		 * problem, as the halt loop will return to sleep after the
		 * wakeup
		 */
		if (!lcpu_state_is_online(lcpu->state))
			continue;

		rc = lcpu_arch_wakeup(lcpu);
		if (unlikely(rc))
			return rc;
	}

	return 0;
}

void ukplat_lcpu_switch_to_thread(struct __regs *regs __unused,
								  void *arg			  __unused)
{
#if CONFIG_HAVE_SCHED
	uk_sched_reschedule();
#elif CONFIG_CUSTOM_CPU_ENTRYPOINT
	lcpu_switch_to();
#endif
}
#endif /* CONFIG_HAVE_SMP */
