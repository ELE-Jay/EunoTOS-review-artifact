/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * Copyright (c) 2017, NEC Europe Ltd., NEC Corporation. All rights reserved.
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

#ifndef __UKPLAT_LCPU_H__
#define __UKPLAT_LCPU_H__

#include <uk/arch/time.h>
#include <uk/arch/lcpu.h>
#include <uk/essentials.h>
#include <uk/plat/offset.h>
#include <uk/config.h>
#include <uk/arch/types.h>
#include <uk/plat/spinlock.h>
#include <uk/list.h>
#if defined(__X86_64__)
#include <x86/lcpu_defs.h>
#endif /* __X86_64__ */

#ifdef __cplusplus
extern "C" {
#endif

extern struct tn_bootstrap_cpu bootstrap_cpu_record;

/**
 * Return the LCPU structure for the CPU executing this function
 */
struct lcpu *lcpu_get_current(void);

/**
 * Enables interrupts
 */
void ukplat_lcpu_enable_irq(void);

/**
 * Disables interrupts
 */
void ukplat_lcpu_disable_irq(void);

/**
 * Returns current interrupt flags and disables them
 *
 * @return interrupt flags (the format is unspecified)
 */
unsigned long ukplat_lcpu_save_irqf(void);

/**
 * Loads interrupt flags
 *
 * @param flags interrupt flags (the format is unspecified)
 */
void ukplat_lcpu_restore_irqf(unsigned long flags);

/**
 * Checks if interrupts are disabled
 *
 * @return non-zero value if interrupts are disabled
 */
int ukplat_lcpu_irqs_disabled(void);

/**
 * Halts the current logical CPU execution
 */
void __noreturn ukplat_lcpu_halt(void);

/**
 * Halts the current logical CPU. Execution is resumed when an interrupt/signal
 * arrives or the specified deadline expires
 *
 * NOTE: This must be called with IRQ's disabled. On return, IRQ's are not
 *        re-enabled.
 *
 * @param until deadline in nanoseconds
 */
void ukplat_lcpu_halt_irq_until(__nsec until);

/**
 * Halts the current logical CPU. Execution is resumed when an interrupt/signal
 * arrives.
 *
 * NOTE: This must be called with IRQ's disabled. On return, IRQ's are not
 *        re-enabled.
 */
void ukplat_lcpu_halt_irq(void);

/**
 * Returns the number of logical CPUs has already initialized in the system
 *
 * @return the number of initialized cpu
 *
 * @note the return value changes during cpu initialization,
 * 	 and will be total count in final
 */
__u32 ukplat_lcpu_count(void);

/* Non-prototyped logical CPU entry function */
typedef void __noreturn (*ukplat_lcpu_entry_t)();

typedef __u32 __lcpuid;	  /* Logical CPU for kernel management*/
typedef __u64 __lcpuid_p; /* Physical ID of logical CPU */

#ifndef CONFIG_HAVE_SCHED
/**
 * When scheduler is not present, save the current thread
 * to switch back, and switch to next thread.
 *
 * @note
 * This context-switching API is typically used
 * only in scenarios without a scheduler,
 * where secondary cores wake up and switch to user-defined threads.
 * It is not recommended for use in other scenarios.
 * @return
 *   NULL
 */
void lcpu_switch_to(void);
#endif

#ifdef CONFIG_HAVE_SMP

struct ukplat_lcpu_func {
	/**
	 * Function to execute.
	 *
	 * @param regs pointer to a snapshot of the current CPU register state.
	 *    Changes to the registers are applied after the RUN IRQ handler
	 *    returns. The parameter might be NULL if the platform does not
	 *    support supplying a register snapshot.
	 * @param arg user-supplied argument
	 */
	void (*fn)(struct __regs *regs, void *arg);

	/* Optional user-supplied argument. */
	void *user;
};

/**
 * Starts multiple logical CPUs and assigns them the given stacks. The logical
 * CPUs execute the entry functions if supplied or enter a low-power wait state
 * otherwise. CPUs that have already been started are ignored.
 *
 * @param lcpuid array with the indices of the logical CPUs that are to be
 *   started. CPUs are started in the order specified in the array. Can be NULL
 *   to include all logical CPUs except the one executing the function, in which
 *   case CPUs are started in sequential order according to their CPU index
 * @param[inout] num if lcpuid is not NULL, provides [IN] the number of
 *   elements in lcpuid, and [OUT] the number of successfully started CPUs in
 *   sequential order of lcpuid. If the call succeeds, input and output values
 *   are equal. Must be NULL if lcpuid is NULL
 * @param sp array of stack pointers, one for each logical CPU to start. If
 *   lcpuid is NULL, must be ukplat_lcpu_count() - 1 stack pointers. The
 *   stacks may be specifically prepared to contain arguments for the entry
 *   function (e.g., cdecl calling convention). The platform may use the
 *   following stack space to execute initialization routines
 * @param entry array of entry functions, one for each logical CPU to start.
 *   Can be NULL, otherwise if lcpuid is NULL, must contain
 *   ukplat_lcpu_count() - 1 function pointers. Provided functions must not
 *   return. If the parameter or individual function pointers are NULL the
 *   respective logical CPUs enter a low-power wait state after startup
 * @param flags (architecture-dependent) flags that specify how to start the
 *   CPUs (see UKPLAT_LCPU_SFLG_* flags if available)
 *
 * @return 0 on success, an errno-type error value otherwise
 */
int ukplat_lcpu_start(const __lcpuid lcpuid[],
		      unsigned int *num,
		      void *sp[],
		      const ukplat_lcpu_entry_t entry[],
		      unsigned long flags);

/**
 * Waits for the specified logical CPUs to enter idle state, or until the
 * timeout expires.
 *
 * @param lcpuid array with the indices of the logical CPUs to wait for. Can
 *   be NULL to include all logical CPUs except the one executing the function
 * @param[inout] num if lcpuid is not NULL, provides [IN] the number of
 *   elements in lcpuid, and [OUT] the number of CPUs in idle state until the
 *   timeout expired in sequential order of lcpuid. If the call succeeds,
 *   input and output values are equal. Must be NULL if lcpuid is NULL
 * @param timeout timeout in nanoseconds for the wait to be satisfied. Can be
 *   0 to wait indefinitely
 *
 * @return 0 if the wait for all specified logical CPUs has been satisfied,
 *   an errno-type error value otherwise (e.g., timeout)
 */
int ukplat_lcpu_wait(const __lcpuid lcpuid[],
		     unsigned int *num,
		     __nsec timeout);

/**
 * Executes a function on the specified logical CPU.
 *
 * @param lcpuid Index of the logical CPU to execute the function on.
 * @param fn The function to be executed.
 * @param flags (architecture-dependent) flags that specify how the function
 *   should be executed (see UKPLAT_LCPU_RFLG_* flags).
 *
 * @return 0 on success, an errno-type error value otherwise.
 */
int ukplat_lcpu_run_core(__lcpuid id, const struct ukplat_lcpu_func *fn,
						 unsigned long flags);

/**
 * Runs a function on all logical CPUs except the current one.
 *
 * @param fn The function to be executed.
 * @param flags (architecture-dependent) flags that specify how the function
 *   should be executed (see UKPLAT_LCPU_RFLG_* flags).
 *
 * @return 0 on success, an errno-type error value otherwise.
 */
int ukplat_lcpu_run_all(const struct ukplat_lcpu_func *fn, unsigned long flags);

/* Do not block while trying to queue the function to the remote core */
#define UKPLAT_LCPU_RFLG_DONOTBLOCK	0x1

/**
 * Wakes up the specified logical CPUs from a halt or low-power sleep state.
 *
 * @param lcpuid array with the indices of the logical CPUs that should be
 *   woken up. Can be NULL to wakeup all logical CPUs except the current one
 * @param[inout] num if lcpuid is not NULL, provides [IN] the number of
 *   elements in lcpuid, and [OUT] the number of successfully woken up CPUs in
 *   sequential order of lcpuid. If the call succeeds, input and output values
 *   are equal. Must be NULL if lcpuid is NULL
 *
 * @return 0 on success, an errno-type error value otherwise
 */
int ukplat_lcpu_wakeup(const __lcpuid lcpuid[], unsigned int *num);

void ukplat_lcpu_switch_to_thread(struct __regs *regs __unused,
								  void *arg			  __unused);
#endif /* CONFIG_HAVE_SMP */

/**
 * Convert the physical id of a cpu to a unique numerical index. The conversion
 * algorithm is determined by plat or arch implementations. E.g., for arm
 * cortex-a55 with 4 cores, mapping between physical cpuid(in MPIDR_EL1) and
 * the index could be:
 *        physical cpuid         index
 *         0.0.0.0                 0
 *         0.0.1.0                 1
 *         0.0.2.0                 2
 *         0.0.3.0                 3
 * and for arm cortex-a53 with 2 cores, mapping between physical cpuid and
 * the index could be:
 *        physical cpuid         index
 *         0.0.0.0                 0
 *         0.0.0.1                 1
 *
 * @param cpuid The physical id of a cpu
 *
 * @return The mapped index
 *
 */
unsigned int tnplat_lcpu_physical_index(__lcpuid_p cpuid);

/* Per-LCPU variable definition */

#define UKPLAT_PER_LCPU_DEFINE(var_type, var_name) \
	var_type var_name[CONFIG_UKPLAT_LCPU_MAXCOUNT]
#define ukplat_per_lcpu(var_name, lcpu_idx) \
	var_name[lcpu_idx]
#define ukplat_per_lcpu_current(var_name) \
	ukplat_per_lcpu(var_name, lcpu_get_current()->id)

#define UKPLAT_PER_LCPU_ARRAY_DEFINE(var_type, var_name, size) \
	var_type var_name[CONFIG_UKPLAT_LCPU_MAXCOUNT][size]
#define ukplat_per_lcpu_array(var_name, lcpu_idx, idx) \
	var_name[lcpu_idx][idx]
#define ukplat_per_lcpu_array_current(var_name, idx) \
	ukplat_per_lcpu_array(var_name, lcpu_get_current()->id, idx)

/*
 * LCPU Startup Arguments
 */
#define LCPU_SARGS_SIZE 0x18
#define LCPU_BOOT_ARGS_SIZE 0x18
#ifdef CONFIG_HAVE_SMP
#define LCPU_FUNC_SIZE 0x10
#endif /* CONFIG_HAVE_SMP */

/*
 * Provide empty architecture-dependent LCPU part as default
 */
struct lcpu_arch {};

/*
 * This structure is used for secondary lcpus early boot-up
 */
struct lcpu_sargs {
	ukplat_lcpu_entry_t entry;
	void *stackp;
	struct lcpu		   *secondary_lcpu;
};

struct tn_bootstrap_cpu {
	/* store bootstrap cpu physical id */
	__lcpuid_p physical_id;
};

struct lcpu_boot_args {
	union {
		/* Startup arguments
		 * Only valid in LCPU_STATE_INIT
		 */
		struct lcpu_sargs s_args;

		/* Remote function to execute
		 * Only valid in LCPU_STATE_IDLE and busy states
		 */
#ifdef CONFIG_HAVE_SMP
		struct ukplat_lcpu_func fn;
#endif /* CONFIG_HAVE_SMP */

		/* Error code indicating the halt reason
		 * Only valid in LCPU_STATE_HALTED
		 */
		int error_code;
	};
};

UK_CTASSERT(sizeof(struct lcpu_sargs) == LCPU_SARGS_SIZE);
UK_CTASSERT(sizeof(struct lcpu_boot_args) == LCPU_BOOT_ARGS_SIZE);
#ifdef CONFIG_HAVE_SMP
UK_CTASSERT(sizeof(struct ukplat_lcpu_func) == LCPU_FUNC_SIZE);
#endif /* CONFIG_HAVE_SMP */

UK_CTASSERT(__offsetof(struct lcpu_sargs, entry)
	    == BOOT_ARGS_SARGS_ENTRY_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu_sargs, stackp)
	    == BOOT_ARGS_SARGS_STACKP_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu_sargs, secondary_lcpu) ==
			BOOT_ARGS_SARGS_CPU_OFFSET);

UK_CTASSERT(__offsetof(struct lcpu_boot_args, s_args.entry)
	    == BOOT_ARGS_SARGS_ENTRY_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu_boot_args, s_args.stackp)
	    == BOOT_ARGS_SARGS_STACKP_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu_boot_args, s_args.secondary_lcpu) ==
			BOOT_ARGS_SARGS_CPU_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu_boot_args, error_code)
	    == BOOT_ARGS_ERR_OFFSET);

/*
 * Logical CPU (LCPU) Structure
 */

#define IS_LCPU_PTR(ptr)                                                       \
	(IN_RANGE((__uptr)(ptr), (__uptr)lcpu_get(0),                          \
		  (__uptr)CONFIG_UKPLAT_LCPU_MAXCOUNT * sizeof(struct lcpu)))
/**
 * LCPU States
 * The following state transitions are safe to execute.
 *
 *                         lcpu_init
 *                   ┌───────────────────┐lcpu_run
 *        lcpu_start │          ┌──────┐ │ ┌─────┐   ┌────
 * ┌─────────┐   ┌───┴──┐   ┌───┴──┐ ┌─▼─▼─┴─┐ ┌─▼───┴─┐
 * │ OFFLINE ├──►│ INIT │   │ IDLE │ │ BUSY0 │ │ BUSY1 │
 * └─────────┘   └───┬──┘   └─┬─▲──┘ └─┬─┬─▲─┘ └─┬─┬─▲─┘
 *                   │        │ └──────┘ │ └─────┘ │ └────
 * ┌────────┐        │        │          │ RUN_IRQ │
 * │ HALTED │◄───────┴────────┴──────────┴─────────┴──────
 * └────────┘        lcpu_halt (ONLY ALLOWED FOR THIS CPU)
 */
#define LCPU_STATE_HALTED -1 /* CPU stopped, needs reset */
#define LCPU_STATE_OFFLINE 0 /* CPU not started */
#define LCPU_STATE_INIT 1    /* CPU started, init not finished */
#define LCPU_STATE_IDLE 2    /* CPU is idle */
#define LCPU_STATE_BUSY0 3   /* >= CPU is busy */

struct __align(CACHE_LINE_SIZE) lcpu
{
	/* point to the thread currently running on this lcpu */
	struct uk_thread *current_thread;

	/* counter for critical region */
	uint32_t critical_nested;

	/* counter for interrupt */
	uint32_t interrupt_nested;

	/* stack point for exception*/
	uintptr_t exception_sp;

	/* stack point for interrupt*/
	uintptr_t interrupt_sp;

#ifdef CONFIG_HAVE_SCHED
	/* idle thread */
	struct uk_thread *idle_thread;
#else
	union {
		/* The thread to be switched */
		struct uk_thread *switch_to;
		/* The thread restored and to be switched back */
		struct uk_thread *switch_back;
	};
#endif

	/* there's pending context switch request */
	uint8_t pending_switch;

	/* internal logical cpu id for kernel management */
	__lcpuid id;

	/* physical cpu id in MPIDR_EL1 */
	__lcpuid_p physical_id;

	/* Current CPU state (LCPU_STATE_*).
	 * Working on it with atomic instructions - must be 8-byte aligned
	 */
	volatile int state __align(8);

	/* Architecture-dependent part */
	struct lcpu_arch arch;
};

UK_CTASSERT(sizeof(struct lcpu) == LCPU_SIZE);
UK_CTASSERT(LCPU_MEMBERS_SIZE <= LCPU_SIZE);

UK_CTASSERT(__offsetof(struct lcpu, current_thread)
	    == LCPU_CURRENT_THREAD_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, critical_nested)
	    == LCPU_CRITICAL_NESTED_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, interrupt_nested)
	    == LCPU_INTERRUPT_NESTED_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, exception_sp) == LCPU_EXCEPTION_SP_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, interrupt_sp) == LCPU_INTERRUPT_SP_OFFSET);
#ifdef CONFIG_HAVE_SCHED
UK_CTASSERT(__offsetof(struct lcpu, idle_thread) == LCPU_IDLE_OFFSET);
#else
UK_CTASSERT(__offsetof(struct lcpu, switch_to) == LCPU_SWITCH_TO_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, switch_back) == LCPU_SWITCH_BACK_OFFSET);
#endif
UK_CTASSERT(__offsetof(struct lcpu, pending_switch)
	    == LCPU_PENGDING_SWITCH_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, id) == LCPU_ID_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, physical_id) == LCPU_PHYSICAL_ID_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, state) == LCPU_STATE_OFFSET);
UK_CTASSERT(__offsetof(struct lcpu, arch) == LCPU_ARCH_OFFSET);


/**
 * Return 1 if the given LCPU is online, 0 otherwise
 */
static inline int lcpu_state_is_online(int state)
{
	return (state >= LCPU_STATE_IDLE);
}

/**
 * Return 1 if the given LCPU is busy, 0 otherwise.
 * NOTE: The negation (i.e., the LCPU is idle) does not have be true!
 */
static inline int lcpu_state_is_busy(int state)
{
	return (state >= LCPU_STATE_BUSY0);
}

/**
 * Allocate a logical CPU and assign the provided CPU ID. This function may
 * only be called from one thread running on the bootstrap processor before
 * secondary CPUs are started.
 *
 * @param physical_id hardware ID of the CPU.
 *
 * @return a LCPU structure with initialized value on success; NULL on failure.
 */
struct lcpu *lcpu_alloc(__lcpuid_p physical_id);

/**
 * Return the LCPU structure for the logical CPU with the given id.
 *
 * @param id the id of the requested LCPU. The id must be less than
 *    the value returned by ukplat_lcpu_count(), otherwise behavior is
 *    undefined
 * @return pointer to the requested LCPU structure
 */
struct lcpu *lcpu_get(__lcpuid id);

#define _lcpu_lcpuid_list_entry(list, i, n)                                    \
	(((i) < (n)) ? lcpu_get((list) ? (list)[i] : (__lcpuid)(i)) : NULL)

#define lcpu_lcpuid_list_foreach(list, num, n, i, lcpu)                        \
	if ((num) == NULL) {                                                   \
		UK_ASSERT(!(list));                                            \
		(n) = ukplat_lcpu_count();                                     \
	} else {                                                               \
		UK_ASSERT((*num) <= ukplat_lcpu_count());                      \
		(n) = *(num);                                                  \
	}                                                                      \
	for ((i) = 0, ({                                                       \
		     if (num)                                                  \
			     *num = i;                                         \
	     }),                                                               \
	    (lcpu) = _lcpu_lcpuid_list_entry(list, i, n);                      \
	     (i) < (n); (i)++, ({                                              \
				if (num)                                       \
					*num = i;                              \
			}),                                                    \
	    (lcpu) = _lcpu_lcpuid_list_entry(list, i, n))

static inline __lcpuid_p get_bootstrap_cpu_physical_id(void)
{
	return bootstrap_cpu_record.physical_id;
}

/**
 * Return 1 if the supplied LCPU is the bootstrap processor, 0 otherwise
 */
static inline int lcpu_is_bsp(struct lcpu *lcpu)
{
	return (lcpu->physical_id == get_bootstrap_cpu_physical_id());
}

/**
 * Return 1 if the executed on the bootstrap processor, 0 otherwise
 */
static inline int lcpu_current_is_bsp(void)
{
	return lcpu_is_bsp(lcpu_get_current());
}

/**
 * Initialize a logical CPU. The function must be executed on the CPU
 * represented by the LCPU as early as possible after startup.
 *
 * @param this_lcpu pointer to the LCPU structure representing the CPU
 *    executing this function
 * @return 0 on success, -errno otherwise
 */
int lcpu_init(struct lcpu *this_lcpu);

#ifdef CONFIG_HAVE_SMP
/* The IRQ vectors passed to lcpu_mp_init */
extern const unsigned long *const lcpu_run_irqv;
extern const unsigned long *const lcpu_wakeup_irqv;

/**
 * Initialize multi-processor functions. Must only be executed once on the
 * bootstrap processor (BSP)
 *
 * @param run_irq the IRQ vector to use for running remote functions
 * @param wakeup_irq the IRQ vector to use for waking up CPUs
 * @param arg an optional parameter from the boot code that is passed to the
 *    architectural initialization
 *
 * @return 0 on success, -errno otherwise
 */
int lcpu_mp_init(unsigned long run_irq, unsigned long wakeup_irq, void *arg);

/**
 * Default entry function for secondary logical CPUs. Will call lcpu_init() and
 * If the logical CPU's startup arguments supply an entry function, the
 * original stack pointer will be restored and execution continues in the
 * supplied entry function with interrupts still disabled. Otherwise, interrupts
 * are enabled and the CPU enters a low-power state to wait for interrupts and
 * calls of ukplat_lcpu_run_x() that are destined for this CPU.
 *
 * NOTE: The function may be replaced with a custom implementation by
 *    overriding the function symbol.
 *
 * NOTE: The architecture's CPU startup code (typically an assembler trampoline)
 *    must jump to this function with interrupts disabled and prepare the stack
 *    and/or registers according to the respective calling convention to
 *    provide the following parameters:
 *
 * @param this_lcpu pointer to the LCPU structure representing the CPU
 *    executing this function
 */
void __noreturn lcpu_entry_default(struct lcpu *this_lcpu);

/**
 * Enqueue a function to the supplied LCPU
 *
 * @param lcpu the LCPU to enqueue the function to
 * @param fn the function to enqueue
 *
 * @return 0 on success, -errno otherwise
 */
int lcpu_fn_enqueue(struct lcpu *lcpu,
		    const struct ukplat_lcpu_func *fn,
		    unsigned long cpuidx);
#endif /* CONFIG_HAVE_SMP */

/*
 * Definitions that must be satisfied by the architectural implementation.
 * DO NOT CALL DIRECTLY. Use the ukplat_* and lcpu_* non-architectural versions.
 */

/**
 * Return the hardware ID of the CPU executing this function. Must be able to
 * return the ID of the bootstrap processor without initialization of the MP
 * functions.
 */
__lcpuid_p lcpu_arch_id(void);

struct lcpu *ukarch_lcpu_current(void);

/**
 * Initialize the architectural part of the LCPU. The function is
 * executed on the CPU represented by the LCPU as part of lcpu_init().
 *
 * @param this_lcpu pointer to the LCPU structure representing the CPU
 *    executing this function
 * @return 0 on success, -errno otherwise
 */
int lcpu_arch_init(struct lcpu *this_lcpu);

/**
 * Switch to the specified stack and jump to the entry function
 *
 * @param sp new stack pointer
 * @param entry the function to jump to
 */
void __noreturn lcpu_arch_jump_to(void *sp, ukplat_lcpu_entry_t entry);

#ifdef CONFIG_HAVE_SMP
/**
 * Initialize the architectural part of the multi-processor functions. This
 * should perform CPU discovery and call lcpu_alloc() for each discovered CPU.
 * The bootstrap processor is already allocated with index 0 and must not be
 * added.
 *
 * @param arg an optional parameter from the boot code. Can be NULL
 * @return 0 on success, -errno otherwise
 */
int lcpu_arch_mp_init(void *arg);

/**
 * Start the given logical CPU. The CPU should execute the entry function
 * with the supplied stack. The CPU will be in INIT state.
 *
 * @param lcpu logical CPU to start
 * @param flags flags for controling how to start the given CPU
 *    (see UKPLAT_LCPU_SFLG_* if available)
 *
 * @return 0 on success, -errno otherwise
 */
int lcpu_arch_start(struct lcpu *lcpu,
		    unsigned long flags,
		    struct lcpu_boot_args *bootargs);

#ifdef LCPU_ARCH_MULTI_PHASE_STARTUP
/**
 * An optional post start routine that is invoked by ukplat_lcpu_start() after
 * issuing a start command to all specified logical CPUs. This can be used on
 * architectures that have a multi-phase startup sequence like x86.
 *
 * @param lcpuid the list of logical CPU indices specified in the call to
 *	ukplat_lcpu_start()
 * @param num the number of entries in the list
 *
 * @return 0 on success, -errno otherwise
 */
int lcpu_arch_post_start(const __lcpuid lcpuid[], unsigned int *num);
#endif /* LCPU_ARCH_MULTI_PHASE_STARTUP */

/**
 * Queue a function to the given logical CPU and send a run IRQ. The
 * implementation may also choose to handle the execution of the function
 * differently, for example, if certain flags are applied.
 *
 * @param lcpu the target logical CPU which should execute the function
 * @param fn the function to execute on the remote CPU
 * @param flags flags that control how the function should be run
 *    (see UKPLAT_LCPU_RFLG_* if available)
 *
 * @return 0 on success, -errno otherwise
 */
int lcpu_arch_run(struct lcpu *lcpu,
		  const struct ukplat_lcpu_func *fn,
		  unsigned long flags);

/**
 * Send a wakeup IRQ to the specified logical CPU. The wakeup IRQ may be
 * implemented in such a way that the IRQ handler just acknowledges the IRQ and
 * immediately returns to keep the overhead minimal. However, in that case, it
 * must be guaranteed that no other IRQs (e.g., for devices) use the same
 * vector.
 *
 * @param lcpu pointer to the LCPU structure of the CPU to wake up
 * @return 0 on success, -errno otherwise
 */
int lcpu_arch_wakeup(struct lcpu *lcpu);
#endif /* CONFIG_HAVE_SMP */

#ifdef __cplusplus
}
#endif

#endif /* __UKPLAT_LCPU_H__ */
