/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_INTCTLR_H__
#define __UK_INTCTLR_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ASSEMBLY__

#include <stdbool.h>
#include <stdint.h>

#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/plat/lcpu.h>

/**
 * This event is raised before the platform code handles an IRQ. The normal
 * IRQ handling will continue or stop according to the returned `UK_EVENT_*`
 * value.
 * Note: this event is usually raised in an interrupt context.
 */
#define UK_INTCTLR_EVENT_IRQ uk_intctlr_event_irq

/**
 * Register the irq handler in driver layer into the exception vector table
 */
#define tn_intctlr_trap_register(x) __alias(x, trap_el1_irq)

/** The event payload for the #UK_INTCTLR_EVENT_IRQ event */
struct uk_intctlr_event_irq_data {
	/** The registers of the interrupted code */
	struct __regs *regs;
	/** The platform specific interrupt vector number */
	unsigned long irq;
};

enum uk_intctlr_irq_trigger {
	UK_INTCTLR_IRQ_TRIGGER_NONE, /* interpreted as "do not change" */
	UK_INTCTLR_IRQ_TRIGGER_EDGE,
	UK_INTCTLR_IRQ_TRIGGER_LEVEL,
};

extern struct uk_intctlr_desc *uk_intctlr;

/** IRQ descriptor */
struct uk_intctlr_irq {
	unsigned int id;
	unsigned int trigger;
};

/**
 * Interrupt controller driver ops
 *
 * These must be implemented by the interrupt controller
 */
struct uk_intctlr_driver_ops {
	/**
	 * Configure trigger type for an interrupt
	 *
	 * @param irq Interrupt configuration
	 * @return zero on success or negative value on error
	 */
	int (*irq_set_trigger)(struct uk_intctlr_irq *irq);
	int (*fdt_xlat)(const void *fdt, int nodeoffset, __u32 index,
			struct uk_intctlr_irq *irq);
	void (*mask_irq)(unsigned int irq);
	void (*unmask_irq)(unsigned int irq);
	void (*initialize)(void);
	void (*handle)(struct __regs *regs);
	int (*percpu_init)(void);

	/**
	 * Send a SGI to the specified core(s).
	 *
	 * @param sgintid the software generated interrupt id
	 * @param send_to_all
	 * true sending sgi to all cores in the system except "self".
	 * false sending sgi to the specified core.
	 * @param cpuid
	 * This parametr work only when `send_to_all` is false.
	 * @return zero on success , negative value on failure
	 */
	int (*sgi_op)(uint8_t sgintid, bool send_to_all,
				  uint32_t cpuid __maybe_unused);

	/**
	 * set priority for interrupt
	 *
	 * @param irq IRQ to set priority
	 * @param priority priority number value [0..GIC_MAX_IRQ]
	 * smaller priority number indicates a higher priority
	 */
	void (*irq_set_priority)(unsigned int irq, uint8_t priority);

	/**
	 * set affinity for SPI interrupt
	 *
	 * @param irq IRQ to set affinity
	 * @param cpuid target CPU id to cope with SPI
	 */
	void (*irq_set_affinity)(unsigned int irq, uint32_t cpuid);
#if defined(CONFIG_LIBUKINTCTLR_TEST) || defined(CONFIG_LIBUKTEST_ALL)
	/**
	 * Get IRQ priority level in non-secure mode
	 *
	 * @param irq IRQ to get priority
	 * @return IRQ priority level
	 */
	uint8_t (*irq_get_priority)(unsigned int irq);

	/**
	 * Get spi affinity status
	 *
	 * @param irq spi to get affinity
	 * @return spi affinity status
	 */
	uint32_t (*spi_get_affinity)(unsigned int irq);

	/**
	 * Set pending bit to simulate spi being triggered
	 *
	 * @param irq spi to set pending status
	 */
	void (*simulate_spi)(unsigned int irq);
#endif
};

/** Interrupt controller descriptor */
struct uk_intctlr_desc {
	char *name;
	struct uk_intctlr_driver_ops *ops;
};

/** Interrupt handler function */
typedef int (*uk_intctlr_irq_handler_func_t)(void *);

/**
 * Probe the interrupt controller
 *
 * This function must be implemented by the driver
 *
 * @return zero on success or negative value on error
 */
int uk_intctlr_probe(void);

/**
 * Handle an interrupt
 *
 * This function provides a unified interrupt handling implementation.
 * Must be called by the driver's interrupt handling routine.
 *
 * @param regs Register context at the time the interrupt was raised
 * @param irq  Interrupt to handle
 * @return zero on success or negative value on error
 */
void uk_intctlr_irq_handle(struct __regs *regs __maybe_unused,
			   unsigned int irq);

/**
 * Configure trigger type for an interrupt
 *
 * @param irq Interrupt configuration
 * @return zero on success or negative value on error
 */
int uk_intctlr_irq_set_trigger(struct uk_intctlr_irq *irq);

/**
 * Register interrupt controller driver with the uk_intctlr subsystem
 *
 * This function must be called by the driver during probe
 *
 * @param intctlr populated interrupt controller descriptor
 * @return zero on success or negative value on error
 */
int uk_intctlr_register(struct uk_intctlr_desc *intctlr);

/**
 * Initialize the uk_intctlr subsystem
 *
 * Must be called after probing the device via uk_intctlr_probe
 *
 * @param alloc The allocator to use for internal allocations
 * @return zero on success, negative value on failure
 */
int uk_intctlr_init(struct uk_alloc *alloc);

/**
 * Register an interrupt handler
 *
 * @param irq     Interrupt to register handler for
 * @param handler Handler function
 * @param arg     Caller data to be passed to the handler
 */
int uk_intctlr_irq_register(unsigned int irq,
			    uk_intctlr_irq_handler_func_t handler,
			    void *arg);

/**
 * Unregister a previously registered interrupt handler
 *
 * @param irq     Interrupt to register handler for
 * @param handler Handler function
 */
int uk_intctlr_irq_unregister(unsigned int irq,
			      uk_intctlr_irq_handler_func_t handler);

/**
 *  Mask an interrupt
 *
 *  @param irq Interrupt to mask
 */
void uk_intctlr_irq_mask(unsigned int irq);

/**
 *  Unmask an interrupt
 *
 *  @param irq Interrupt to unmask
 */
void uk_intctlr_irq_unmask(unsigned int irq);

/**
 * Allocate IRQs from available pool
 *
 * @param irqs pointer to array of irqs
 * @param sz   number of array elements
 * @return zero on success, or negative value on error
 */
int uk_intctlr_irq_alloc(unsigned int *irqs, __sz count);

/**
 * Free previously allocated IRQs
 *
 * @param irqs pointer to array of irqs
 * @param sz   number of array elements
 * @return zero on success, or negative value on error
 */
int uk_intctlr_irq_free(unsigned int *irqs, __sz count);

/**
 * Translate from `interrupts` fdt node to IRQ descriptor
 *
 * This function is only available for devices that are discoverable
 * via fdt
 *
 * @param fdt pointer to the device tree blob
 * @param nodeoffset offset of `interrupts` node to parse in the fdt
 * @param index the index of the interrupt to retrieve within the node
 * @param irq interrupt descriptor to populate
 * @return zero on success or libfdt error on failure
 */
int uk_intctlr_irq_fdt_xlat(const void *fdt, int nodeoffset, __u32 index,
			    struct uk_intctlr_irq *irq);

/**
 * Handle function for interrupt controller
 *
 * @param regs Resgisters which the interrupt controller needs to handle
 */
void uk_intctlr_handle(struct __regs *regs);

/**
 * Send a SGI to the specified core(s).
 *
 * @param sgintid the software generated interrupt id
 * @param send_to_all
 * true sending sgi to all cores in the system except "self".
 * false sending sgi to the specified core.
 * @param cpuid
 * This parametr work only when `send_to_all` is false.
 * @return zero on success, negative value on failure
 * @note
 * OS is running in a non-secure environment (NS), and only supports SGI IDs
 * in the range of 0-7. SGI IDs 8-15 are typically reserved for secure
 * operations and are not suggested to use in the NS context.
 */
int uk_intctlr_sgi_op(uint8_t sgintid, bool send_to_all,
					  uint32_t cpuid __maybe_unused);

/**
 * extra initialize function for each cpu core
 * @return zero on success , error code on failure
 */
int uk_intctlr_percpu_init(void);

/**
 * set priority for interrupt
 *
 * @param irq           IRQ to set priority
 * @param priority      priority number value [0..GIC_MAX_IRQ]
 * smaller priority number indicates a higher priority
 */
void uk_intctlr_irq_set_priority(unsigned int irq, uint8_t priority);

/**
 * set affinity for SPI interrupt
 *
 * @param irq  SPI Interrupt to set affinity
 * @param cpuid  target CPU id to cope with SPI
 */
void uk_intctlr_irq_set_affinity(unsigned int irq, uint32_t cpuid);

#if defined(CONFIG_LIBUKINTCTLR_TEST) || defined(CONFIG_LIBUKTEST_ALL)
/**
 * Get IRQ priority level in non-secure mode
 *
 * @param irq irq to get priority information
 * @return irq priority level
 */
uint8_t uk_intctlr_irq_get_priority(unsigned int irq);

/**
 * Get spi affinity status
 *
 * @param irq spi to get affinity
 * @return spi affinity status
 */
uint32_t uk_intctlr_spi_get_affinity(unsigned int irq);

/**
 * sets the status of the corresponding
 * peripheral interrupt to pending status
 *
 * @param irq spi to set pending
 */
void uk_intctlr_simulate_spi(unsigned int irq);
#endif

#endif /* __ASSEMBLY__ */

#ifdef __cplusplus
}
#endif

#endif /* __UK_INTCTLR_H__ */
