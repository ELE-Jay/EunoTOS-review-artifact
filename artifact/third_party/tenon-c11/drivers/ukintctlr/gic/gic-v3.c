/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020, OpenSynergy GmbH. All rights reserved.
 *
 * ARM Generic Interrupt Controller support v3 version
 * based on plat/drivers/gic/gic-v2.c:
 *
 * Authors: Wei Chen <Wei.Chen@arm.com>
 *          Jianyong Wu <Jianyong.Wu@arm.com>
 *
 * Copyright (c) 2018, Arm Ltd. All rights reserved.
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
#include <string.h>
#include <libfdt.h>
#include <uk/config.h>
#include <uk/essentials.h>
#include <uk/print.h>
#include <uk/assert.h>
#include <uk/bitops.h>
#include <uk/asm.h>
#include <uk/plat/lcpu.h>
#ifdef CONFIG_UKPLAT_ACPI
#include <uk/plat/common/acpi.h>
#endif /* CONFIG_UKPLAT_ACPI */
#include <uk/plat/common/bootinfo.h>
#include <uk/plat/spinlock.h>
#include <arm/cpu.h>
#include <uk/intctlr.h>
#include <uk/intctlr/gic.h>
#include <uk/intctlr/gic-v3.h>
#include <uk/intctlr/limits.h>
#include <uk/ofw/fdt.h>

#define GIC_MAX_IRQ	UK_INTCTLR_MAX_IRQ

#define GIC_RDIST_REG(gdev, r)					\
	((void *)(gdev.rdist_mem_addr + (r) +			\
	lcpu_get_current()->id * GICR_STRIDE))

#define GIC_AFF_TO_ROUTER(aff, mode)				\
	((((uint64_t)(aff) << 8) & MPIDR_AFF3_MASK) | ((aff) & 0xffffff) | \
	 ((uint64_t)(mode) << 31))

#ifdef CONFIG_HAVE_SMP
__spinlock gicv3_dist_lock;
#endif /* CONFIG_HAVE_SMP */

/** GICv3 driver */
struct _gic_dev gicv3_drv = {
	.version        = GIC_V3,
	.is_present     = 0,
	.is_probed      = 0,
	.is_initialized = 0,
	.dist_mem_addr  = 0,
	.dist_mem_size  = 0,
	.rdist_mem_addr = 0,
	.rdist_mem_size = 0,
#ifdef CONFIG_HAVE_SMP
	.dist_lock      = &gicv3_dist_lock,
#endif /* CONFIG_HAVE_SMP */
};

static const char * const gic_device_list[] __maybe_unused = {
	"arm,gic-v3",
	NULL
};

/* Inline functions to access GICD & GICR registers */
static inline void write_gicd8(uint64_t offset, uint8_t val)
{
	ioreg_write8(GIC_DIST_REG(gicv3_drv, offset), val);
}

static inline void write_gicrd8(uint64_t offset, uint8_t val)
{
	ioreg_write8(GIC_RDIST_REG(gicv3_drv, offset), val);
}

static inline void write_gicd32(uint64_t offset, uint32_t val)
{
	ioreg_write32(GIC_DIST_REG(gicv3_drv, offset), val);
}

static inline void write_gicd64(uint64_t offset, uint64_t val)
{
	ioreg_write64(GIC_DIST_REG(gicv3_drv, offset), val);
}

static inline uint64_t read_gicd64(uint64_t offset)
{
	return ioreg_read64(GIC_DIST_REG(gicv3_drv, offset));
}

static inline uint32_t read_gicd32(uint64_t offset)
{
	return ioreg_read32(GIC_DIST_REG(gicv3_drv, offset));
}

static inline void write_gicrd32(uint64_t offset, uint32_t val)
{
	ioreg_write32(GIC_RDIST_REG(gicv3_drv, offset), val);
}

static inline uint32_t read_gicrd32(uint64_t offset)
{
	return ioreg_read32(GIC_RDIST_REG(gicv3_drv, offset));
}

static inline uint32_t read_gicd8(uint64_t offset)
{
	return ioreg_read8(GIC_DIST_REG(gicv3_drv, offset));
}

static inline uint32_t read_gicrd8(uint64_t offset)
{
	return ioreg_read8(GIC_RDIST_REG(gicv3_drv, offset));
}

/**
 * Wait for a write completion in [re]distributor
 *
 * @param offset Memory address of distributor or redistributor
 */
static void wait_for_rwp(uint64_t offset)
{
	uint32_t val;

	do {
		val = ioreg_read32((void *)(offset + GICD_CTLR));
	} while ((val & GICD_CTLR_RWP));
}

/**
 * Affinitize all SPI interrupts to the current cpu
 *
 * @param irq_number SPI interrupt number
 */
static void affinitize_all_spi_to_current_cpu(uint32_t irq_number)
{
	uint32_t i;
	uint64_t mpidr = SYSREG_READ64(MPIDR_EL1);
	uint64_t aff = ((mpidr & MPIDR_AFF3_MASK) >> 8) |
				(mpidr & MPIDR_AFF2_MASK) |
				(mpidr & MPIDR_AFF1_MASK) |
				(mpidr & MPIDR_AFF0_MASK);
	/* Route all global SPIs to this CPU */
	uint64_t irouter_val = GIC_AFF_TO_ROUTER(aff, 0);

	for (i = GIC_SPI_BASE; i < irq_number; i++)
		write_gicd64(GICD_IROUTER(i), irouter_val);
}

/**
 * Acknowledge IRQ and retrieve highest priority pending interrupt
 *
 * @return the ID of the signaled interrupt
 */
static uint32_t gicv3_ack_irq(void)
{
	uint32_t irq;

	irq = SYSREG_READ32(ICC_IAR1_EL1);

	return irq;
}

#if defined(CONFIG_LIBUKINTCTLR_TEST) || defined(CONFIG_LIBUKTEST_ALL)
/**
 * Set pending bit to simulate specified SPI being triggered
 */
static void gicv3_simulate_spi(uint32_t irq)
{
	UK_ASSERT(irq >= GIC_SPI_BASE && irq <= GIC_MAX_IRQ);
	uint32_t pending_offset;
	unsigned long flags __maybe_unused;

	pending_offset = GICD_ISPENDR(irq);
	dist_lock(gicv3_drv, flags);
	write_gicd32(pending_offset, 1UL << (irq % 32));
	dist_unlock(gicv3_drv, flags);
}

/**
 *  Get the interrupt priority level in non-secure mode
 * @param irq irq to get priority information
 * @return priority level of irq
 */
static uint8_t gicv3_get_irq_prio(uint32_t irq)
{
	uint8_t prio_level;
	unsigned long flags __maybe_unused;

	dist_lock(gicv3_drv, flags);
	if (irq < GIC_SPI_BASE) /* Change in redistributor */
		prio_level =
			read_gicrd8(GICR_IPRIORITYR(irq));
	else
		prio_level =
			read_gicd8(GICD_IPRIORITYR(irq));
	dist_unlock(gicv3_drv, flags);
	return prio_level;
}

/**
 *  Get the spi affinity stats
 * @param irq irq to get affinity information
 * @return affinity information of irq
 */
static uint32_t gicv3_get_spi_affinity(uint32_t irq)
{
	UK_ASSERT(irq >= GIC_SPI_BASE && irq <= GIC_MAX_IRQ);
	unsigned long flags __maybe_unused;

	dist_lock(gicv3_drv, flags);
	uint64_t router_value = read_gicd64(GICD_IROUTER(irq));

	uint32_t aff = (uint32_t)((router_value >> 8) & 0xFFFFFF);

	dist_unlock(gicv3_drv, flags);
	return aff;
}
#endif  /* CONFIG_LIBUKINTCTLR_TEST || CONFIG_LIBUKTEST_ALL */

/**
 * Signal completion of interrupt processing
 *
 * @param irq the ID of the interrupt to complete. Must be from a corresponding
 *    call to gicv3_ack_irq()
 */
static void gicv3_eoi_irq(uint32_t irq)
{
	/* Lower the priority */
	SYSREG_WRITE32(ICC_EOIR1_EL1, irq);
	isb();
#ifdef CONFIG_VIRTUALIZE_PLAT
	/* Deactivate */
	SYSREG_WRITE32(ICC_DIR_EL1, irq);
	isb();
#endif
}

/**
 * Enable an interrupt
 *
 * @param irq interrupt number [0..GIC_MAX_IRQ]
 */
static void gicv3_enable_irq(uint32_t irq)
{
	UK_ASSERT(irq <= GIC_MAX_IRQ);
	unsigned long flags __maybe_unused;

	dist_lock(gicv3_drv, flags);

	if (irq >= GIC_SPI_BASE)
		write_gicd32(GICD_ISENABLER(irq),
				UK_BIT(irq % GICD_I_PER_ISENABLERn));
	else
		write_gicrd32(GICR_ISENABLER0,
				UK_BIT(irq % GICR_I_PER_ISENABLERn));

	dist_unlock(gicv3_drv, flags);
}

/**
 * Generate a Software Generated Interrupt (SGI)
 *
 * @param sgintid the software generated interrupt id
 * @param send_to_all
 * true sending sgi to all PEs in the system except "self".
 * false sending sgi to the specified core.
 * @param cpuid
 * This parametr work only when `send_to_all` is false.
 * @return zero on success, negative value on failure
 */
static int gicv3_sgi_gen(uint8_t sgintid, bool send_to_all,
						 uint32_t cpuid __maybe_unused)
{
	uint64_t			sgi_register = 0;
	uint64_t control_register_rss, type_register_rss;
	uint64_t range_selector = 0, extended_cpuid;
	uint32_t aff0;
	unsigned long flags __maybe_unused;

	/* Only INTID 0-15 allocated to sgi */
	UK_ASSERT(sgintid <= GICD_SGI_MAX_INITID);

	sgi_register |= (sgintid << 24);

	if (send_to_all) {
		sgi_register |= ICC_SGI1R_EL1_IRM_ALL;
		dist_lock(gicv3_drv, flags);
		SYSREG_WRITE64(ICC_SGI1R_EL1, sgi_register);
		dist_unlock(gicv3_drv, flags);
		return 0;
	}

	sgi_register |= ICC_SGI1R_EL1_IRM;

	control_register_rss =
		SYSREG_READ64(ICC_CTLR_EL1) & (1 << 18);
	type_register_rss =
		read_gicd32(GICD_TYPER)  & (1 << 26);

	extended_cpuid = (uint64_t)(cpuid);

	/* Set affinity fields and optional range selector */
	sgi_register |= (extended_cpuid & MPIDR_AFF3_MASK) << 16;
	sgi_register |= (extended_cpuid & MPIDR_AFF2_MASK) << 16;
	sgi_register |= (extended_cpuid & MPIDR_AFF1_MASK) << 8;

	aff0		   = extended_cpuid & MPIDR_AFF0_MASK;
	range_selector = aff0 / 16;

	if (range_selector >= 1 &&
		(control_register_rss != 1 || type_register_rss != 1)) {
		uk_pr_err(
			"send sgi to target core(s) failed: \r\n"
			"mismatch cpuid(0x%lx) and rs(GICD_TYPER.RS: %lu, ICC_CTLR.RS: %lu)\n",
			extended_cpuid, type_register_rss, control_register_rss);
		return -1;
	}

	sgi_register |= ((1 << (aff0 % 16)) | (range_selector << 44));

	dist_lock(gicv3_drv, flags);
	SYSREG_WRITE64(ICC_SGI1R_EL1, sgi_register);
	dist_unlock(gicv3_drv, flags);

	return 0;
}

/**
 * Disable an interrupt
 *
 * @param irq interrupt number [0..GIC_MAX_IRQ]
 */
static void gicv3_disable_irq(uint32_t irq)
{
	UK_ASSERT(irq <= GIC_MAX_IRQ);
	unsigned long flags __maybe_unused;

	dist_lock(gicv3_drv, flags);

	if (irq >= GIC_SPI_BASE)
		write_gicd32(GICD_ICENABLER(irq),
				UK_BIT(irq % GICD_I_PER_ICENABLERn));
	else
		write_gicrd32(GICR_ICENABLER0,
				UK_BIT(irq % GICR_I_PER_ICENABLERn));

	dist_unlock(gicv3_drv, flags);
}

/**
 * Set interrupt affinity
 *
 * @param irq interrupt number [GIC_SPI_BASE..GIC_MAX_IRQ]
 * @param affinity target CPU affinity in 32 bits format
 * (AFF3|AFF2|AFF1|AFF0), as returned by GET_CPU_AFFINITY()
 */
static void gicv3_set_irq_affinity(uint32_t irq, uint32_t affinity)
{
	UK_ASSERT(irq >= GIC_SPI_BASE && irq <= GIC_MAX_IRQ);
	unsigned long flags __maybe_unused;

	dist_lock(gicv3_drv, flags);
	write_gicd64(GICD_IROUTER(irq), GIC_AFF_TO_ROUTER(affinity, 0));
	dist_unlock(gicv3_drv, flags);
}

/**
 * Set priority for an interrupt
 *
 * @param irq interrupt number [0..GIC_MAX_IRQ]
 * @param priority Available interrupt priority range in non-secure mode,
 * Lower values correspond to higher priorities
 * Refer to the gic documentation for more details.
 */
static void gicv3_set_irq_prio(uint32_t irq, uint8_t priority)
{
	UK_ASSERT(priority < (1 << (8 - TRANS_PRIORITY_SHIFT)));
	unsigned long flags __maybe_unused;

	dist_lock(gicv3_drv, flags);
	if (irq < GIC_SPI_BASE) /* Change in redistributor */
		write_gicrd8(GICR_IPRIORITYR(irq),
			priority << TRANS_PRIORITY_SHIFT);
	else
		write_gicd8(GICD_IPRIORITYR(irq),
			priority << TRANS_PRIORITY_SHIFT);

	dist_unlock(gicv3_drv, flags);
}

/**
 * Configure trigger type for an interrupt
 *
 * @param irq interrupt number [GIC_PPI_BASE..GIC_MAX_IRQ]
 * @param trigger trigger type (UK_INTCTLR_IRQ_TRIGGER_*)
 */
static
void gicv3_set_irq_trigger(uint32_t irq, enum uk_intctlr_irq_trigger trigger)
{
	uint32_t val, mask, oldmask;
	unsigned long flags __maybe_unused;

	UK_ASSERT(irq >= GIC_PPI_BASE && irq <= GIC_MAX_IRQ);
	UK_ASSERT(trigger == UK_INTCTLR_IRQ_TRIGGER_EDGE ||
		  trigger == UK_INTCTLR_IRQ_TRIGGER_LEVEL);

	dist_lock(gicv3_drv, flags);

	val = read_gicd32(GICD_ICFGR(irq));
	mask = oldmask = (val >> ((irq % GICD_I_PER_ICFGRn) * 2)) &
			GICD_ICFGR_MASK;

	if (trigger == UK_INTCTLR_IRQ_TRIGGER_LEVEL) {
		mask &= ~GICD_ICFGR_TRIG_MASK;
		mask |= GICD_ICFGR_TRIG_LVL;
	} else if (trigger == UK_INTCTLR_IRQ_TRIGGER_EDGE) {
		mask &= ~GICD_ICFGR_TRIG_MASK;
		mask |= GICD_ICFGR_TRIG_EDGE;
	}

	/* Check if nothing changed */
	if (mask == oldmask)
		goto EXIT_UNLOCK;

	/* Update new interrupt type */
	val &= (~(GICD_ICFGR_MASK << (irq % GICD_I_PER_ICFGRn) * 2));
	val |= (mask << (irq % GICD_I_PER_ICFGRn) * 2);
	write_gicd32(GICD_ICFGR(irq), val);

EXIT_UNLOCK:
	dist_unlock(gicv3_drv, flags);
}

/** Enable distributor */
static void gicv3_enable_dist(void)
{
	unsigned long flags __maybe_unused;

	dist_lock(gicv3_drv, flags);
	write_gicd32(GICD_CTLR, GICD_CTLR_ARE_NS |
			GICD_CTLR_ENABLE_G0 | GICD_CTLR_ENABLE_G1NS);
	wait_for_rwp(gicv3_drv.dist_mem_addr);
	dist_unlock(gicv3_drv, flags);
}

/** Disable distributor */
static void gicv3_disable_dist(void)
{
	unsigned long flags __maybe_unused;

	/* Write 0 to disable distributor */
	dist_lock(gicv3_drv, flags);
	write_gicd32(GICD_CTLR, 0);
	wait_for_rwp(gicv3_drv.dist_mem_addr);
	dist_unlock(gicv3_drv, flags);
}

/** Enable the redistributor */
static void gicv3_init_redist(void)
{
	uint32_t i, val;

	/* Wake up CPU redistributor */
	val  = read_gicrd32(GICR_WAKER);
	val &= ~GICR_WAKER_ProcessorSleep;
	write_gicrd32(GICR_WAKER, val);

	/* Poll GICR_WAKER.ChildrenAsleep */
	do {
		val = read_gicrd32(GICR_WAKER);
	} while ((val & GICR_WAKER_ChildrenAsleep));

	/* Set PPI and SGI to a default value */
	for (i = 0; i < GIC_SPI_BASE; i += GICD_I_PER_IPRIORITYn)
		write_gicrd32(GICR_IPRIORITYR4(i), GICD_IPRIORITY_DEF);

	/* Deactivate SGIs and PPIs as the state is unknown at boot */
	write_gicrd32(GICR_ICACTIVER0, GICD_DEF_ICACTIVERn);

	/* Disable all PPIs */
	write_gicrd32(GICR_ICENABLER0, GICD_DEF_PPI_ICENABLERn);

	/* Configure SGIs and PPIs as non-secure Group 1 */
	write_gicrd32(GICR_IGROUPR0, GICD_DEF_IGROUPRn);

	/* Enable all SGIs */
	write_gicrd32(GICR_ISENABLER0, GICD_DEF_SGI_ISENABLERn);

	/* Wait for completion */
	wait_for_rwp(gicv3_drv.rdist_mem_addr);

	/* Enable system register access */
	val  = SYSREG_READ32(ICC_SRE_EL1);
	val |= 0x7;
	SYSREG_WRITE32(ICC_SRE_EL1, val);
	isb();

	/* No priority grouping */
	SYSREG_WRITE32(ICC_BPR1_EL1, 0);

	/* Set priority mask register */
	SYSREG_WRITE32(ICC_PMR_EL1, 0xff);

	SYSREG_WRITE32(ICC_CTLR_EL1, ICC_CTLR_EL1_EOImode);

	/* Enable Group 1 interrupts */
	SYSREG_WRITE32(ICC_IGRPEN1_EL1, 1);

	isb();

	uk_pr_info("GICv3 redistributor initialized.\n");
}

/** Initialize the distributor */
static void gicv3_init_dist(void)
{
	uint32_t val, irq_number;
	uint32_t i;

	/* Disable the distributor */
	gicv3_disable_dist();

	/* Get GIC redistributor interface */
	val = read_gicd32(GICD_TYPER);
	irq_number = GICD_TYPER_LINE_NUM(val);
	if (irq_number > GIC_MAX_IRQ)
		irq_number = GIC_MAX_IRQ + 1;
	uk_pr_info("GICv3 Max interrupt lines: %d\n", irq_number);

	/* Check for LPI support */
	if (val & GICD_TYPE_LPIS)
		uk_pr_warn("LPI support is not implemented by this driver!\n");

	/* Configure all SPIs as non-secure Group 1 */
	for (i = GIC_SPI_BASE; i < irq_number; i += GICD_I_PER_IGROUPRn)
		write_gicd32(GICD_IGROUPR(i), GICD_DEF_IGROUPRn);

	/* Check for 1 of N SPI interrupts support */
	if (val & GICD_TYPE_NO1N_MASK) {
		affinitize_all_spi_to_current_cpu(irq_number);
	} else {
#ifdef CONFIG_HAVE_SMP
		for (i = GIC_SPI_BASE; i < irq_number; i++)
			write_gicd64(GICD_IROUTER(i),
					GIC_AFF_TO_ROUTER(0ULL, 1));
#else
		affinitize_all_spi_to_current_cpu(irq_number);
#endif /* CONFIG_HAVE_SMP */
	}

	/* Set all SPI's interrupt type to be level-sensitive */
	for (i = GIC_SPI_BASE; i < irq_number; i += GICD_I_PER_ICFGRn)
		write_gicd32(GICD_ICFGR(i), GICD_ICFGR_DEF_TYPE);

	/* Set all SPI's priority to a default value */
	for (i = GIC_SPI_BASE; i < irq_number; i += GICD_I_PER_IPRIORITYn)
		write_gicd32(GICD_IPRIORITYR4(i), GICD_IPRIORITY_DEF);

	/* Deactivate and disable all SPIs */
	for (i = GIC_SPI_BASE; i < irq_number; i += GICD_I_PER_ICACTIVERn) {
		write_gicd32(GICD_ICACTIVER(i), GICD_DEF_ICACTIVERn);
		write_gicd32(GICD_ICENABLER(i), GICD_DEF_ICENABLERn);
	}

	/* Wait for completion */
	wait_for_rwp(gicv3_drv.dist_mem_addr);

	/* Enable the distributor */
	gicv3_enable_dist();

	uk_pr_info("GICv3 distributor initialized.\n");
}

static void gicv3_handle_irq(struct __regs *regs)
{
	uint32_t stat, irq;

	stat = gicv3_ack_irq();
	irq = stat & GICC_IAR_INTID_MASK;

	/* No valid interruption */
	if (irq == GICC_IAR_INTID_SPURIOUS) {
		return;
	}
	/* Unlawful interruption */
	if unlikely (irq > GIC_MAX_IRQ) {
		return;
	}

	uk_intctlr_irq_handle(regs, irq);
	gicv3_eoi_irq(stat);
	return;
}

tn_intctlr_trap_register(gicv3_handle_irq);

/**
 * Initialize GICv3
 * NOTE: First time must not be called from multiple CPUs in parallel
 *
 * @return 0 on success, a non-zero error otherwise
 */
static int gicv3_initialize(void)
{
#ifdef CONFIG_HAVE_SMP
	if (gicv3_drv.is_initialized) {
		/* Distributor is already initialized, we just need to
		 * initialize the CPU redistributor interface
		 */
		gicv3_init_redist();
		return 0;
	}
#endif /* CONFIG_HAVE_SMP */

	/* Initialize GICv3 distributor */
	gicv3_init_dist();

	/* Initialize GICv3 CPU redistributor */
	gicv3_init_redist();

	gicv3_drv.is_initialized = 1;

	return 0;
}

static inline void gicv3_set_ops(void)
{
	struct _gic_operations drv_ops = {
		.initialize        = gicv3_initialize,
		.ack_irq           = gicv3_ack_irq,
		.eoi_irq           = gicv3_eoi_irq,
		.enable_irq        = gicv3_enable_irq,
		.disable_irq       = gicv3_disable_irq,
		.set_irq_trigger   = gicv3_set_irq_trigger,
		.set_irq_prio      = gicv3_set_irq_prio,
		.set_irq_affinity  = gicv3_set_irq_affinity,
		.handle_irq        = gicv3_handle_irq,
		.gic_sgi_gen	   = gicv3_sgi_gen,
#if defined(CONFIG_LIBUKINTCTLR_TEST) || defined(CONFIG_LIBUKTEST_ALL)
		.get_irq_prio      = gicv3_get_irq_prio,
		.simulate_spi      = gicv3_simulate_spi,
		.get_spi_affinity  = gicv3_get_spi_affinity,
#endif
	};

	/* Set driver functions */
	gicv3_drv.ops = drv_ops;
}

#if defined(CONFIG_UKPLAT_ACPI)
static int acpi_get_gicr(struct _gic_dev *g)
{
	union {
		struct acpi_madt_gicr *gicr;
		struct acpi_subsdt_hdr *h;
	} m;
	struct acpi_madt *madt;
	__sz off, len;

	madt = acpi_get_madt();
	UK_ASSERT(madt);

	/* We do not count the Redistributor regions, instead we rely on
	 * having the GICv3 in an always-on power domain so that we are
	 * aligned with the current state of the driver, which only supports
	 * contiguous GIC Redistributors...
	 */
	len = madt->hdr.tab_len - sizeof(*madt);
	for (off = 0; off < len; off += m.h->len) {
		m.h = (struct acpi_subsdt_hdr *)(madt->entries + off);

		if (m.h->type != ACPI_MADT_GICR)
			continue;

		g->rdist_mem_addr = m.gicr->paddr;
		g->rdist_mem_size = m.gicr->len;

		/* We assume we only have one redistributor region */
		return 0;
	}

	return -ENOENT;
}

static int gicv3_do_probe(void)
{
	int rc;

	rc = acpi_get_gicd(&gicv3_drv);
	if (unlikely(rc < 0))
		return rc;

	/* Normally we should check first if there exists a Redistributor.
	 * If there is none then we must get its address from the GICC
	 * structure, since that means that the Redistributors are not in an
	 * always-on power domain. Otherwise there could be a GICR for each
	 * Redistributor region and the DT probe version does not accommodate
	 * anyway for multiple regions. So, until there is need for that (not
	 * the case for QEMU Virt), align ACPI probe with DT probe and assume
	 * we only have one Redistributor region.
	 */
	return acpi_get_gicr(&gicv3_drv);
}
#else /* CONFIG_UKPLAT_ACPI */
static int gicv3_do_probe(void)
{
	struct ukplat_bootinfo *bi = ukplat_bootinfo_get();
	int fdt_gic, r;
	void *fdt;

	UK_ASSERT(bi);
	fdt = (void *)bi->dtb;

	/* Currently, we only support 1 GIC per system */
	fdt_gic = fdt_node_offset_by_compatible_list(fdt, -1, gic_device_list);
	if (fdt_gic < 0)
		return -FDT_ERR_NOTFOUND; /* GICv3 not present */

	/* Get address and size of the GIC's register regions */
	r = fdt_get_address(fdt, fdt_gic, 0, &gicv3_drv.dist_mem_addr,
				&gicv3_drv.dist_mem_size);
	if (unlikely(r < 0)) {
		uk_pr_err("Could not find GICv3 distributor region!\n");
		return r;
	}

	/* TODO: Redistributors may be spread out in different regions.
	 * Make sure we get the count of such regions and enumerate properly
	 * using the `#redistributor-regions"` DT property. Furthermore,
	 * we should also check for the `redistributor-stride` property,
	 * since there are `Devicetree`'s that have `GICv4` nodes that use the
	 * `GICv3` compatible (there is also mixed `GICv3/4`, see Chapter 9.7
	 * from `GICv3 and GICv4 Software Overview`). The main difference
	 * between `GICv3/4` is the support for `vLPI`'s which basically
	 * doubles the address space range (with some exceptions):
	 * RD + SGI + vLPI + reserved.
	 */
	r = fdt_get_address(fdt, fdt_gic, 1, &gicv3_drv.rdist_mem_addr,
				&gicv3_drv.rdist_mem_size);
	if (unlikely(r < 0)) {
		uk_pr_err("Could not find GICv3 redistributor region!\n");
		return r;
	}

	return 0;
}
#endif /* !CONFIG_UKPLAT_ACPI */

/**
 * Probe device tree for GICv3
 * NOTE: First time must not be called from multiple CPUs in parallel
 *
 * @param [out] dev receives pointer to GICv3 if available, NULL otherwise
 *
 * @return 0 if device is available, an FDT (FDT_ERR_*) error otherwise
 */
int gicv3_probe(struct _gic_dev **dev)
{
	int rc;

#ifdef CONFIG_HAVE_SMP
	if (gicv3_drv.is_probed) {
		/* GIC is already probed, we don't need to probe again */
		if (gicv3_drv.is_present) {
			*dev = &gicv3_drv;
			return 0;
		}

		*dev = NULL;
		return -FDT_ERR_NOTFOUND;
	}
#endif /* CONFIG_HAVE_SMP */

	gicv3_drv.is_probed = 1;

	rc = gicv3_do_probe();
	if (rc) {
		*dev = NULL;
		return rc;
	}

	uk_pr_info("Found GICv3 on:\n");
	uk_pr_info("\tDistributor  : 0x%lx - 0x%lx\n",	gicv3_drv.dist_mem_addr,
		   gicv3_drv.dist_mem_addr + gicv3_drv.dist_mem_size - 1);
	uk_pr_info("\tRedistributor: 0x%lx - 0x%lx\n", gicv3_drv.rdist_mem_addr,
		   gicv3_drv.rdist_mem_addr + gicv3_drv.rdist_mem_size - 1);

	/* GICv3 is present */
	gicv3_drv.is_present = 1;
	gicv3_set_ops();

	*dev = &gicv3_drv;
	return 0;

}
