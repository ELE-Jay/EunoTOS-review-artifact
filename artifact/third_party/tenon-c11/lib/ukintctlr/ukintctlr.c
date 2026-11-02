/* SPDX-License-Identifier: ISC */
/*
 * Authors: Dan Williams
 *          Martin Lucina
 *          Ricardo Koller
 *          Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2015-2017 IBM
 * Copyright (c) 2016-2017 Docker, Inc.
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Taken from solo5 intr.c */

#include <stdlib.h>
#include <uk/alloc.h>
#include <uk/bitmap.h>
#include <uk/plat/lcpu.h>
#include <uk/plat/time.h>
#include <uk/intctlr.h>
#include <uk/intctlr/limits.h>
#include <uk/assert.h>
#include <uk/event.h>
#include <uk/trace.h>
#include <uk/print.h>
#include <errno.h>
#include <uk/bitops.h>
#include <uk/trace_macros.h>
#if CONFIG_LIBUKINTCTLR_ISR_ECTX_ASSERTIONS
#include <uk/arch/ctx.h>
#endif /* CONFIG_LIBUKINTCTLR_ISR_ECTX_ASSERTIONS */

#if !defined(UK_INTCTLR_MAX_IRQ) ||					\
	!defined(UK_INTCTLR_ALLOCABLE_IRQ_COUNT) ||			\
	!defined(UK_INTCTLR_FIRST_ALLOCABLE_IRQ) ||			\
	!defined(UK_INTCTLR_LAST_ALLOCABLE_IRQ)
#error "Incomplete definition of uk_intctlr driver limits"
#endif

#define MAX_IRQ				UK_INTCTLR_MAX_IRQ
#define MAX_HANDLERS_PER_IRQ		CONFIG_LIBUKINTCTLR_MAX_HANDLERS_PER_IRQ

#define ALLOCABLE_IRQ_COUNT		UK_INTCTLR_ALLOCABLE_IRQ_COUNT
#define FIRST_ALLOCABLE_IRQ		UK_INTCTLR_FIRST_ALLOCABLE_IRQ
#define LAST_ALLOCABLE_IRQ		UK_INTCTLR_LAST_ALLOCABLE_IRQ

struct uk_intctlr_desc *uk_intctlr;

UK_EVENT(UK_INTCTLR_EVENT_IRQ);

UK_TRACEPOINT(trace_uk_intctlr_unhandled_irq, "Unhandled irq=%lu\n",
	      unsigned long);

static unsigned long irqs_allocated[UK_BITS_TO_LONGS(ALLOCABLE_IRQ_COUNT)];

/* IRQ handlers declarations */
struct irq_handler {
	uk_intctlr_irq_handler_func_t func;
	void *arg;
};

static struct irq_handler irq_handlers[MAX_IRQ][MAX_HANDLERS_PER_IRQ];

static inline struct irq_handler *allocate_handler(unsigned long irq)
{
	UK_ASSERT(irq <= MAX_IRQ);

	for (int i = 0; i < MAX_HANDLERS_PER_IRQ; i++)
		if (irq_handlers[irq][i].func == NULL)
			return &irq_handlers[irq][i];
	return NULL;
}

int uk_intctlr_irq_register(unsigned int irq,
			    uk_intctlr_irq_handler_func_t func, void *arg)
{
	struct irq_handler *h;
	unsigned long flags;

	UK_ASSERT(func);
	UK_ASSERT(irq <= MAX_IRQ);

	flags = ukplat_lcpu_save_irqf();
	h = allocate_handler(irq);
	if (!h) {
		ukplat_lcpu_restore_irqf(flags);
		return -ENOMEM;
	}

	h->func = func;
	h->arg = arg;

	ukplat_lcpu_restore_irqf(flags);

	uk_intctlr->ops->unmask_irq(irq);

	return 0;
}

int uk_intctlr_irq_unregister(unsigned int irq,
			      uk_intctlr_irq_handler_func_t func)
{
	struct irq_handler *h = NULL;
	unsigned long flags;
	int count;
	int i;

	UK_ASSERT(func);
	UK_ASSERT(irq <= MAX_IRQ);

	flags = ukplat_lcpu_save_irqf();

	count = MAX_HANDLERS_PER_IRQ;
	for (i = 0; i < count; i++) {
recheck:
		if (irq_handlers[irq][i].func == func) {
			h = &irq_handlers[irq][i];
			h->func = NULL;
			h->arg = NULL;

			/* Copy all following handlers forward */
			memmove(h, h + 1, sizeof(*h) * (count - i - 1));
			goto recheck;
		}
	}

	ukplat_lcpu_restore_irqf(flags);

	/* If `h` is set, then there was at least one instance found */
	if (unlikely(!h)) {
		uk_pr_crit("Invalid irq handler %p for irq %u ", func, irq);
		return -ENOENT;
	}

	return 0;
}

void uk_intctlr_irq_handle(struct __regs *regs __maybe_unused, unsigned int irq)
{
	TN_TRACE_FUNC_ENTER(isr, handle, irq);
	struct irq_handler *h;
	int i;
#if CONFIG_LIBUKINTCTLR_ISR_ECTX_ASSERTIONS
	__sz ectx_align = ukarch_ectx_align();
	__u8 ectxbuf[ukarch_ectx_size() + ectx_align];
	struct ukarch_ectx *ectx = (struct ukarch_ectx *)
		ALIGN_UP((__uptr) ectxbuf, ectx_align);

	ukarch_ectx_init(ectx);
#endif /* CONFIG_LIBUKINTCTLR_ISR_ECTX_ASSERTIONS */

	UK_ASSERT(irq <= MAX_IRQ);

	ukplat_lcpu_enable_irq();
	for (i = 0; i < MAX_HANDLERS_PER_IRQ; i++) {
		if (irq_handlers[irq][i].func == NULL)
			break;
		h = &irq_handlers[irq][i];
		if (h->func(h->arg) == 1)
			goto exit;
	}
	/*
	 * Acknowledge interrupts even in the case when there was no handler for
	 * it. We do this to (1) compensate potential spurious interrupts of
	 * devices, and (2) to minimize impact on drivers that share one
	 * interrupt line that would then stay disabled.
	 */
	trace_uk_intctlr_unhandled_irq(irq);

	TN_TRACE_FUNC_EXIT(isr, handle, irq);

exit:
	ukplat_lcpu_disable_irq();
#if CONFIG_LIBUKINTCTLR_ISR_ECTX_ASSERTIONS
	ukarch_ectx_assert_equal(ectx);
#endif /* CONFIG_LIBUKINTCTLR_ISR_ECTX_ASSERTIONS */

	return;
}

void uk_intctlr_irq_mask(unsigned int irq)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->mask_irq);

	return uk_intctlr->ops->mask_irq(irq);
}

void uk_intctlr_irq_unmask(unsigned int irq)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->unmask_irq);

	return uk_intctlr->ops->unmask_irq(irq);
}

int uk_intctlr_irq_set_trigger(struct uk_intctlr_irq *irq)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->irq_set_trigger);
	UK_ASSERT(irq);

	return uk_intctlr->ops->irq_set_trigger(irq);
}

int uk_intctlr_irq_fdt_xlat(const void *fdt, int nodeoffset, __u32 index,
			    struct uk_intctlr_irq *irq)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->fdt_xlat);
	UK_ASSERT(fdt);
	UK_ASSERT(irq);

	/* We're using an assertion here instead of returning -ENOTSUP
	 * because the implementation returns libfdt error codes.
	 */
	UK_ASSERT(uk_intctlr->ops->fdt_xlat);

	return uk_intctlr->ops->fdt_xlat(fdt, nodeoffset, index, irq);
}

int uk_intctlr_irq_alloc(unsigned int *irqs, __sz count)
{
	unsigned long start, idx;

	UK_ASSERT(irqs);

	start = uk_bitmap_find_next_zero_area(irqs_allocated,
					      ALLOCABLE_IRQ_COUNT, 0,
					      count, 0);
	if (start == ALLOCABLE_IRQ_COUNT)
		return -ENOSPC;

	uk_bitmap_set(irqs_allocated, start, count);
	for (idx = start; idx < (start + count); idx++) {
		*irqs = idx + FIRST_ALLOCABLE_IRQ;
		irqs++;
	}

	return 0;
}

int uk_intctlr_irq_free(unsigned int *irqs, __sz count)
{
	int rc = 0;

	UK_ASSERT(irqs);

	for (__sz i = 0; i < count; i++) {
		UK_ASSERT(irqs[i] >= FIRST_ALLOCABLE_IRQ &&
			  irqs[i] <= LAST_ALLOCABLE_IRQ);

		rc = uk_test_and_clear_bit(irqs[i] - FIRST_ALLOCABLE_IRQ,
					   irqs_allocated);
		UK_ASSERT(rc);
	}

	return !rc;
}

int uk_intctlr_init(struct uk_alloc *a __maybe_unused)
{
	UK_ASSERT(uk_intctlr);
	UK_ASSERT(ukplat_lcpu_irqs_disabled());

	return 0;
}

int uk_intctlr_register(struct uk_intctlr_desc *intctlr)
{
	UK_ASSERT(intctlr);

	uk_intctlr = intctlr;

	return 0;
}

void uk_intctlr_handle(struct __regs *regs)
{
	UK_ASSERT(uk_intctlr->ops->handle);

	return uk_intctlr->ops->handle(regs);
}

int uk_intctlr_sgi_op(uint8_t sgintid, bool send_to_all,
					  uint32_t cpuid __maybe_unused)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->sgi_op);

	return uk_intctlr->ops->sgi_op(sgintid, send_to_all, cpuid);
}

int uk_intctlr_percpu_init(void)
{
	UK_ASSERT(uk_intctlr->ops->percpu_init);

	/* initialize interrupt controller of specified cpu core */
	return uk_intctlr->ops->percpu_init();
}

void uk_intctlr_irq_set_priority(unsigned int irq, uint8_t priority)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->irq_set_priority);

	return uk_intctlr->ops->irq_set_priority(irq, priority);
}

void uk_intctlr_irq_set_affinity(unsigned int irq, uint32_t cpuid)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->irq_set_affinity);

	return uk_intctlr->ops->irq_set_affinity(irq, cpuid);
}

#if defined(CONFIG_LIBUKINTCTLR_TEST) || defined(CONFIG_LIBUKTEST_ALL)
uint8_t uk_intctlr_irq_get_priority(unsigned int irq)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->irq_get_priority);

	return uk_intctlr->ops->irq_get_priority(irq);
}

uint32_t uk_intctlr_spi_get_affinity(unsigned int irq)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->spi_get_affinity);

	return uk_intctlr->ops->spi_get_affinity(irq);
}

void uk_intctlr_simulate_spi(unsigned int irq)
{
	UK_ASSERT(uk_intctlr && uk_intctlr->ops->simulate_spi);

	return uk_intctlr->ops->simulate_spi(irq);
}
#endif
