/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */
#include <errno.h>
#include <uk/assert.h>
#include <uk/config.h>
#include <uk/intctlr.h>

#if CONFIG_LIBUKINTCTLR_APIC
#include <uk/intctlr/apic.h>
#endif /* CONFIG_LIBUKINTCTLR_APIC */

#include "pic.h"

static struct uk_intctlr_desc intctlr;

static int irq_set_trigger(struct uk_intctlr_irq *irq __unused)
{
	return 0;
}

void uk_intctlr_xpic_handle_irq(struct __regs *regs, unsigned int irq)
{
	uk_intctlr_irq_handle(regs, irq);

#if CONFIG_LIBUKINTCTLR_APIC
	apic_ack_interrupt();

	/* FIXME This is here because right now we only use
	 * APIC for IPIs on SMP. This should be removed as
	 * soon as we fully implement APIC and get rid of
	 * PIC
	 */
	if (irq <= 16)
		pic_ack_irq(irq);
#else   /* !CONFIG_LIBUKINTCTLR_APIC */
	pic_ack_irq(irq);
#endif /* !CONFIG_LIBUKINTCTLR_APIC */
}

tn_intctlr_trap_register(uk_intctlr_xpic_handle_irq);

int uk_intctlr_probe(void)
{
	int rc = -ENODEV;
	struct uk_intctlr_driver_ops *ops;

	rc = pic_init(&ops);
	if (unlikely(rc))
		return rc;

#if CONFIG_LIBUKINTCTLR_APIC
	apic_enable();
	intctlr.name = "APIC";
#else /* ! CONFIG_LIBUKINTCTLR_APIC */
	intctlr.name = "PIC";
#endif /* CONFIG_LIBUKINTCTLR_APIC */

	intctlr.ops = ops;
	intctlr.ops->irq_set_trigger = irq_set_trigger;
	intctlr.ops->initialize = __NULL;
	intctlr.ops->handle = uk_intctlr_xpic_handle_irq;
	intctlr.ops->fdt_xlat = __NULL;
	intctlr.ops->sgi_op = __NULL;
	intctlr.ops->percpu_init = __NULL;
	intctlr.ops->irq_set_priority = __NULL;
	intctlr.ops->irq_set_affinity = __NULL;
#if defined(CONFIG_LIBUKINTCTLR_TEST) || defined(CONFIG_LIBUKTEST_ALL)
	intctlr.ops->irq_get_priority = __NULL;
	intctlr.ops->spi_get_affinity = __NULL;
	intctlr.ops->simulate_spi = __NULL;
#endif
	return uk_intctlr_register(&intctlr);
}
