#include "rst_def.h"
#include "rst_ipc.h"
#include "rst_cfg.h"
#include <stdio.h>
#include <zephyr/kernel.h>

static unsigned long flags;

void rst_irq_mask(void)
{
	flags = irq_lock();
}

void rst_irq_unmask(void)
{
	irq_unlock(flags);
}
