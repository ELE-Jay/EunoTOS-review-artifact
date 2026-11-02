#include "rst_def.h"
#include "rst_ipc.h"
#include <uk/plat/lcpu.h>

static unsigned long flags;

void rst_irq_mask(void)
{
	flags = ukplat_lcpu_save_irqf();
}

void rst_irq_unmask(void)
{
	ukplat_lcpu_restore_irqf(flags);
}
