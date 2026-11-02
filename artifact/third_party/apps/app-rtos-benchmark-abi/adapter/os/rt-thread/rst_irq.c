#include "rst_def.h"
#include "rst_ipc.h"
#include "rtthread.h"

static rt_base_t level;

void rst_irq_mask(void)
{
	level = rt_hw_interrupt_disable();
}

void rst_irq_unmask(void)
{
	rt_hw_interrupt_enable(level);
}
