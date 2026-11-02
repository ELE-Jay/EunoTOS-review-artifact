#include "rst_def.h"
#include "rst_ipc.h"
#include "rst_cfg.h"

#include <rtthread.h>
#include <board.h>
#include <rtdevice.h>
#include <stdio.h>
#include <rthw.h>

#define TEST_GIC_DIST_REG(r) ((void *)(uintptr_t)(0xfd400000 + (r)))

static inline void ioreg_write32(const volatile uint32_t *address,
				 uint32_t value)
{
	__asm__ __volatile__("str %w0, [%1]" : : "rZ"(value), "r"(address));
}

rst_status rst_isr_install(int vector, rst_isr_func handler, void *param)
{
	rt_hw_interrupt_install(RST_ISR_NUM, (rt_isr_handler_t)handler, 0,
				"IRQ_Handler");
	rt_hw_interrupt_umask(RST_ISR_NUM);
	return RST_OK;
}

void rst_isr_trigger(int vector)
{
	uint32_t offset = (0x0200 + 4 * ((vector) >> 5));
	ioreg_write32(TEST_GIC_DIST_REG(offset), (1UL << (vector % 32)));
}
