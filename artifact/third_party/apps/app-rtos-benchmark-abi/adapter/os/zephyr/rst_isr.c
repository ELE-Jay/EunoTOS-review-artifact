#include "rst_def.h"
#include "rst_ipc.h"

#include <zephyr/kernel.h>
#include <zephyr/irq.h>
#include <zephyr/drivers/interrupt_controller/gic.h>

typedef void (*isr_handler)(void *);

rst_status rst_isr_install(int vector, rst_isr_func handler, void *param)
{
	IRQ_CONNECT(RST_ISR_NUM, 0, rst_isr_handler, NULL, 0);
	irq_enable(RST_ISR_NUM);
}

void rst_isr_trigger(int vector)
{
	uint8_t aff0;
	uint32_t mpidr = MPIDR_TO_CORE(GET_MPIDR());
	aff0 = MPIDR_AFFLVL(mpidr, 0);
	gic_raise_sgi(RST_ISR_NUM, (uint64_t)mpidr, 1 << aff0);
}
