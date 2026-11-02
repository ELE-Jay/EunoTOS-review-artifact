#include "rst_def.h"
#include "rst_ipc.h"
#include <uk/intctlr.h>
#include <uk/intctlr/gic-v3.h>
#include <uk/plat/lcpu.h>
#include <uk/print.h>

#define TEST_GIC_DIST_REG(r) ((void *)(uintptr_t)(0xfd400000 + (r)))

struct rst_irq_context {
	rst_isr_func handler;
	void *param;
};

static struct rst_irq_context rst_sgi_contexts[16];

/* Tenon's controller requires an int return: 1 means this IRQ was handled. */
static int rst_irq_dispatch(void *arg)
{
	struct rst_irq_context *context = arg;
	context->handler(context->param);
	return 1;
}

rst_status rst_isr_install(int vector __unused, rst_isr_func handler,
			   void *param)
{
	if (vector < 0 || vector >= 16 || handler == NULL)
		return RST_INVAL;
	struct rst_irq_context *context = &rst_sgi_contexts[vector];
	context->handler = handler;
	context->param = param;
	uk_intctlr_irq_set_priority(vector, 1);
	return uk_intctlr_irq_register(vector, rst_irq_dispatch, context) == 0
		? RST_OK : RST_ERROR;
}

void rst_isr_trigger(int vector __unused) {
	uint64_t current_cpu = SYSREG_READ64(MPIDR_EL1);
	uint64_t aff = ((current_cpu & MPIDR_AFF3_MASK) >> 8)
		       | (current_cpu & MPIDR_AFF2_MASK)
		       | (current_cpu & MPIDR_AFF1_MASK)
		       | (current_cpu & MPIDR_AFF0_MASK);

	uk_intctlr_sgi_op(vector, false, (uint32_t)aff);
}
