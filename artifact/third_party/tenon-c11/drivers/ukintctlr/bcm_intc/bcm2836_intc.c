/* Copyright 2023 Hangzhou Yingyi Technology Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <uk/intctlr/bcm2835_intc.h>
#include <uk/intctlr/bcm2836_intc.h>
#include <uk/ofw/fdt.h>
#include <uk/intctlr.h>
#include <uk/essentials.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/plat/lcpu.h>
#include <uk/intctlr/limits.h>
#include <uk/intctlr/bcm_intc.h>
#include <arm/time.h>
#include <libfdt.h>

int fdt_bcm2836_intc_offset;

static const char *const bcm2836_intc_device_list[] __maybe_unused = {
	"brcm,bcm2836-l1-intc",
	NULL
};

struct bcm_intc_dev bcm2836_intc_drv = {
	.mem_addr  = 0,
	.mem_size  = 0,
};

int fdt_xlat_bcm2836(const void *fdt, int nodeoffset, __u32 index,
		    struct uk_intctlr_irq *irq)
{
	int ret, size;
	fdt32_t *prop;
	__u32 type, flags;

	UK_ASSERT(irq);

	ret = fdt_get_interrupt(fdt, nodeoffset, index, &size, &prop);
	if (unlikely(ret < 0))
		return ret;

	/* bcm中断控制器interrupt-cells为2 */
	UK_ASSERT(size == 2);

	type = fdt32_to_cpu(prop[0]);
	flags = fdt32_to_cpu(prop[1]);

	switch (type) {
	case IRQ_TYPE_CNTPS:
	case IRQ_TYPE_CNTPNS:
	case IRQ_TYPE_CNTHP:
	case IRQ_TYPE_CNTV:
		irq->id = IRQ_ID_CNTV;
		break;
	case IRQ_TYPE_MAILBOX0:
		irq->id = IRQ_BASE + IRQ_TYPE_MAILBOX0;
		break;
	case IRQ_TYPE_MAILBOX1:
		irq->id = IRQ_BASE + IRQ_TYPE_MAILBOX1;
		break;
	case IRQ_TYPE_MAILBOX2:
		irq->id = IRQ_BASE + IRQ_TYPE_MAILBOX2;
		break;
	case IRQ_TYPE_MAILBOX3:
		irq->id = IRQ_BASE + IRQ_TYPE_MAILBOX3;
		break;
	case IRQ_TYPE_GPU_FAST:
		irq->id = IRQ_BASE + IRQ_TYPE_GPU_FAST;
		break;
	case IRQ_TYPE_PMU_FAST:
		irq->id = IRQ_BASE + IRQ_TYPE_PMU_FAST;
		break;
	default:
		irq->id = IRQ_ID_INVALID;
	}

	switch (flags & FDT_BCM_INTC_IRQ_FLAGS_TL_MASK) {
	case FDT_BCM_INTC_IRQ_FLAGS_TL_EDGE_HI:
	case FDT_BCM_INTC_IRQ_FLAGS_TL_EDGE_LO:
		irq->trigger = UK_INTCTLR_IRQ_TRIGGER_EDGE;
		break;
	case FDT_BCM_INTC_IRQ_FLAGS_TL_LEVEL_LO:
	case FDT_BCM_INTC_IRQ_FLAGS_TL_LEVEL_HI:
		irq->trigger = UK_INTCTLR_IRQ_TRIGGER_LEVEL;
		break;
	default:
		return -FDT_ERR_BADVALUE;
	}

	return 0;
}

static void bcm2836_enable_timer_irq(void)
{
	ioreg_write32((void *)
		(ARM_TIMER_BASE + ARM_C0_TIMER_IRQ_CTL),
		ARM_C0_TIMER_IRQ_CTL_CNTVIRQ_ENABLE);
}

static void bcm2836_enable_mailbox0(void)
{
	/* unused */
}

static void bcm2836_enable_gpu_irq(void)
{
	/* unused */
}

static void bcm2836_enable_pmu_irq(void)
{
	/* unused */
}

static void bcm2836_intc_enable_irq(uint32_t irq __maybe_unused)
{
	BCM2835_OPS_ENABLE_IRQ(irq);

	switch (irq) {
	case IRQ_TYPE_CNTPS:
	case IRQ_TYPE_CNTPNS:
	case IRQ_TYPE_CNTHP:
	case IRQ_TYPE_CNTV:
		bcm2836_enable_timer_irq();
		break;
	case IRQ_TYPE_MAILBOX0:
		bcm2836_enable_mailbox0();
		break;
	case IRQ_TYPE_MAILBOX1:
		/* unused */
		break;
	case IRQ_TYPE_MAILBOX2:
		/* unused */
		break;
	case IRQ_TYPE_MAILBOX3:
		/* unused */
		break;
	case IRQ_TYPE_GPU_FAST:
		bcm2836_enable_gpu_irq();
		break;
	case IRQ_TYPE_PMU_FAST:
		bcm2836_enable_pmu_irq();
		break;
	default:
		uk_pr_err("unsurpported bcm2836irq id:%d\n", irq);
	}
}

static void bcm2836_disable_timer_irq(void)
{
	ioreg_write32((void *)
		(ARM_TIMER_BASE + ARM_C0_TIMER_IRQ_CTL),
		ARM_C0_TIMER_IRQ_CTL_CNTVIRQ_DISABLE);
}

static void bcm2836_disable_mailbox0(void)
{
	/* unused */
}

static void bcm2836_disable_gpu_irq(void)
{
	/* unused */
}

static void bcm2836_disable_pmu_irq(void)
{
	/* unused */
}

static void bcm2836_intc_disable_irq(uint32_t irq __maybe_unused)
{
	BCM2835_OPS_DISABLE_IRQ(irq);

	switch (irq) {
	case IRQ_TYPE_CNTPS:
	case IRQ_TYPE_CNTPNS:
	case IRQ_TYPE_CNTHP:
	case IRQ_TYPE_CNTV:
		bcm2836_disable_timer_irq();
		break;
	case IRQ_TYPE_MAILBOX0:
		bcm2836_disable_mailbox0();
		break;
	case IRQ_TYPE_MAILBOX1:
		/* unused */
		break;
	case IRQ_TYPE_MAILBOX2:
		/* unused */
		break;
	case IRQ_TYPE_MAILBOX3:
		/* unused */
		break;
	case IRQ_TYPE_GPU_FAST:
		bcm2836_disable_gpu_irq();
		break;
	case IRQ_TYPE_PMU_FAST:
		bcm2836_disable_pmu_irq();
		break;
	default:
		uk_pr_err("unsurpported bcm2836irq id:%d\n", irq);
	}
}

static
void bcm2836_intc_set_irq_trigger(uint32_t irq __maybe_unused,
				  enum uk_intctlr_irq_trigger trigger
				  __maybe_unused)
{
	/* unused */
	BCM2835_OPS_SET_IRQ_TRIGGER(irq, trigger);
}

static void bcm2836_intc_initialize(void)
{
	BCM2835_OPS_INITIALIZE;
}

static void bcm2836_intc_handle_irq(struct __regs *regs)
{
	__u32 intc_source_val;

	intc_source_val = ioreg_read32(
		(void *)(ARM_TIMER_BASE + ARM_C0_TIMER_IRQ_CTL));
	switch (intc_source_val) {
	case IRQ_SOURCE_CNTPS:
	case IRQ_SOURCE_CNTPNS:
	case IRQ_SOURCE_CNTHP:
	case IRQ_SOURCE_CNTV:
		uk_intctlr_irq_handle(regs, IRQ_ID_CNTV);
		break;
	case IRQ_SOURCE_MAILBOX0:
		uk_intctlr_irq_handle(regs, IRQ_BASE + IRQ_TYPE_MAILBOX0);
		break;
	case IRQ_SOURCE_MAILBOX1:
		uk_intctlr_irq_handle(regs, IRQ_BASE + IRQ_TYPE_MAILBOX1);
		break;
	case IRQ_SOURCE_MAILBOX2:
		uk_intctlr_irq_handle(regs, IRQ_BASE + IRQ_TYPE_MAILBOX2);
		break;
	case IRQ_SOURCE_MAILBOX3:
		uk_intctlr_irq_handle(regs, IRQ_BASE + IRQ_TYPE_MAILBOX3);
		break;
	case IRQ_SOURCE_GPU_FAST:
		uk_intctlr_irq_handle(regs, IRQ_BASE + IRQ_TYPE_GPU_FAST);
		break;
	case IRQ_SOURCE_PMU_FAST:
		uk_intctlr_irq_handle(regs, IRQ_BASE + IRQ_TYPE_PMU_FAST);
		break;
	default:
		break;
	}
}

tn_intctlr_trap_register(bcm2836_intc_handle_irq);

static inline void bcm2836_intc_set_ops(void)
{
	struct bcm_operations drv_ops = {
		.initialize        = bcm2836_intc_initialize,
		.enable_irq        = bcm2836_intc_enable_irq,
		.disable_irq       = bcm2836_intc_disable_irq,
		.set_irq_trigger   = bcm2836_intc_set_irq_trigger,
		.handle_irq        = bcm2836_intc_handle_irq,
	};

	bcm2836_intc_drv.ops = drv_ops;
}

int bcm2836_intc_do_probe(struct bcm_intc_dev **dev)
{
	struct ukplat_bootinfo *bi = ukplat_bootinfo_get();
	int ret;
	void *fdt;

	UK_ASSERT(bi);
	fdt = (void *)bi->dtb;
	if (bcm2835_intc_set_info(fdt) < 0)
		/* bcm2835_intc 初始化失败 */
		return -FDT_ERR_NOTFOUND;

	fdt_bcm2836_intc_offset = fdt_node_offset_by_compatible_list(
		fdt, -1, bcm2836_intc_device_list);
	if (fdt_bcm2836_intc_offset < 0)
		/* bcm2836_intc 在设备树中未找到 */
		return -FDT_ERR_NOTFOUND;

	/* 从设备树获取中断控制器内存地址与长度 */
	ret = fdt_get_address(fdt, fdt_bcm2836_intc_offset, 0,
			    &bcm2836_intc_drv.mem_addr,
			    &bcm2836_intc_drv.mem_size);
	if (unlikely(ret < 0)) {
		uk_pr_err("Could not find bcm2836_intc memory region!\n");
		return ret;
	}

	bcm2836_intc_set_ops();
	*dev = &bcm2836_intc_drv;

	return 0;
}
