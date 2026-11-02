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

#include <libfdt.h>
#include <uk/essentials.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/intctlr/limits.h>
#include <uk/intctlr/bcm_intc.h>
#include <uk/plat/lcpu.h>
#include <uk/ofw/fdt.h>
#include <uk/intctlr/bcm2835_intc.h>

static const char *const bcm2835_intc_device_list[] __maybe_unused = {
	/* 此处bcm2836-armctrl-ic沿用2835的中断控制器设计 */
	"brcm,bcm2836-armctrl-ic",
	"brcm,bcm2835-armctrl-ic",
	NULL
};

int fdt_bcm2835_intc_offset;

/** bcm2835 interrupt driver */
struct bcm_intc_dev bcm2835_intc_drv = {
	.mem_addr  = 0,
	.mem_size  = 0,
};

int fdt_xlat_bcm2835(const void *fdt, int nodeoffset, __u32 index,
		    struct uk_intctlr_irq *irq)
{
	int ret, size;
	fdt32_t *prop;
	__u32 bank_type, bank_irq_id;

	ret = fdt_get_interrupt(fdt, nodeoffset, index, &size, &prop);
	if (unlikely(ret < 0))
		return ret;

	/* bcm中断控制器interrupt-cells为2 */
	UK_ASSERT(size == 2);

	bank_type = fdt32_to_cpu(prop[0]);
	bank_irq_id = fdt32_to_cpu(prop[1]);

	switch (bank_type) {
	case IRQ_BANK_BASIC:
		if (bank_irq_id >= IRQ_BANK_BASIC_IRQ_MAX)
			goto err;
		irq->id = bank_irq_id + IRQ_BANK_BASIC_IRQ_OFFSET;
		break;
	case IRQ_BANK_1:
		if (bank_irq_id >= IRQ_BANK_1_IRQ_MAX)
			goto err;
		irq->id = bank_irq_id + IRQ_BANK_1_IRQ_OFFSET;
		break;
	case IRQ_BANK_2:
		if (bank_irq_id >= IRQ_BANK_2_IRQ_MAX)
			goto err;
		irq->id = bank_irq_id + IRQ_BANK_2_IRQ_OFFSET;
		break;
	default:
		goto err;
	}

	return 0;

err:
	uk_pr_err("DTB: bcm2835 interrupt irq bank err\n");
	uk_pr_err("bank_type: %x\n", bank_type);
	uk_pr_err("bank_irq_id: %x\n", bank_irq_id);
	return -FDT_ERR_BADNCELLS;
}

static void bcm2835_intc_initialize(void)
{
	/* 初始化阶段先mask所有中断 */
	ioreg_write32((void *)
		(ARM_SIDE_INTC_BASE + DISABLE_BASIC_IRQS_OFFSET),
		IRQ_REG_MASK);
	ioreg_write32((void *)
		(ARM_SIDE_INTC_BASE + DISABLE_IRQS_1_OFFSET),
		IRQ_REG_MASK);
	ioreg_write32((void *)
		(ARM_SIDE_INTC_BASE + DISABLE_IRQS_2_OFFSET),
		IRQ_REG_MASK);
}

static void bcm2835_intc_enable_irq(uint32_t irq)
{
	if ((irq >= IRQ_BANK_BASIC_IRQ_OFFSET) &&
	    (irq < IRQ_BANK_BASIC_IRQ_OFFSET + IRQ_BANK_1_IRQ_OFFSET)) {
		ioreg_write32((void *)
			(ARM_SIDE_INTC_BASE + ENABLE_BASIC_IRQS_OFFSET),
			1 << (irq - IRQ_BANK_BASIC_IRQ_OFFSET));
	} else if ((irq >= IRQ_BANK_1_IRQ_OFFSET) &&
	    (irq < IRQ_BANK_2_IRQ_OFFSET)) {
		ioreg_write32((void *)
			(ARM_SIDE_INTC_BASE + ENABLE_IRQS_1_OFFSET),
			1 << (irq - IRQ_BANK_1_IRQ_OFFSET));
	} else if (irq >= IRQ_BANK_2_IRQ_OFFSET) {
		ioreg_write32((void *)
			(ARM_SIDE_INTC_BASE + ENABLE_IRQS_2_OFFSET),
			1 << (irq - IRQ_BANK_2_IRQ_OFFSET));
	}
}

static void bcm2835_intc_disable_irq(uint32_t irq)
{
	if ((irq >= IRQ_BANK_BASIC_IRQ_OFFSET) &&
	    (irq < IRQ_BANK_BASIC_IRQ_OFFSET + IRQ_BANK_1_IRQ_OFFSET)) {
		ioreg_write32((void *)
			(ARM_SIDE_INTC_BASE + DISABLE_IRQS_1_OFFSET),
			1 << (irq - IRQ_BANK_BASIC_IRQ_OFFSET));
	} else if ((irq >= IRQ_BANK_1_IRQ_OFFSET) &&
	    (irq < IRQ_BANK_2_IRQ_OFFSET)) {
		ioreg_write32((void *)
			(ARM_SIDE_INTC_BASE + DISABLE_IRQS_2_OFFSET),
			1 << (irq - IRQ_BANK_1_IRQ_OFFSET));
	} else if (irq >= IRQ_BANK_2_IRQ_OFFSET) {
		ioreg_write32((void *)
			(ARM_SIDE_INTC_BASE + ENABLE_IRQS_2_OFFSET),
			1 << (irq - IRQ_BANK_2_IRQ_OFFSET));
	}
}

static
void bcm2835_intc_set_irq_trigger(uint32_t irq __unused,
				  enum uk_intctlr_irq_trigger trigger __unused)
{
	/* unused */
}

static void bcm2835_intc_handle_irq(struct __regs *regs)
{
	__u32 intc_source_val, intc_pending_val;

	intc_source_val = ioreg_read32(
		(void *)(ARM_SIDE_INTC_BASE + IRQ_BASIC_PENDING_OFFSET));

	for (int cnt = 0; cnt < IRQ_BANK_BASIC_IRQ_MAX; cnt++) {
		if (((intc_source_val >> cnt) & 1) == 1) {
			uk_intctlr_irq_handle(regs,
					      IRQ_BANK_BASIC_IRQ_OFFSET + cnt);
			goto end;
		}
	}

	if ((intc_source_val & IRQ_PENDING_1_SET) == IRQ_PENDING_1_SET) {
		intc_pending_val = ioreg_read32(
			(void *)(ARM_SIDE_INTC_BASE +
			IRQ_PENDING_1_OFFSET));
		for (int cnt = 0; cnt < IRQ_BANK_1_IRQ_MAX; cnt++) {
			if (((intc_pending_val >> cnt) & 1) == 1) {
				uk_intctlr_irq_handle(regs,
					      IRQ_BANK_1_IRQ_OFFSET + cnt);
				goto end;
			}
		}
	}

	if ((intc_source_val & IRQ_PENDING_2_SET) == IRQ_PENDING_2_SET) {
		intc_pending_val = ioreg_read32(
			(void *)(ARM_SIDE_INTC_BASE +
			IRQ_PENDING_2_OFFSET));
		for (int cnt = 0; cnt < IRQ_BANK_2_IRQ_MAX; cnt++) {
			if (((intc_pending_val >> cnt) & 1) == 1) {
				uk_intctlr_irq_handle(regs,
					      IRQ_BANK_2_IRQ_OFFSET + cnt);
				goto end;
			}
		}
	}
end:
	uk_pr_info("finished handling irq\n");
}

static inline void bcm2835_intc_set_ops(void)
{
	struct bcm_operations drv_ops = {
		.initialize        = bcm2835_intc_initialize,
		.enable_irq        = bcm2835_intc_enable_irq,
		.disable_irq       = bcm2835_intc_disable_irq,
		.set_irq_trigger   = bcm2835_intc_set_irq_trigger,
		.handle_irq        = bcm2835_intc_handle_irq,
	};

	bcm2835_intc_drv.ops = drv_ops;
}

/* bcm2835中断控制器初始化函数 */
int bcm2835_intc_set_info(void *fdt)
{
	int ret;

	/* 从设备树获取中断控制器节点信息 */
	fdt_bcm2835_intc_offset = fdt_node_offset_by_compatible_list(
		fdt, -1, bcm2835_intc_device_list);
	if (fdt_bcm2835_intc_offset < 0)
		/* 节点不存在 */
		return -FDT_ERR_NOTFOUND;

	/* 获取中断控制器的内存区域地址和大小 */
	ret = fdt_get_address(fdt, fdt_bcm2835_intc_offset, 0,
			    &bcm2835_intc_drv.mem_addr,
			    &bcm2835_intc_drv.mem_size);
	if (unlikely(ret < 0)) {
		uk_pr_err("Could not find bcm2835_intc memory region!\n");
		return ret;
	}

	bcm2835_intc_set_ops();

	uk_pr_info("Found bcm2835_intc on:\n");
	uk_pr_info("\tDistributor  : 0x%lx - 0x%lx\n",
		   bcm2835_intc_drv.mem_addr,
		   bcm2835_intc_drv.mem_addr +
		   bcm2835_intc_drv.mem_size - 1);

	return 0;
}

/* bcm2835中断控制器注册函数 */
int bcm2835_intc_do_probe(struct bcm_intc_dev **dev)
{
	struct ukplat_bootinfo *bi = ukplat_bootinfo_get();
	int ret;
	void *fdt;

	UK_ASSERT(bi);
	fdt = (void *)bi->dtb;
	ret = bcm2835_intc_set_info(fdt);
	if (unlikely(ret < 0))
		return ret;
	*dev = &bcm2835_intc_drv;

	return 0;
}
