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

#include <errno.h>
#include <uk/config.h>
#include <uk/assert.h>
#include <uk/intctlr.h>
#include <uk/intctlr/limits.h>
#ifdef CONFIG_LIBUKINTCTLR_BCM2836_INTC
#include <uk/intctlr/bcm2836_intc.h>
#endif
#ifdef CONFIG_LIBUKINTCTLR_BCM2835_INTC
#include <uk/intctlr/bcm2835_intc.h>
#endif

struct bcm_intc_dev *bcm_intc;
struct uk_intctlr_desc intctlr;
struct uk_intctlr_driver_ops ops;

#if CONFIG_LIBUKOFW

#include <libfdt.h>
#include <uk/ofw/fdt.h>

static int fdt_xlat(const void *fdt, int nodeoffset, __u32 index,
		    struct uk_intctlr_irq *irq)
{
	int ret, irq_parent_offset, is_done;

	UK_ASSERT(irq);

	irq_parent_offset = fdt_find_irq_parent_offset(fdt, nodeoffset);
	is_done = 0;
#ifdef CONFIG_LIBUKINTCTLR_BCM2836_INTC
	if ((fdt_bcm2836_intc_offset > 0) &&
		(irq_parent_offset == fdt_bcm2836_intc_offset)) {
		ret = fdt_xlat_bcm2836(fdt, nodeoffset, index, irq);
		is_done = 1;
		if (unlikely(ret < 0))
			return ret;
	}
#endif /* CONFIG_LIBUKINTCTLR_BCM2836_INTC */

#ifdef CONFIG_LIBUKINTCTLR_BCM2835_INTC
	if ((fdt_bcm2835_intc_offset > 0) &&
		(irq_parent_offset == fdt_bcm2835_intc_offset)) {
		ret = fdt_xlat_bcm2835(fdt, nodeoffset, index, irq);
		is_done = 1;
		if (unlikely(ret < 0))
			return ret;
	}
#endif /* CONFIG_LIBUKINTCTLR_BCM2835_INTC */
	if (is_done == 0)
		return -FDT_ERR_NOTFOUND;
	return 0;
}
#endif /* CONFIG_LIBUKOFW */

/* 根据设备树参数来设置中断属性 */
static int irq_set_trigger(struct uk_intctlr_irq *irq)
{
	if (irq->trigger != UK_INTCTLR_IRQ_TRIGGER_NONE)
		/* 调用函数配置irq_trigger */
		bcm_intc->ops.set_irq_trigger(irq->id, irq->trigger);

	return 0;
}

/* 注册中断API */
int uk_intctlr_probe(void)
{
	int ret = -ENODEV;

#ifdef CONFIG_LIBUKINTCTLR_BCM2836_INTC
	ret = bcm2836_intc_do_probe(&bcm_intc);
	if (ret == 0)
		goto init;
#endif /* CONFIG_LIBUKINTCTLR_BCM2836_INTC */

#ifdef CONFIG_LIBUKINTCTLR_BCM2835_INTC
	ret = bcm2835_intc_do_probe(&bcm_intc);
	if (ret == 0)
		goto init;
#endif /* CONFIG_LIBUKINTCTLR_BCM2835_INTC */
	if (unlikely(ret))
		return ret;

init:
	intctlr.name = "BCM-INTC";
	ops.initialize = bcm_intc->ops.initialize;
	ops.percpu_init = __NULL;
	ops.irq_set_trigger = irq_set_trigger;
	ops.mask_irq = bcm_intc->ops.disable_irq;
	ops.unmask_irq = bcm_intc->ops.enable_irq;
	ops.handle = bcm_intc->ops.handle_irq;
	ops.irq_set_affinity = __NULL;
	ops.irq_set_priority = __NULL;
#if defined(CONFIG_LIBUKINTCTLR_TEST) || defined(CONFIG_LIBUKTEST_ALL)
	ops.irq_get_priority = __NULL;
	ops.spi_get_affinity = __NULL;
	ops.simulate_spi     = __NULL;
#endif
	/* reserved for software general interrupt to specified core */
	ops.sgi_op = __NULL;
#if CONFIG_LIBUKOFW
	ops.fdt_xlat = fdt_xlat;
#endif /* CONFIG_LIBUKOFW */

	intctlr.ops = &ops;

	return uk_intctlr_register(&intctlr);
}
