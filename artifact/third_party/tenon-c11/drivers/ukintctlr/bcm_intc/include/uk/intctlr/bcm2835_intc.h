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

#ifndef BCM2835_INTC_H
#define BCM2835_INTC_H

#include <uk/intctlr/bcm_intc.h>

#ifdef CONFIG_LIBUKINTCTLR_BCM2835_INTC
#define BCM2835_OPS_INITIALIZE		bcm2835_intc_drv.ops.initialize()
#define BCM2835_OPS_ENABLE_IRQ(irq)	bcm2835_intc_drv.ops.enable_irq(irq)
#define BCM2835_OPS_DISABLE_IRQ(irq)	bcm2835_intc_drv.ops.disable_irq(irq)
#define BCM2835_OPS_SET_IRQ_TRIGGER(irq, trigger) \
	bcm2835_intc_drv.ops.set_irq_trigger(irq, trigger)
#define BCM2835_OPS_HANDLE_TRQ(regs)	bcm2835_intc_drv.ops.handle_irq(regs)
#else
#define BCM2835_OPS_INITIALIZE
#define BCM2835_OPS_ENABLE_IRQ(irq)
#define BCM2835_OPS_DISABLE_IRQ(irq)
#define BCM2835_OPS_SET_IRQ_TRIGGER(irq, trigger)
#define BCM2835_OPS_HANDLE_TRQ(regs)
#endif

#define IRQ_BANK_BASIC	0
#define IRQ_BANK_1	1
#define IRQ_BANK_2	2
#define IRQ_BANK_BASIC_IRQ_MAX	8
#define IRQ_BANK_1_IRQ_MAX	32
#define IRQ_BANK_2_IRQ_MAX	32
#ifdef CONFIG_LIBUKINTCTLR_BCM2836_INTC
#define ARM_SIDE_IRQ_ID_BASE	32
#else
#define ARM_SIDE_IRQ_ID_BASE	0
#endif

#define IRQ_BANK_BASIC_IRQ_OFFSET	ARM_SIDE_IRQ_ID_BASE
#define IRQ_BANK_1_IRQ_OFFSET	(IRQ_BANK_BASIC_IRQ_OFFSET + \
	IRQ_BANK_BASIC_IRQ_MAX)
#define IRQ_BANK_2_IRQ_OFFSET	(IRQ_BANK_1_IRQ_OFFSET + IRQ_BANK_1_IRQ_MAX)

/* Macros to access Interrupt Controller Registers with base address */
#define ARM_SIDE_INTC_BASE		bcm2835_intc_drv.mem_addr

#define IRQ_BASIC_PENDING_OFFSET	0x00
#define IRQ_PENDING_1_OFFSET		0x04
#define IRQ_PENDING_2_OFFSET		0x08
#define FIQ_CONTROL_OFFSET		0x0C
#define ENABLE_IRQS_1_OFFSET		0x10
#define ENABLE_IRQS_2_OFFSET		0x14
#define ENABLE_BASIC_IRQS_OFFSET	0x18
#define DISABLE_IRQS_1_OFFSET		0x1C
#define DISABLE_IRQS_2_OFFSET		0x20
#define DISABLE_BASIC_IRQS_OFFSET	0x24

#define IRQ_PENDING_1_SET		(1 << 8)
#define IRQ_PENDING_2_SET		(1 << 9)

#define IRQS_1_SYSTEM_TIMER_IRQ_0	(1 << 0)
#define IRQS_1_SYSTEM_TIMER_IRQ_1	(1 << 1)
#define IRQS_1_SYSTEM_TIMER_IRQ_2	(1 << 2)
#define IRQS_1_SYSTEM_TIMER_IRQ_3	(1 << 3)
#define IRQS_1_USB_IRQ			(1 << 9)

#define IRQ_REG_MASK			0xFFFFFFFF

int bcm2835_intc_set_info(void *fdt);
int bcm2835_intc_do_probe(struct bcm_intc_dev **dev);
int fdt_xlat_bcm2835(const void *fdt, int nodeoffset, __u32 index,
		    struct uk_intctlr_irq *irq);
extern struct bcm_intc_dev bcm2835_intc_drv;
extern int fdt_bcm2835_intc_offset;

#endif
