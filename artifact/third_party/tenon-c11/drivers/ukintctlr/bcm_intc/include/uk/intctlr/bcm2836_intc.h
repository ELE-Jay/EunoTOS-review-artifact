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

#ifndef BCM2836_INTC_H
#define BCM2836_INTC_H

#include <uk/intctlr/bcm_intc.h>

/* bcm2836 registers*/
#define ARM_TIMER_BASE			bcm2836_intc_drv.mem_addr
#define ARM_C0_TIMER_IRQ_CTL		0x40
#define ARM_C0_TIMER_IRQ_CTL_CNTVIRQ_ENABLE	(1 << 3)
#define ARM_C0_TIMER_IRQ_CTL_CNTVIRQ_DISABLE	0

#define IRQ_BASE		20
#define IRQ_TYPE_CNTPS		0
#define IRQ_TYPE_CNTPNS		1
#define IRQ_TYPE_CNTHP		2
#define IRQ_TYPE_CNTV		3
#define IRQ_TYPE_MAILBOX0	4
#define IRQ_TYPE_MAILBOX1	5
#define IRQ_TYPE_MAILBOX2	6
#define IRQ_TYPE_MAILBOX3	7
#define IRQ_TYPE_GPU_FAST	8
#define IRQ_TYPE_PMU_FAST	9
#define IRQ_ID_CNTV		0
#define IRQ_ID_INVALID		0xFFFF

#define IRQ_SOURCE_CNTPS	0
#define IRQ_SOURCE_CNTPNS	(1 << 1)
#define IRQ_SOURCE_CNTHP	(1 << 2)
#define IRQ_SOURCE_CNTV		(1 << 3)
#define IRQ_SOURCE_MAILBOX0	(1 << 4)
#define IRQ_SOURCE_MAILBOX1	(1 << 5)
#define IRQ_SOURCE_MAILBOX2	(1 << 6)
#define IRQ_SOURCE_MAILBOX3	(1 << 7)
#define IRQ_SOURCE_GPU_FAST	(1 << 8)
#define IRQ_SOURCE_PMU_FAST	(1 << 9)

extern struct bcm_intc_dev bcm2836_intc_drv;
extern int fdt_bcm2836_intc_offset;
int bcm2836_intc_do_probe(struct bcm_intc_dev **dev);
int fdt_xlat_bcm2836(const void *fdt, int nodeoffset, __u32 index,
		    struct uk_intctlr_irq *irq);

#endif
