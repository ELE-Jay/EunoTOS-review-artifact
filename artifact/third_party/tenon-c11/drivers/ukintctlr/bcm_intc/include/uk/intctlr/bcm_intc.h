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

#ifndef BCM_INTC_H
#define BCM_INTC_H

#include <stdint.h>
#include <uk/intctlr.h>

#define FDT_BCM_INTC_IRQ_FLAGS_TL_MASK		0xf /* trigger - level */
#define FDT_BCM_INTC_IRQ_FLAGS_TL_EDGE_HI	1 /* 上升沿使能 */
#define FDT_BCM_INTC_IRQ_FLAGS_TL_EDGE_LO	2 /* 下降沿使能 */
#define FDT_BCM_INTC_IRQ_FLAGS_TL_LEVEL_LO	4 /* 低电平使能 */
#define FDT_BCM_INTC_IRQ_FLAGS_TL_LEVEL_HI	8 /* 高电平使能 */

/** BCM driver operations */
struct bcm_operations {
	/** Initialize BCM controller */
	void (*initialize)(void);
	/** Enable IRQ */
	void (*enable_irq)(uint32_t irq);
	/** Disable IRQ */
	void (*disable_irq)(uint32_t irq);
	/** Set IRQ trigger type */
	void (*set_irq_trigger)(uint32_t irq,
				enum uk_intctlr_irq_trigger trigger);
	/** Handle IRQ */
	void (*handle_irq)(struct __regs *regs);
};

/** bcm controller structure */
struct bcm_intc_dev {
	/** Base address */
	uint64_t mem_addr;
	/** Memory size */
	uint64_t mem_size;
	/** Driver operations */
	struct bcm_operations ops;
};

#endif
