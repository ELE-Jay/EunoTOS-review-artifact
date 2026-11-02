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

#ifndef LIMITS_H
#define LIMITS_H

/* currently bcm_intctlr support irq number */
#define UK_INTCTLR_FIRST_ALLOCABLE_IRQ	0
#define UK_INTCTLR_LAST_ALLOCABLE_IRQ	99
#define UK_INTCTLR_MAX_IRQ		100

#define UK_INTCTLR_ALLOCABLE_IRQ_COUNT			\
	(UK_INTCTLR_LAST_ALLOCABLE_IRQ - UK_INTCTLR_FIRST_ALLOCABLE_IRQ)

#endif
