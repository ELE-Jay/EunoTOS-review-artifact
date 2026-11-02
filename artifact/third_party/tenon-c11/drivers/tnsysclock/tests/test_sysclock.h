/* Copyright 2024 Hangzhou Yingyi Technology Co., Ltd
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

#ifndef __TEST_SYSCLOCK_H__
#define __TEST_SYSCLOCK_H__

#include <uk/intctlr.h>

extern struct uk_intctlr_irq irq;
extern uint32_t freq;

uint64_t sysclock_get_counts(void);
void sysclock_unmask_irq(void);
void sysclock_mask_irq(void);
void sysclock_set_next(uint64_t set_counts, uint8_t is_start __unused);

#endif /* __TEST_SYSCLOCK_H__ */
