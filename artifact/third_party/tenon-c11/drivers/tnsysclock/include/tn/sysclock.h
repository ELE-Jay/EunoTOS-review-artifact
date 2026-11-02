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
 * WITHOUT WARRANTIES OR CONDITIONS OF ssANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __TN_SYSCLOCK_H__
#define __TN_SYSCLOCK_H__

/**
 * Probe and initialize the configured system clock.
 * @return 0 on success, negative errno on error
 */
int tn_sysclock_probe(void);

/**
 * Get the current system clock count.
 * Every system clock driver must provide a unsigned 64-bit count.
 * This value can be read from the hardware timer directly or can be
 * calculated based on the hardware timer.
 * @return The current system clock count.
 */
uint64_t tn_sysclock_get_counts(void);

/**
 * Notify the system clock driver that a time base interrupt has occurred.
 * This function is called by the system clock interrupt handler.
 */
void tn_sysclock_isr_notify(void);

/**
 * Mask the system clock interrupt.
 */
void tn_sysclock_mask_irq(void);

/**
 * Unmask the system clock interrupt.
 */
void tn_sysclock_unmask_irq(void);

/**
 * Set the next time-base interrupt occurrence.
 * @param set_counts Counts for the next time-base irq occurring
 * @param set_auto_reload 1 means that driver can set auto-reload mode if the
 * sysclock supports it, 0 means that driver can't set auto-reload mode.
 * @return void
 */
void tn_sysclock_set_next(uint64_t set_counts, uint8_t set_auto_reload);

#endif /* __TN_SYSCLOCK_H__ */
