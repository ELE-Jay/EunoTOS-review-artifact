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

#ifndef __TN_LIBTNSYSTICK_IMPL_H__
#define __TN_LIBTNSYSTICK_IMPL_H__

#include <uk/arch/time.h>
#include <uk/intctlr.h>
#include <tn/systick.h>
#include <stdint.h>

#define __MAX_CONVERT_SECS 3600UL
#define __MAX_CONVERT_NS (__MAX_CONVERT_SECS * ukarch_time_sec_to_nsec(1))

/*
 * Calculate multiplier/shift factors for scaled math.
 */
static inline void calculate_mult_shift(uint32_t *mult, uint8_t *shift,
					uint64_t from, uint64_t to)
{
	uint64_t tmp;
	uint32_t sft, sftacc = 32;

	/*
	 * Calculate the shift factor which is limiting the conversion
	 * range:
	 */
	tmp = ((uint64_t)__MAX_CONVERT_SECS * from) >> 32;
	while (tmp) {
		tmp >>= 1;
		sftacc--;
	}

	/*
	 * Calculate shift factor (S) and scaling multiplier (M).
	 *
	 * (S) needs to be the largest shift factor (<= max_shift) where
	 * the result of the M calculation below fits into uint32_t
	 * without truncation.
	 *
	 * multiplier = (target << shift) / source
	 */
	for (sft = 32; sft > 0; sft--) {
		tmp = (uint64_t)to << sft;

		/* Ensuring we round to nearest when calculating the
		 * multiplier
		 */
		tmp += from / 2;
		tmp /= from;
		if ((tmp >> sftacc) == 0)
			break;
	}
	*mult = tmp;
	*shift = sft;
}

void tn_systick_register(const char *name,
			 uint32_t freq,
			 struct uk_intctlr_irq *irq);

#endif /* __TN_LIBTNSYSTICK_IMPL_H__ */
