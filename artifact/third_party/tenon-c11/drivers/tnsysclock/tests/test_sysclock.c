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

#include <uk/test.h>
#include <uk/intctlr.h>
#include "test_sysclock.h"

/* 测试系统定时器定时功能场景
 * current_count：测试时基中断产生的时间戳
 * test_time_base_irq_handled：测试时基中断函数是否发生
 */
static uint64_t current_count;
static uint8_t test_time_base_irq_handled;

/* 测试时基中断函数 */
static int test_sysclock_irq_handler(void *arg __unused)
{
	current_count = sysclock_get_counts();
	sysclock_mask_irq();
	test_time_base_irq_handled = 1;
	return 1;
}

/* TEST_TIMING_SECS：测试定时器超时时长，单位秒(s)
 * TEST_TIMING_BIAS_NANOSECS：允许时间戳误差，单位纳秒(ns)
 * TEST_TIMING_BIAS_COUNT：允许时间戳误差，单位count
 */
#define TEST_TIMING_SECS 2
/* 误差设定为0.2s */
#define TEST_TIMING_BIAS_NANOSECS 200000000ULL
#define TEST_TIMING_BIAS_COUNT                                                 \
	((TEST_TIMING_BIAS_NANOSECS / (1000000000ULL / freq)))

UK_TESTCASE(uk_driver_sysclock, test_driver_sysclock_timing)
{
	uint64_t last_count, delta_count, next_count;

	/* 1.初始化测试场景 */
	/* 1.1设置定时器超时时长 */
	next_count = freq * TEST_TIMING_SECS;

	/* 1.2注册测试时基中断函数 */
	uk_intctlr_irq_register(irq.id, test_sysclock_irq_handler, NULL);

	/* 2.测试系统定时器定时功能场景 */
	/* 2.1保存当前时间戳与开始系统定时器定时 */
	last_count = sysclock_get_counts();
	sysclock_set_next((uint64_t)next_count, 0);
	sysclock_unmask_irq();

	/* 2.2处理测试时基中断 */
	while (test_time_base_irq_handled != 1)
		__asm__ __volatile__("wfi");

	/* 3.计算超时时间，校验测试结果 */
	delta_count = current_count - last_count;
	/* 实际超时时间预期在预设时间允许误差内(+-BIAS) */
	UK_TEST_EXPECT_SNUM_GT(delta_count,
			       next_count - (uint64_t)TEST_TIMING_BIAS_COUNT);
	UK_TEST_EXPECT_SNUM_LT(delta_count,
			       next_count + (uint64_t)TEST_TIMING_BIAS_COUNT);

	/* 4.恢复环境 */
	uk_intctlr_irq_unregister(irq.id, test_sysclock_irq_handler);
}

uk_testsuite_register(uk_driver_sysclock, NULL, NULL);
