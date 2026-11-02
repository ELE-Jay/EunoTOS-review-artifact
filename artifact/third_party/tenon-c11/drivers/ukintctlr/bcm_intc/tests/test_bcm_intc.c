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

#include <uk/test.h>
#include <uk/assert.h>
#include <uk/ofw/fdt.h>

/* 设备树测试相关宏 */
#define TEST_DTB_SIZE 1000

/* 测试设备树中中断控制器读取异常场景 */
UK_TESTCASE(uk_driver_bcm_intc, test_driver_dtb_bcm_intc_info_err)
{
	int ret, bufsize, fdt_bcm_intc, test_timer;
	__u64 fdt_address_val, fdt_size_val;
	const char *const bcm_intc_device_list[] __maybe_unused = {
	    "brcm,bcm2836-l1-intc",
	    NULL,
	};

	/* 1.初始化测试场景 */
	bufsize = TEST_DTB_SIZE;
	void *test_fdt = malloc(bufsize);

	ret = fdt_create_empty_tree(test_fdt, bufsize);
	if (ret)
		uk_pr_err("create a dtb failed\n");

	/* 2.设备树读取中断控制器异常场景 */
	/* 2.1根据compatible读取中断控制器异常场景 */
	fdt_bcm_intc = fdt_node_offset_by_compatible_list(test_fdt, -1,
							  bcm_intc_device_list);
	UK_TEST_EXPECT_SNUM_EQ(fdt_bcm_intc, -FDT_ERR_NOTFOUND);

	/* 2.2读取中断控制器地址与长度异常场景 */
	/* 向临时设备树中添加测试节点 */
	test_timer = fdt_add_subnode(test_fdt, 0, "intc");
	ret = fdt_setprop(test_fdt, test_timer, "compatible",
			  "brcm,bcm2836-l1-intc",
			  strlen(bcm_intc_device_list[0]));
	if (ret)
		uk_pr_err("set compatible failed\n");

	/* 校验设备树中已注册测试节点 */
	fdt_bcm_intc = fdt_node_offset_by_compatible_list(test_fdt, -1,
							  bcm_intc_device_list);
	UK_TEST_EXPECT_SNUM_EQ(fdt_bcm_intc, test_timer);

	/* 尝试读取地址,预期失败 */
	ret = fdt_get_address(test_fdt, 0, 0, &fdt_address_val, &fdt_size_val);
	UK_TEST_EXPECT_SNUM_EQ(ret, -FDT_ERR_NOTFOUND);

	/* 3.恢复环境 */
	free(test_fdt);
}

uk_testsuite_register(uk_driver_bcm_intc, NULL, NULL);
