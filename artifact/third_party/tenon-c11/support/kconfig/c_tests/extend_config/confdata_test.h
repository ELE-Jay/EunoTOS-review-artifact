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

#ifndef CONFDATA_TEST_H
#define CONFDATA_TEST_H

/* 测试用例失败错误信息打印 */
#define ERR_PRINT()	\
	do {	\
		printf("**fail test case info**\n");	\
		printf("*file: %s\n", __FILE__);	\
		printf("*func: %s\n", __func__);	\
		printf("*line: %d\n", __LINE__);	\
		printf("**end**\n");	\
	} while (0)

/* case创建各自的文件夹，权限设置为可读/写 */
#define FOLDER_PERMMISION 0755
/* 流读取文件的单行最大缓存 */
#define FILE_LEN 80
/* 流读取文件的总缓存大小 */
#define FILE_MAX 512
/* 需要删除文件的路径最大长度 */
#define REMOVE_DIR_PATH_MAX 256

#endif
