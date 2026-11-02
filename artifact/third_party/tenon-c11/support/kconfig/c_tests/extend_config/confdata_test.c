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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include "confdata_test.h"
#include "../../lkc.h"

static struct property local_prompt = {0};

/* 测试函数指针 */
typedef int (*test_func)(void);

/* 文件对比函数，相同返回0，不一致返回1 */
static int compare_file(FILE *dest_fp, FILE *src_fp)
{
	int dest_word, src_word;

	/* 比较每个字符asic码 */
	while ((dest_word = fgetc(dest_fp)) != EOF &&
	       (src_word = fgetc(src_fp)) != EOF) {
		if (dest_word != src_word)
			return 1;
	}

	/* 如果目标文件读取结束,对比文件需要再读一位 */
	if (dest_word == EOF)
		src_word = fgetc(src_fp);

	/* 目标文件与对比文件同时结束才算对比成功 */
	if ((dest_word == EOF) && (src_word == EOF))
		return  0;
	else
		return  1;
}

/* 判断dest中是否完全包含src内容，是返回0，否则返回1 */
/* 要求读取的文件大小不大于1024bytes，否则返回-1 */
static int is_file_contains(FILE *dest_fp, FILE *src_fp)
{
	char dest_line[FILE_LEN];
	char src_line[FILE_LEN];
	char dest_data[FILE_MAX];
	char src_data[FILE_MAX];
	int length;
	int offset = 0;

	/* 读取dest文件 */
	while (fgets(dest_line, FILE_LEN, dest_fp) != NULL) {
		length = strlen(dest_line);
		if (offset + length > FILE_MAX) {
			ERR_PRINT();
			return -1;
		}
		memcpy(dest_data + offset, dest_line, length);
		offset += length;
	}
	*(dest_data + offset++) = '\0';

	/* 读取src文件 */
	offset = 0;
	while (fgets(src_line, FILE_LEN, src_fp) != NULL) {
		length = strlen(src_line);
		if (offset + length > FILE_MAX) {
			ERR_PRINT();
			return -1;
		}
		memcpy(src_data + offset, src_line, length);
		offset += length;
	}
	*(src_data + offset++) = '\0';

	/* 判断是否包含 */
	if (strstr(dest_data, src_data) != NULL)
		return 0;
	else
		return 1;
}

/* 删除文件夹里所有目录及文件,删除成功返回0,否则返回1 */
static int remove_dir(const char *dest_dir)
{
	char cur_dir[] = ".";
	char up_dir[] = "..";
	char dir_name[REMOVE_DIR_PATH_MAX + 1];
	DIR *dirp;
	struct dirent *dp;
	struct stat dir_stat;

	/* 参数传递进来的目录不存在，直接返回 */
	if (access(dest_dir, F_OK) != 0) {
		ERR_PRINT();
		return 0;
	}

	/* 获取目录属性失败，直接返回 */
	if (stat(dest_dir, &dir_stat) < 0) {
		ERR_PRINT();
		return 1;
	}

	if (S_ISREG(dir_stat.st_mode))
		/* 普通文件直接删除 */
		remove(dest_dir);
	else if (S_ISDIR(dir_stat.st_mode)) {
		/* 目录文件，递归删除目录中内容 */
		dirp = opendir(dest_dir);
		while ((dp = readdir(dirp)) != NULL) {
			if ((strcmp(cur_dir, dp->d_name)) == 0 ||
			    (strcmp(up_dir, dp->d_name)) == 0)
				/* 忽略 . 和 .. */
				continue;
			sprintf(dir_name, "%s/%s", dest_dir, dp->d_name);
			/* 递归删除 */
			remove_dir(dir_name);
		}
		closedir(dirp);
		/* 删除空目录 */
		rmdir(dest_dir);
	} else {
		fprintf(stderr, "unknown file type!");
		ERR_PRINT();
	}

	return 0;
}

/* 测试场景初始化 */
/* 成功返回0，否则返回1 */
static int test_case_init(void)
{
	rootmenu.prompt = &local_prompt;

	const char *defconfig_file = "kconfig/def_test_files/defconfig";
	const char *config_file = "kconfig/def_test_files/config.test";

	/* 解析config文件 */
	conf_parse(config_file);

	/* 读取默认配置 */
	if (conf_read(defconfig_file)) {
		ERR_PRINT();
		return 1;
	}

	/* 设置默认配置 */
	conf_set_all_new_symbols(def_default);

	/* 写入全局环境变量 */
	if (conf_write(NULL)) {
		ERR_PRINT();
		return 1;
	}
	rootmenu.prompt->text = "test";
}

/* 测试用例c_test_extend_not_set */
static int test_case_extend_not_set(void)
{
	FILE *expeced_config_fp, *expeced_header_fp;
	FILE *src_config_fp, *src_header_fp;
	int ret = 1;

	printf("test :c_test_extend_not_set->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_not_set", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		return 1;
	}
	ret = 1;
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "n", 1);
	setenv("KCONFIG_AUTOCONFIG", "c_test_extend_not_set/auto.conf", 1);
	setenv("KCONFIG_AUTOHEADER", "c_test_extend_not_set/_config.h", 1);
	setenv("KCONFIG_TRISTATE", "c_test_extend_not_set/tristate.config", 1);

	/* 2 调用conf_write_autoconf，执行用例 */
	ret = conf_write_autoconf(0);
	if (ret != 0) {
		/* 执行出错，打印错误位置，恢复环境 */
		ERR_PRINT();
		goto err_reset_env;
	}
	ret = 1;

	/* 3 判断输出文件是否符合预期 */
	/* 3.1 读取头文件与配置文件 */
	expeced_config_fp =
		fopen("kconfig/def_test_files/expected_config_not_set", "r");
	if (expeced_config_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	expeced_header_fp =
		fopen("kconfig/def_test_files/expected_header_not_set", "r");
	if (expeced_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_expeced_header_file;
	}

	src_config_fp = fopen("c_test_extend_not_set/auto.conf", "r");
	if (src_config_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_config_file;
	}

	src_header_fp = fopen("c_test_extend_not_set/_config.h", "r");
	if (src_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_header_file;
	}

	/* 3.2 将生成的配置文件与预期结果作比较 */
	ret = compare_file(expeced_config_fp, src_config_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	ret = 1;

	ret = compare_file(expeced_header_fp, src_header_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(expeced_header_fp);
	fclose(src_header_fp);
	fclose(expeced_config_fp);
	fclose(src_config_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	remove_dir("c_test_extend_not_set");

	printf("------c_test_extend_not_set->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_header_fp);
err_handle_src_header_file:
	fclose(src_config_fp);
err_handle_src_config_file:
	fclose(expeced_header_fp);
err_handle_expeced_header_file:
	fclose(expeced_config_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	remove_dir("c_test_extend_not_set");

	printf("------c_test_extend_not_set->fail!!\n");
	return 1;
}

/* 测试用例c_test_extend_set */
static int test_case_extend_set(void)
{
	FILE *expeced_config_fp, *expeced_header_fp;
	FILE *src_config_fp, *src_header_fp;
	int ret = 1;

	printf("test :c_test_extend_set->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_set", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		return 1;
	}
	ret = 1;
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "y", 1);
	setenv("KCONFIG_AUTOCONFIG", "c_test_extend_set/auto.conf", 1);
	setenv("KCONFIG_AUTOHEADER", "c_test_extend_set/_config.h", 1);
	setenv("KCONFIG_TRISTATE", "c_test_extend_set/tristate.config", 1);
	setenv("KCONFIG_EXTEND_NAME", "EXTENDTEST", 1);
	setenv("KCONFIG_EXTEND_TEMPLATE", "kconfig/def_test_files/std_template",
	       1);
	setenv("KCONFIG_EXTEND_AUTOCONFIG",
	       "c_test_extend_set/.extend.config", 1);
	setenv("KCONFIG_EXTEND_AUTOHEADER", "c_test_extend_set/autoconf.h", 1);

	/* 2 调用conf_write_autoconf，执行用例 */
	ret = conf_write_autoconf(0);
	if (ret != 0) {
		/* 执行出错，打印错误位置，恢复环境 */
		ERR_PRINT();
		goto err_reset_env;
	}
	ret = 1;

	/* 3 判断输出文件是否符合预期 */
	/* 3.1 读取头文件与配置文件 */
	expeced_config_fp =
		fopen("kconfig/def_test_files/expected_extend_config_set",
		      "r");
	if (expeced_config_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	expeced_header_fp =
		fopen("kconfig/def_test_files/expected_extend_header_set",
		      "r");
	if (expeced_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_expeced_header_file;
	}

	src_config_fp = fopen("c_test_extend_set/.extend.config", "r");
	if (src_config_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_config_file;
	}

	src_header_fp = fopen("c_test_extend_set/autoconf.h", "r");
	if (src_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_header_file;
	}

	/* 3.2 将生成的配置文件与预期结果作比较 */
	ret = compare_file(expeced_config_fp, src_config_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	ret = 1;

	ret = compare_file(expeced_header_fp, src_header_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(expeced_header_fp);
	fclose(src_header_fp);
	fclose(expeced_config_fp);
	fclose(src_config_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_set");

	printf("------c_test_extend_set->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_header_fp);
err_handle_src_header_file:
	fclose(src_config_fp);
err_handle_src_config_file:
	fclose(expeced_header_fp);
err_handle_expeced_header_file:
	fclose(expeced_config_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_set");

	printf("------c_test_extend_set->fail!!\n");
	return 1;
}

/* 测试用例c_test_extend_no_template_path */
static int test_case_extend_no_template_path(void)
{
	FILE *expeced_config_fp, *expeced_header_fp;
	FILE *src_config_fp, *src_header_fp;
	int ret = 1;

	printf("test :c_test_extend_no_template_path->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_no_template_path", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		return 1;
	}
	ret = 1;
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "y", 1);
	setenv("KCONFIG_AUTOCONFIG",
	       "c_test_extend_no_template_path/auto.conf", 1);
	setenv("KCONFIG_AUTOHEADER",
	       "c_test_extend_no_template_path/_config.h", 1);
	setenv("KCONFIG_TRISTATE",
	       "c_test_extend_no_template_path/tristate.config", 1);
	setenv("KCONFIG_EXTEND_NAME", "EXTENDTEST", 1);
	setenv("KCONFIG_EXTEND_AUTOCONFIG",
	       "c_test_extend_no_template_path/.extend.config", 1);
	setenv("KCONFIG_EXTEND_AUTOHEADER",
	       "c_test_extend_no_template_path/autoconf.h", 1);

	/* 2 调用conf_write_autoconf，执行用例 */
	ret = conf_write_autoconf(0);
	if (ret != 0) {
		/* 执行出错，打印错误位置，恢复环境 */
		ERR_PRINT();
		goto err_reset_env;
	}
	ret = 1;

	/* 3 判断输出文件是否符合预期 */
	/* 3.1 读取头文件与配置文件 */
	expeced_config_fp =
	fopen("kconfig/def_test_files/expected_extend_config_no_template_path",
	      "r");
	if (expeced_config_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	expeced_header_fp =
	fopen("kconfig/def_test_files/expected_extend_header_no_template_path",
	      "r");
	if (expeced_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_expeced_header_file;
	}

	src_config_fp = fopen("c_test_extend_no_template_path/.extend.config",
			      "r");
	if (src_config_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_config_file;
	}

	src_header_fp = fopen("c_test_extend_no_template_path/autoconf.h", "r");
	if (src_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_header_file;
	}

	/* 3.2 将生成的配置文件与预期结果作比较 */
	ret = compare_file(expeced_config_fp, src_config_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	ret = 1;

	ret = compare_file(expeced_header_fp, src_header_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(expeced_config_fp);
	fclose(src_config_fp);
	fclose(expeced_header_fp);
	fclose(src_header_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_no_template_path");

	printf("------c_test_extend_no_template_path->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_header_fp);
err_handle_src_header_file:
	fclose(src_config_fp);
err_handle_src_config_file:
	fclose(expeced_header_fp);
err_handle_expeced_header_file:
	fclose(expeced_config_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_no_template_path");

	printf("------c_test_extend_no_template_path->fail!!\n");
	return 1;
}

/* 测试用例c_test_extend_err_template_path */
static int test_case_extend_err_template_path(void)
{
	FILE *expeced_err_fp, *src_err_fp;
	int ret = 1;

	printf("test :c_test_extend_err_template_path->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_err_template_path", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		/* 恢复stderr重定向 */
		fclose(stderr);
		freopen("/dev/tty", "w", stderr);
		return 1;
	}
	/* 将stderr重定向至文件中 */
	if (freopen("c_test_extend_err_template_path/err.log", "w", stderr) ==
	    NULL) {
		ERR_PRINT();
		return 1;
	}
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "y", 1);
	setenv("KCONFIG_AUTOCONFIG",
	       "c_test_extend_err_template_path/auto.conf", 1);
	setenv("KCONFIG_AUTOHEADER",
	       "c_test_extend_err_template_path/_config.h", 1);
	setenv("KCONFIG_TRISTATE",
	       "c_test_extend_err_template_path/tristate.config", 1);
	setenv("KCONFIG_EXTEND_NAME", "EXTENDTEST", 1);
	setenv("KCONFIG_EXTEND_TEMPLATE", "std_template", 1);
	setenv("KCONFIG_EXTEND_AUTOCONFIG",
	       "c_test_extend_err_template_path/.extend.config", 1);
	setenv("KCONFIG_EXTEND_AUTOHEADER",
	       "c_test_extend_err_template_path/autoconf.h", 1);

	/* 2 调用conf_write_autoconf，执行用例 */
	ret = conf_write_autoconf(0);
	fclose(stderr);
	freopen("/dev/tty", "w", stderr);
	if (ret == 0) {
		/* 执行正确不符合预期 */
		ERR_PRINT();
		goto err_reset_env;
	}

	/* 3 判断输出文件是否符合预期 */
	/* 3.1 读取错误日志 */
	expeced_err_fp = fopen(
		"kconfig/def_test_files/expected_err_info_err_template_path",
		"r");
	if (expeced_err_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	src_err_fp = fopen("c_test_extend_err_template_path/err.log", "r");
	if (src_err_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_err_file;
	}

	/* 3.2 检测err输出是否包含预期错误 */
	ret = is_file_contains(src_err_fp, expeced_err_fp);
	if (ret == 1) {
		ERR_PRINT();
		goto err_reset_all;
	} else if (ret == -1) {
		/* err文本大于512bytes限制单独报错 */
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(src_err_fp);
	fclose(expeced_err_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_err_template_path");

	printf("------c_test_extend_err_template_path->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_err_fp);
err_handle_src_err_file:
	fclose(expeced_err_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_err_template_path");

	printf("------c_test_extend_err_template_path->fail!!\n");
	return 1;
}

/* 测试用例c_test_extend_def_conf_path */
static int test_case_extend_def_conf_path(void)
{
	FILE *expeced_config_fp, *expeced_header_fp;
	FILE *src_config_fp, *src_header_fp;
	int ret = 1;

	printf("test :c_test_extend_def_conf_path->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_def_conf_path", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		return 1;
	}
	ret = 1;
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "y", 1);
	setenv("KCONFIG_AUTOCONFIG",
	       "c_test_extend_def_conf_path/auto.conf", 1);
	setenv("KCONFIG_AUTOHEADER",
	       "c_test_extend_def_conf_path/_config.h", 1);
	setenv("KCONFIG_TRISTATE",
	       "c_test_extend_def_conf_path/tristate.config", 1);
	setenv("KCONFIG_EXTEND_NAME", "EXTENDTEST", 1);
	setenv("KCONFIG_EXTEND_TEMPLATE", "kconfig/def_test_files/std_template",
	       1);

	/* 2 调用conf_write_autoconf，执行用例 */
	ret = conf_write_autoconf(0);
	if (ret != 0) {
		/* 执行出错，打印错误位置，恢复环境 */
		ERR_PRINT();
		goto err_reset_env;
	}
	ret = 1;

	/* 3 判断输出文件是否符合预期 */
	/* 3.1 读取头文件与配置文件 */
	expeced_config_fp = fopen(
		"kconfig/def_test_files/expected_extend_config_def_conf_path",
		"r");
	if (expeced_config_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	expeced_header_fp = fopen(
		"kconfig/def_test_files/expected_extend_header_def_conf_path",
		"r");
	if (expeced_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_expeced_header_file;
	}

	src_config_fp = fopen("include/config/.extend.config", "r");
	if (src_config_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_config_file;
	}

	src_header_fp = fopen("include/config/extend_autoconf.h", "r");
	if (src_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_header_file;
	}

	/* 3.2 将生成的配置文件与预期结果作比较 */
	ret = compare_file(expeced_config_fp, src_config_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	ret = 1;

	ret = compare_file(expeced_header_fp, src_header_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(expeced_config_fp);
	fclose(src_config_fp);
	fclose(expeced_header_fp);
	fclose(src_header_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	remove_dir("c_test_extend_def_conf_path");

	printf("------c_test_extend_def_conf_path->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_header_fp);
err_handle_src_header_file:
	fclose(src_config_fp);
err_handle_src_config_file:
	fclose(expeced_header_fp);
err_handle_expeced_header_file:
	fclose(expeced_config_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	remove_dir("c_test_extend_def_conf_path");

	printf("------c_test_extend_def_conf_path->fail!!\n");
	return 1;
}

/* 测试用例c_test_extend_no_name */
static int test_case_extend_no_name(void)
{
	FILE *expeced_err_fp, *src_err_fp;
	int ret = 0;

	printf("test :c_test_extend_no_name->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_no_name", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		/* 恢复stderr重定向 */
		fclose(stderr);
		freopen("/dev/tty", "w", stderr);
		return 1;
	}
	/* 将stderr重定向至文件中 */
	if (freopen("c_test_extend_no_name/err.log", "w", stderr) == NULL) {
		ERR_PRINT();
		return 1;
	}
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "y", 1);

	/* 2 调用conf_write_autoconf，执行用例 */
	ret = conf_write_autoconf(0);
	fclose(stderr);
	freopen("/dev/tty", "w", stderr);
	if (ret == 0) {
		/* 执行正确不符合预期 */
		ERR_PRINT();
		goto err_reset_env;
	}

	/* 3 判断输出文件是否符合预期 */
	/* 3.1 读取错误日志 */
	expeced_err_fp = fopen(
			"kconfig/def_test_files/expected_err_info_no_name",
			"r");
	if (expeced_err_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	src_err_fp = fopen("c_test_extend_no_name/err.log", "r");
	if (src_err_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_err_file;
	}

	/* 3.2 检测err输出是否包含预期错误 */
	ret = is_file_contains(src_err_fp, expeced_err_fp);
	if (ret == 1) {
		ERR_PRINT();
		goto err_reset_all;
	} else if (ret == -1) {
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(src_err_fp);
	fclose(expeced_err_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	remove_dir("c_test_extend_no_name");

	printf("------c_test_extend_no_name->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_err_fp);
err_handle_src_err_file:
	fclose(expeced_err_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	remove_dir("c_test_extend_no_name");

	printf("------c_test_extend_no_name->fail!!\n");
	return 1;
}

/* 测试用例c_test_extend_err_format */
static int test_case_extend_err_format(void)
{
	FILE *expeced_err_fp, *src_err_fp;
	int ret = 1;

	printf("test :c_test_extend_err_format->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_err_format", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		/* 恢复stderr重定向 */
		fclose(stderr);
		freopen("/dev/tty", "w", stderr);
		return 1;
	}
	/* 将stderr重定向至文件中 */
	if (freopen("c_test_extend_err_format/miss_start_identifier_err.log",
		    "w", stderr) == NULL) {
		ERR_PRINT();
		return 1;
	}
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "y", 1);
	setenv("KCONFIG_AUTOCONFIG", "c_test_extend_err_format/auto.conf", 1);
	setenv("KCONFIG_AUTOHEADER", "c_test_extend_err_format/_config.h", 1);
	setenv("KCONFIG_TRISTATE",
	       "c_test_extend_err_format/tristate.config", 1);
	setenv("KCONFIG_EXTEND_NAME", "EXTENDTEST", 1);
	setenv("KCONFIG_EXTEND_TEMPLATE",
	       "kconfig/def_test_files/src_template_miss_start_identifier", 1);
	setenv("KCONFIG_EXTEND_AUTOCONFIG",
	       "c_test_extend_err_format/.extend.config", 1);
	setenv("KCONFIG_EXTEND_AUTOHEADER",
	       "c_test_extend_err_format/autoconf.h", 1);

	/* 2 调用conf_write_autoconf，执行用例 */
	/* 2.1 模板数据格式缺失头标识符 */
	ret = conf_write_autoconf(0);
	if (ret == 0) {
		/* 执行正确不符合预期 */
		fclose(stderr);
		freopen("/dev/tty", "w", stderr);
		ERR_PRINT();
		goto err_reset_env;
	}

	/* 2.2 模板数据格式缺失尾标识符 */
	setenv("KCONFIG_EXTEND_TEMPLATE",
	       "kconfig/def_test_files/src_template_miss_end_identifier", 1);
	if (freopen("c_test_extend_err_format/miss_end_identifier_err.log", "w",
		    stderr) == NULL) {
		ERR_PRINT();
		return 1;
	}
	ret = conf_write_autoconf(0);
	if (ret == 0) {
		/* 执行正确不符合预期 */
		fclose(stderr);
		freopen("/dev/tty", "w", stderr);
		ERR_PRINT();
		goto err_reset_env;
	}

	/* 2.3 模板数据同一组标识符重复出现 */
	setenv("KCONFIG_EXTEND_TEMPLATE",
	       "kconfig/def_test_files/src_template_mutidefined_identifier", 1);
	if (freopen("c_test_extend_err_format/mutidefined_identifier_err.log",
		    "w", stderr) == NULL) {
		ERR_PRINT();
		return 1;
	}
	ret = conf_write_autoconf(0);
	if (ret == 0) {
		/* 执行正确不符合预期 */
		fclose(stderr);
		freopen("/dev/tty", "w", stderr);
		ERR_PRINT();
		goto err_reset_env;
	}

	/* 2.4 模板有效数据大小超过512bytes */
	setenv("KCONFIG_EXTEND_TEMPLATE",
	       "kconfig/def_test_files/src_template_file_oversize", 1);
	if (freopen("c_test_extend_err_format/file_oversize_err.log",
		    "w", stderr) == NULL) {
		ERR_PRINT();
		return 1;
	}
	ret = conf_write_autoconf(0);
	if (ret == 0) {
		/* 执行正确不符合预期 */
		fclose(stderr);
		freopen("/dev/tty", "w", stderr);
		ERR_PRINT();
		goto err_reset_env;
	}
	fclose(stderr);
	freopen("/dev/tty", "w", stderr);

	/* 3 判断输出文件是否符合预期 */
	/* 读取错误日志并比较 */
	/* 3.1 模板数据格式缺失头标识符 */
	expeced_err_fp = fopen(
		"kconfig/def_test_files/expected_err_info_err_format",
		"r");
	if (expeced_err_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	src_err_fp = fopen(
		"c_test_extend_err_format/miss_start_identifier_err.log",
		"r");
	if (src_err_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_err_file;
	}

	ret = is_file_contains(src_err_fp, expeced_err_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}

	fclose(src_err_fp);
	fclose(expeced_err_fp);

	/* 3.2 模板数据格式缺失尾标识符 */
	expeced_err_fp = fopen(
		"kconfig/def_test_files/expected_err_info_err_format",
		"r");
	if (expeced_err_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	src_err_fp = fopen(
		"c_test_extend_err_format/miss_end_identifier_err.log",
		"r");
	if (src_err_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_err_file;
	}

	ret = is_file_contains(src_err_fp, expeced_err_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}

	fclose(src_err_fp);
	fclose(expeced_err_fp);

	/* 3.3 模板数据同一组标识符重复出现 */
	expeced_err_fp = fopen(
		"kconfig/def_test_files/expected_err_info_err_format",
		"r");
	if (expeced_err_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	src_err_fp = fopen(
		"c_test_extend_err_format/mutidefined_identifier_err.log",
		"r");
	if (src_err_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_err_file;
	}

	ret = is_file_contains(src_err_fp, expeced_err_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}

	fclose(src_err_fp);
	fclose(expeced_err_fp);

	/* 3.4 模板有效数据大小超过512bytes */
	expeced_err_fp = fopen(
			"kconfig/def_test_files/expected_err_info_err_format",
			"r");
	if (expeced_err_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	src_err_fp = fopen("c_test_extend_err_format/file_oversize_err.log",
			   "r");
	if (src_err_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_err_file;
	}

	ret = is_file_contains(src_err_fp, expeced_err_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(src_err_fp);
	fclose(expeced_err_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_err_format");

	printf("------c_test_extend_err_format->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_err_fp);
err_handle_src_err_file:
	fclose(expeced_err_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_err_format");

	printf("------c_test_extend_err_format->fail!!\n");
	return 1;
}

/* 测试用例c_test_extend_incomplete_format */
static int test_case_extend_incomplete_format(void)
{
	FILE *expeced_config_fp, *expeced_header_fp;
	FILE *src_config_fp, *src_header_fp;
	int ret = 1;

	printf("test :c_test_extend_incomplete_format->begin!\n");
	/* 1 用例依赖环境初始化 */
	ret = mkdir("c_test_extend_incomplete_format", FOLDER_PERMMISION);
	if (ret != 0) {
		ERR_PRINT();
		return 1;
	}
	ret = 1;
	setenv("KCONFIG_EXTEND_CONFIG_ENABLE", "y", 1);
	setenv("KCONFIG_AUTOCONFIG",
	       "c_test_extend_incomplete_format/auto.conf", 1);
	setenv("KCONFIG_AUTOHEADER",
	       "c_test_extend_incomplete_format/_config.h", 1);
	setenv("KCONFIG_TRISTATE",
	       "c_test_extend_incomplete_format/tristate.config", 1);
	setenv("KCONFIG_EXTEND_NAME", "EXTENDTEST", 1);
	setenv("KCONFIG_EXTEND_TEMPLATE",
	       "kconfig/def_test_files/src_template_incomplete_format", 1);
	setenv("KCONFIG_EXTEND_AUTOCONFIG",
	       "c_test_extend_incomplete_format/.extend.config", 1);
	setenv("KCONFIG_EXTEND_AUTOHEADER",
	       "c_test_extend_incomplete_format/autoconf.h", 1);

	/* 2 调用conf_write_autoconf，执行用例 */
	ret = conf_write_autoconf(0);
	if (ret != 0) {
		/* 执行出错，打印错误位置，恢复环境 */
		ERR_PRINT();
		goto err_reset_env;
	}
	ret = 1;

	/* 3 判断输出文件是否符合预期 */
	/* 3.1 读取头文件与配置文件 */
	expeced_config_fp =
		fopen(
		"kconfig/def_test_files/expected_extend_config_incomplete_format",
		"r");
	if (expeced_config_fp == NULL) {
		ERR_PRINT();
		goto err_reset_env;
	}

	expeced_header_fp =
		fopen(
		"kconfig/def_test_files/expected_extend_header_incomplete_format",
		"r");
	if (expeced_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_expeced_header_file;
	}

	src_config_fp = fopen("c_test_extend_incomplete_format/.extend.config",
			      "r");
	if (src_config_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_config_file;
	}

	src_header_fp = fopen("c_test_extend_incomplete_format/autoconf.h",
			      "r");
	if (src_header_fp == NULL) {
		ERR_PRINT();
		goto err_handle_src_header_file;
	}

	/* 3.2 将生成的配置文件与预期结果作比较 */
	ret = compare_file(expeced_config_fp, src_config_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	ret = 1;

	ret = compare_file(expeced_header_fp, src_header_fp);
	if (ret != 0) {
		ERR_PRINT();
		goto err_reset_all;
	}
	fclose(expeced_config_fp);
	fclose(expeced_header_fp);
	fclose(src_config_fp);
	fclose(src_header_fp);

	/* 4 用例执行完成，恢复环境 */
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_incomplete_format");

	printf("------c_test_extend_incomplete_format->success!\n");
	return 0;

	/* 5 错误处理入口 */
err_reset_all:
	fclose(src_header_fp);
err_handle_src_header_file:
	fclose(src_config_fp);
err_handle_src_config_file:
	fclose(expeced_header_fp);
err_handle_expeced_header_file:
	fclose(expeced_config_fp);
err_reset_env:
	unsetenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	unsetenv("KCONFIG_AUTOCONFIG");
	unsetenv("KCONFIG_AUTOHEADER");
	unsetenv("KCONFIG_TRISTATE");
	unsetenv("KCONFIG_EXTEND_NAME");
	unsetenv("KCONFIG_EXTEND_TEMPLATE");
	unsetenv("KCONFIG_EXTEND_AUTOCONFIG");
	unsetenv("KCONFIG_EXTEND_AUTOHEADER");
	remove_dir("c_test_extend_incomplete_format");

	printf("------c_test_extend_incomplete_format->fail!!\n");
	return 1;
}

/* c白盒测试主函数 */
int main(void)
{
	/* 测试函数数组 */
	test_func test_case_table[] = {test_case_extend_not_set,
				       test_case_extend_set,
				       test_case_extend_no_template_path,
				       test_case_extend_err_template_path,
				       test_case_extend_def_conf_path,
				       test_case_extend_no_name,
				       test_case_extend_err_format,
				       test_case_extend_incomplete_format};
	int test_case_num = sizeof(test_case_table) / sizeof(test_func);
	int test_case_suc_num = 0;
	int test_case_fail_num = 0;

	printf("\n---C test begin---\n");
	/* 初始化测试场景 */
	test_case_init();

	/* 轮询调用每个测试函数 */
	for (int i = 0; i < test_case_num; i++) {
		if (test_case_table[i]() != 0)
			test_case_fail_num++;
		else
			test_case_suc_num++;
	}
	printf("-success test cases:%d\n-fail test cases:%d\n",
	       test_case_suc_num, test_case_fail_num);
	printf("---C test end---\n");

	/* 恢复环境 */
	remove("../.config");

	if (test_case_fail_num != 0)
		return 1;
	else
		return 0;
}
