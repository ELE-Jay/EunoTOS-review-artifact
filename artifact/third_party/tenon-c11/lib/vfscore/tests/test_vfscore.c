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

#include <vfscore/dentry.h>
#include <vfscore/eventpoll.h>
#include <vfscore/file.h>
#include <vfscore/fs.h>
#include <vfscore/mount.h>
#include <vfscore/prex.h>
#include <vfscore/uio.h>
#include <vfscore/vnode.h>
#include <uk/syscall.h>
#include <uk/test.h>

/* 测试mkdir的路径中包含"/"，即递归创建 */
UK_TESTCASE(vfscore, test_vfscore_mkdir_recursion)
{
	int rc;
	struct stat st;

	/* 1.创建test/文件夹 */
	rc = uk_syscall_r_mkdirat((long)AT_FDCWD, (long)"test/",
				  (long)((mode_t)0777));
	UK_TEST_EXPECT_ZERO(rc);

	/* 2.创建test1/test2文件夹,预期创建失败 */
	rc = uk_syscall_r_mkdirat((long)AT_FDCWD, (long)"test1/test2",
				  (long)((mode_t)0777));
	UK_TEST_EXPECT_NOT_ZERO(rc);

	/* 3.读取test文件夹，判断是否存在 */
	rc = uk_syscall_r_newfstatat((long)AT_FDCWD, (long)"test", (long)(&st),
				     0);
	UK_TEST_EXPECT_ZERO(rc);

	/* 4.删除test文件夹 */
	rc = rmdir("test");
	UK_TEST_EXPECT_ZERO(rc);

	/* 5.删除test文件夹，判断是否删除成功 */
	rc = uk_syscall_r_newfstatat((long)AT_FDCWD, (long)"test", (long)(&st),
				     0);
	UK_TEST_EXPECT_NOT_ZERO(rc);
}

/* 测试能否赋予权限 */
UK_TESTCASE(vfscore, test_vfscore_fchmodat)
{
	int rc;
	struct stat st;
	int dirfd;

	/* 1.创建test文件夹 */
	rc = uk_syscall_r_mkdirat((long)AT_FDCWD, (long)"test",
				  (long)((mode_t)0777));
	UK_TEST_EXPECT_ZERO(rc);

	/* 2.更改test文件夹权限为421，分别为rwx权限 */
	rc = uk_syscall_r_fchmodat((long)AT_FDCWD, (long)"test",
				   (long)((mode_t)0421), 0);
	UK_TEST_EXPECT_ZERO(rc);

	/* 3.查看test文件夹权限是否为写入的权限 */
	rc = uk_syscall_r_newfstatat((long)AT_FDCWD, (long)"test", (long)(&st),
				     0);
	UK_TEST_EXPECT_SNUM_EQ(st.st_mode & 0777, 0421);

	/* 4.在test文件夹下创建test1文件夹 */
	rc = uk_syscall_r_mkdirat((long)AT_FDCWD, (long)"test/test1",
				  (long)((mode_t)0777));
	UK_TEST_EXPECT_ZERO(rc);

	/* 5.读取test文件夹的文件描述符 */
	dirfd = uk_syscall_r_openat((long)AT_FDCWD, (long)"test",
				    (long)O_RDONLY, 0);

	/* 6.采用test的文件描述符作传参给test1文件夹写权限 */
	rc = uk_syscall_r_fchmodat((long)dirfd, (long)"test1",
				   (long)((mode_t)0345), 0);
	UK_TEST_EXPECT_ZERO(rc);

	/* 7.查看test1文件夹权限是否为写入的权限 */
	rc =
	    uk_syscall_r_newfstatat((long)dirfd, (long)"test1", (long)(&st), 0);
	UK_TEST_EXPECT_SNUM_EQ(st.st_mode & 0777, 0345);

	/* 8.删除test和test1文件夹 */
	rc = rmdir("test/test1");
	rc = rmdir("test");
	UK_TEST_EXPECT_ZERO(rc);

	/* 9.删除test文件夹，判断是否删除成功 */
	rc = uk_syscall_r_newfstatat(AT_FDCWD, (long)"test", (long)(&st), 0);
	UK_TEST_EXPECT_NOT_ZERO(rc);
}

uk_testsuite_rootfs_prio(vfscore, NULL, NULL, UK_PRIO_LATEST);
