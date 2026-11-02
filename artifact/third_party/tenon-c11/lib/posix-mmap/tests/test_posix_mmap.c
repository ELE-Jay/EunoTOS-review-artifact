/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#include <uk/print.h>
#include <uk/test.h>
#include <uk/list.h>
#include <uk/arch/paging.h>
#include <uk/vmem.h>
#include <uk/nofault.h>

#define pm_bug_on(cond)							\
	do {								\
		if (unlikely(cond))					\
			UK_CRASH("'%s' during test execution.\n",	\
				 STRINGIFY(cond));			\
	} while (0)

struct vma_entry {
	__vaddr_t start;
	__vaddr_t end;
	unsigned long attr;
};

static void vmem_print(struct uk_vas *vas)
{
	struct uk_vma *vma;
	int i = 0;

	uk_pr_info("   VAS layout:\n");
	uk_list_for_each_entry(vma, &vas->vma_list, vma_list) {
		if (vma->name && strcmp("heap", vma->name) == 0)
			continue;
		if (vma->name && strcmp("auxiliary_stack", vma->name) == 0)
			continue;

		uk_pr_info("     [%d] 0x%lx-0x%lx %c%c%c %s\n", i++, vma->start,
			   vma->end,
			   (vma->attr & PAGE_ATTR_PROT_READ) ? 'r' : '-',
			   (vma->attr & PAGE_ATTR_PROT_WRITE) ? 'w' : '-',
			   (vma->attr & PAGE_ATTR_PROT_EXEC) ? 'x' : '-',
			   (vma->name) ? vma->name : "");
	}
}

static int chk_vas(struct uk_vas *vas, struct vma_entry *vmas, int num)
{
	struct uk_vma *vma;
	int i = 0;

	vmem_print(vas);

	uk_list_for_each_entry(vma, &vas->vma_list, vma_list) {
		if (vma->name && strcmp("heap", vma->name) == 0)
			continue;
		if (vma->name && strcmp("auxiliary_stack", vma->name) == 0)
			continue;

		if (i >= num)
			return -1;

		if (vma->start != vmas[i].start ||
		    vma->end   != vmas[i].end ||
		    vma->attr  != vmas[i].attr ||
		    vma->vas   != vas)
			return -1;

		i++;
	}

	return (i == num) ? 0 : -1;
}

static struct uk_vas *vas_init(void)
{
	struct uk_vas *vas = uk_vas_get_active();

	pm_bug_on(vas == __NULL);
	return vas;
}

static void vas_clean(struct uk_vas *vas)
{
	struct uk_vma *vma;
	int restart, rc;

	do {
		restart = 0;
		uk_list_for_each_entry(vma, &vas->vma_list, vma_list) {
			if (vma->name && strcmp("heap", vma->name) == 0)
				continue;
			if (vma->name &&
				strcmp("auxiliary_stack", vma->name) == 0)
				continue;

			rc = uk_vma_unmap(vas, vma->start,
					  vma->end - vma->start, 0);
			pm_bug_on(rc != 0);

			restart = 1;
			break;
		}
	} while (restart);
}


static inline __sz probe_r(__vaddr_t vaddr, __sz len)
{
	return uk_nofault_probe_r(vaddr, len, UK_NOFAULTF_CONTINUE);
}

static inline __sz probe_rw(__vaddr_t vaddr, __sz len)
{
	return uk_nofault_probe_rw(vaddr, len, UK_NOFAULTF_CONTINUE);
}

static inline __sz probe_r_nopage(__vaddr_t vaddr, __sz len)
{
	unsigned long flags = UK_NOFAULTF_CONTINUE | UK_NOFAULTF_NOPAGING;

	return uk_nofault_probe_r(vaddr, len, flags);
}

static inline __sz probe_rw_nopage(__vaddr_t vaddr, __sz len)
{
	unsigned long flags = UK_NOFAULTF_CONTINUE | UK_NOFAULTF_NOPAGING;

	return uk_nofault_probe_rw(vaddr, len, flags);
}

UK_TESTCASE(posix_mmap, test_mmap)
{
	struct uk_vas *vas = vas_init();
	void *addr;
	int rc;

	addr = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	UK_TEST_EXPECT(addr != MAP_FAILED);

	rc = munmap(addr, 2 * PAGE_SIZE);
	UK_TEST_EXPECT_ZERO(rc);

	vas_clean(vas);
}

#ifdef CONFIG_LIBVFSCORE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

UK_TESTCASE(posix_mmap, test_munmap)
{
	struct uk_vas *vas = vas_init();
	void *addr1, *addr2;
	int fd, rc;

	fd = creat("/test_munmap", 0700);

	addr1 = mmap(NULL, 2 * PAGE_SIZE, PROT_READ,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	UK_TEST_EXPECT(addr1 != MAP_FAILED);

	addr2 = mmap(addr1 + 2 * PAGE_SIZE, 2 * PAGE_SIZE, PROT_READ,
		     MAP_PRIVATE, fd, 0);
	UK_TEST_EXPECT(addr2 != MAP_FAILED);

	rc = munmap(addr1 + PAGE_SIZE, 2 * PAGE_SIZE);
	UK_TEST_EXPECT_ZERO(rc);

	UK_TEST_EXPECT_ZERO(chk_vas(vas, (struct vma_entry[]){
		{(__vaddr_t)addr1, (__vaddr_t)addr1 + PAGE_SIZE, PROT_READ},
		{(__vaddr_t)addr2 + PAGE_SIZE, (__vaddr_t)addr2 + 2 * PAGE_SIZE,
		PROT_READ},
	}, 2));

	/* Clean up */
	close(fd);
	unlink("/test_munmap");

	vas_clean(vas);
}

UK_TESTCASE(posix_mmap, test_mprotect)
{
	struct uk_vas *vas = vas_init();
	void *addr1, *addr2;
	int fd, rc;

	fd = creat("/test_mprotect", 0700);

	addr1 = mmap(NULL, 2 * PAGE_SIZE, PROT_READ,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	UK_TEST_EXPECT(addr1 != MAP_FAILED);

	addr2 = mmap(addr1 + 2 * PAGE_SIZE, 2 * PAGE_SIZE, PROT_READ,
		    MAP_PRIVATE, fd, 0);
	UK_TEST_EXPECT(addr2 != MAP_FAILED);

	UK_TEST_EXPECT_ZERO(chk_vas(vas, (struct vma_entry[]){
		{(__vaddr_t)addr1, (__vaddr_t)addr1 + 2 * PAGE_SIZE, PROT_READ},
		{(__vaddr_t)addr2, (__vaddr_t)addr2 + 2 * PAGE_SIZE, PROT_READ},
	}, 2));

	rc = mprotect(addr1 + PAGE_SIZE, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE);
	UK_TEST_EXPECT_ZERO(rc);

	UK_TEST_EXPECT_ZERO(chk_vas(vas, (struct vma_entry[]){
		{(__vaddr_t)addr1, (__vaddr_t)addr1 + PAGE_SIZE, PROT_READ},
		{(__vaddr_t)addr1 + PAGE_SIZE, (__vaddr_t)addr1 + 2 * PAGE_SIZE,
		PROT_READ | PROT_WRITE},
		{(__vaddr_t)addr2, (__vaddr_t)addr2 + PAGE_SIZE,
		PROT_READ | PROT_WRITE},
		{(__vaddr_t)addr2 + PAGE_SIZE, (__vaddr_t)addr2 + 2 * PAGE_SIZE,
		PROT_READ},
	}, 4));

	/* Clean up */
	close(fd);
	unlink("/test_mprotect");

	vas_clean(vas);
}



UK_TESTCASE(posix_mmap, test_mix_mmap)
{
	struct uk_vas *vas = vas_init();
	void *addr1, *addr2;
	int fd, rc, len2;

	fd = creat("/test_vma_file_munmap", 0700);

	addr1 = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	UK_TEST_EXPECT(addr1 != MAP_FAILED);
	len2 = probe_r_nopage((unsigned long)addr1, 2 * PAGE_SIZE);
	UK_TEST_EXPECT_SNUM_EQ(len2, 0);

	addr2 = mmap(addr1 + 2 * PAGE_SIZE, 2 * PAGE_SIZE,
			PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	UK_TEST_EXPECT(addr2 != MAP_FAILED);

	UK_TEST_EXPECT_ZERO(chk_vas(
	    vas,
	    (struct vma_entry[]){
		{ (unsigned long)addr1, (unsigned long)addr1 + 2 * PAGE_SIZE,
		  PROT_READ | PROT_WRITE },
		{ (unsigned long)addr2, (unsigned long)addr2 + 2 * PAGE_SIZE,
		  PROT_READ | PROT_WRITE },
	    },
	    2));

	// todo:unikraft has not impletement UK_VMA_ADV_WILLNEED yet
	// should be modified when unikraft finish it
	rc = madvise(addr1, PAGE_SIZE, UK_VMA_ADV_WILLNEED);
	UK_TEST_EXPECT_ZERO(rc);
	UK_TEST_EXPECT_ZERO(chk_vas(
	    vas,
	    (struct vma_entry[]){
		{ (unsigned long)addr1, (unsigned long)addr1 + 2 * PAGE_SIZE,
		  PROT_READ | PROT_WRITE },
		{ (unsigned long)addr2, (unsigned long)addr2 + 2 * PAGE_SIZE,
		  PROT_READ | PROT_WRITE },
	    },
	    2));
	len2 = probe_rw_nopage((unsigned long)addr1, 2 * PAGE_SIZE);
	UK_TEST_EXPECT_SNUM_EQ(len2, 0);

	rc = madvise(addr1, 3 * PAGE_SIZE, MADV_DONTNEED);
	UK_TEST_EXPECT_ZERO(rc);
	UK_TEST_EXPECT_ZERO(chk_vas(
	    vas,
	    (struct vma_entry[]){
		{ (unsigned long)addr1, (unsigned long)addr1 + 2 * PAGE_SIZE,
		  PROT_READ | PROT_WRITE },
		{ (unsigned long)addr2, (unsigned long)addr2 + 2 * PAGE_SIZE,
		  PROT_READ | PROT_WRITE },
	    },
	    2));
	len2 = probe_rw_nopage((unsigned long)addr1, PAGE_SIZE);
	UK_TEST_EXPECT_SNUM_EQ(len2, 0);
	len2 = probe_rw_nopage((unsigned long)addr1 + PAGE_SIZE, PAGE_SIZE);
	UK_TEST_EXPECT_SNUM_EQ(len2, 0);
	len2 = probe_rw_nopage((unsigned long)addr1 + PAGE_SIZE * 2, PAGE_SIZE);
	UK_TEST_EXPECT_SNUM_EQ(len2, 0);
	vas_clean(vas);

	/* Clean up */
	close(fd);
	unlink("/test_vma_file_munmap");

	vas_clean(vas);
}
# endif

uk_testsuite_register(posix_mmap, NULL, NULL);
