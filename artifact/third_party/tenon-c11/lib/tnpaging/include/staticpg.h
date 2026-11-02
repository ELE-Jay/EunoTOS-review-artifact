/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#ifndef __TN_STATICPG_H__
#define __TN_STATICPG_H__

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <uk/arch/lcpu.h>
#include <uk/arch/paging.h>
#include <uk/bits/config.h>
#include <uk/plat/memory.h>

#define PGTABLE_INFO_SECTION ".tn_static_memregion"
#define PGTABLE_SECTION ".tn_static_pt"
#define PGTABLE_INFO_DIRECT_SECTION ".tn_direct_memregion"
#define BLOCK_SIZE 4096
#define PTE_PER_LEVEL 512

#define PMD_SHIFT 21
#define PUD_SHIFT 30
#define PGD_SHIFT 39

#define PMD_SIZE (1UL << PMD_SHIFT)
#define PUD_SIZE (1UL << PUD_SHIFT)

typedef struct page_table {
	struct {
		/* Used to identify page table entries.
		 * If True, data it points to the next level page table;
		 * if False, data points to a physical block.
		 */
		bool pte_table;
		/* Used to store page table entries. */
		uint64_t data;
	} entries[PTE_PER_LEVEL];
} page_table;

static void print_memregion(struct ukplat_memregion_desc *mrd)
{
	printf(" %012lx-%012lx %012lx-%012lx %c%c%c %016lx %s\n", mrd->pbase,
		   mrd->pbase + mrd->pg_count * PAGE_SIZE, mrd->pbase + mrd->pg_off,
		   mrd->pbase + mrd->pg_off + mrd->len,
		   (mrd->flags & UKPLAT_MEMRF_READ) ? 'r' : '-',
		   (mrd->flags & UKPLAT_MEMRF_WRITE) ? 'w' : '-',
		   (mrd->flags & UKPLAT_MEMRF_EXECUTE) ? 'x' : '-', mrd->vbase,
#if CONFIG_UKPLAT_MEMRNAME
		   mrd->name
#else  /* !CONFIG_UKPLAT_MEMRNAME */
		   ""
#endif /* !CONFIG_UKPLAT_MEMRNAME */
	);
}

#define ASSERT_VALID_MRD_TYPE(mrd)                          \
	do {                                                      \
		switch ((mrd)->type) {                                \
		case UKPLAT_MEMRT_FREE:                               \
			__fallthrough;                                    \
		case UKPLAT_MEMRT_RESERVED:                           \
			__fallthrough;                                    \
		case UKPLAT_MEMRT_KERNEL:                             \
			__fallthrough;                                    \
		case UKPLAT_MEMRT_INITRD:                             \
			__fallthrough;                                    \
		case UKPLAT_MEMRT_CMDLINE:                            \
			__fallthrough;                                    \
		case UKPLAT_MEMRT_DEVICETREE:                         \
			__fallthrough;                                    \
		case UKPLAT_MEMRT_STACK:                              \
			break;                                            \
		default:                                            \
			printf("Invalid mrd type: %hu\n",               \
			       (mrd)->type);                            \
			exit(EXIT_FAILURE);                             \
		}                                                   \
	} while (0)

#if defined(CONFIG_ARCH_ARM_64)
#define ASSERT_VALID_MRD_FLAGS(mrd)                            \
	do {                                                       \
		assert(UKPLAT_MRMRF_MAP_IS_VALID((mrd)->flags));       \
		assert(UKPLAT_MEMRF_EXECUTE_IS_VALID((mrd)->flags));   \
		assert(UKPLAT_MEMRF_MAIR_IS_VALID((mrd)->flags));      \
		assert(UKPLAT_MEMRF_SHAREABLE_IS_VALID((mrd)->flags)); \
		assert(UKPLAT_MEMRF_LEVEL_IS_VALID((mrd)->flags));     \
	} while (0)
#else
#define ASSERT_VALID_MRD_FLAGS(mrd)                       \
	do {                                                  \
		assert(UKPLAT_MEMRF_PERM_IS_VALID((mrd)->flags)); \
		assert(UKPLAT_MEMRF_MAP_IS_VALID((mrd)->flags));  \
	} while (0)
#endif

#define ASSERT_VALID_MRD(mrd)                                           \
	do {                                                                \
		ASSERT_VALID_MRD_TYPE((mrd));                                   \
		ASSERT_VALID_MRD_FLAGS((mrd));                                  \
		assert(PAGE_ALIGNED((mrd)->vbase));                             \
		assert(PAGE_ALIGNED((mrd)->pbase));                             \
		assert((mrd)->pg_off >= 0 && (mrd)->pg_off < (__off)PAGE_SIZE); \
	} while (0)

#endif /* __TN_STATICPG_H__ */
