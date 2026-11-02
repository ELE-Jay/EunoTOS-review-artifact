/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * Copyright (c) 2017, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __UKPLAT_MEMORY_H__
#define __UKPLAT_MEMORY_H__

#include <stddef.h>

#include <uk/alloc.h>
#include <uk/arch/ctx.h>
#include <uk/arch/paging.h>
#include <uk/arch/types.h>
#include <uk/config.h>
#include <uk/essentials.h>
#if CONFIG_LIBUKVMEM
#include <uk/vmem.h>
#endif /* CONFIG_LIBUKVMEM */

#ifdef __cplusplus
extern "C" {
#endif

/* Memory region flags:
 *  bit[15-0]
 *        ---------------------------------------------------------------------
 * flags: |  LEVEL  |  ACCESS | SHAREABLE |  MAIR  |  MAP  | U_PERMS | PERMS  |
 * bit:   | [15:14] | [13:11] |   [10:9]  | [8:6]  | [5:4] |   [3]   |  [2:0] |
 *        ---------------------------------------------------------------------
 *
 * LEVEL:     Indicates the granularity level of mapping (e.g., PAGE, PMD, PUD)
 * ACCESS:    Additional access attributes such as AF, nG, or CONTIGUOUS.
 * SHAREABLE: Shareability attributes (e.g., Inner-Shareable).
 * MAIR:      Memory type index for MAIR.
 * MAP:       Mapping attributes, e.g., UNMAP at boot.
 * U_PERMS:   User permissions.
 * PERMS:     Memory region access permissions (e.g., READ, WRITE, EXECUTE).
 */

/* Memory region types */
#define UKPLAT_MEMRT_ANY		0xffff

#define UKPLAT_MEMRT_FREE		0x0001	/* Uninitialized memory */
#define UKPLAT_MEMRT_RESERVED 0x0002	/* In use by platform */
#define UKPLAT_MEMRT_KERNEL		0x0004	/* Kernel binary segment */
#define UKPLAT_MEMRT_INITRD		0x0008	/* Initramdisk */
#define UKPLAT_MEMRT_CMDLINE 0x0010		/* Command line */
#define UKPLAT_MEMRT_DEVICETREE 0x0020	/* Device tree */
#define UKPLAT_MEMRT_STACK		0x0040	/* Thread stack */

/* Memory region flags */
#define UKPLAT_MEMRF_ALL		0xffff

#define UKPLAT_MEMRF_PERMS		0x0007
#define UKPLAT_MEMRF_READ		0x0001	/* Region is readable */
#define UKPLAT_MEMRF_WRITE		0x0002	/* Region is writable */

/* Represents (PTE_ATTR_PXN | PTE_ATTR_UXN) when creating a page table.
 * Kept for compatibility.
 *
 * TODO: Update to use separate flag definitions for PXN and UXN.
 */
#define UKPLAT_MEMRF_EXECUTE		0x0004	/* Region is executable */

#define UKPLAT_MEMRF_EXTRACT_PERM(x) ((x) & UKPLAT_MEMRF_PERMS)

/* 0 or 1 of any bit is valid */
#define UKPLAT_MEMRF_PERM_IS_VALID(x) 1

#define UKPLAT_MEMRF_MAP_MASK 0x0030
#define UKPLAT_MEMRF_MAP_SHIFT 4
#define UKPLAT_MEMRF_UNMAP		0x0010	/* Must be unmapped at boot */
#define UKPLAT_MEMRF_MAP		0x0020	/* Must be mapped at boot */

#define UKPLAT_MEMRF_EXTRACT_MAP(x) ((x) & UKPLAT_MEMRF_MAP_MASK)
/* valid flag is UKPLAT_MEMRF_MAP or UKPLAT_MEMRF_UNMAP, any combined value is
 * invalid
 */
#define UKPLAT_MRMRF_MAP_IS_VALID(x) \
	((UKPLAT_MEMRF_EXTRACT_MAP((x)) >> UKPLAT_MEMRF_MAP_SHIFT) <= 2)

/* Memory region attribute in page table*/
#if defined(CONFIG_ARCH_ARM_64)

/* ---- User Execute Never: Prohibit user-mode exec. ---- */
#define UKPLAT_MEMRF_UXN 0x0008

#define UKPLAT_MEMRF_EXECUTE_IS_VALID(x) \
	(((x) & UKPLAT_MEMRF_UXN) == 0 || ((x) & UKPLAT_MEMRF_EXECUTE) == 0)

/* ---- MAIR (Memory Attribute Indirection Register) index definitions ---- */
#define UKPLAT_MEMRF_MAIR_MASK 0x7
#define UKPLAT_MEMRF_MAIR_SHIFT 6

#define UKPLAT_MEMRF_MAIR_NORMAL_WB 0		 /* Normal, Write-Back. */
#define UKPLAT_MEMRF_MAIR_NORMAL_WT 1		 /* Normal, Write-Through. */
#define UKPLAT_MEMRF_MAIR_NORMAL_NC 2		 /* Normal, Non-Cacheable. */
#define UKPLAT_MEMRF_MAIR_DEVICE_nGnRnE 3	 /* Device, nGnRnE. */
#define UKPLAT_MEMRF_MAIR_DEVICE_nGnRE 4	 /* Device, nGnRE. */
#define UKPLAT_MEMRF_MAIR_DEVICE_GRE 5		 /* Device, GRE. */
#define UKPLAT_MEMRF_MAIR_NORMAL_WB_TAGGED 6 /* Write-Back, tagged. */

/* use this macro to generate mair flags, x is one of the UKPLAT_MEMRF_MAIR_x
 * value above
 */
#define UKPLAT_MEMRF_MAIR(x) ((x) << UKPLAT_MEMRF_MAIR_SHIFT)

/* use this macro to extract mair value from flags */
#define UKPLAT_MEMRF_EXTRACT_MAIR(x) \
	(((x) >> UKPLAT_MEMRF_MAIR_SHIFT) & UKPLAT_MEMRF_MAIR_MASK)

/* valid flag is one of the UKPLAT_MEMRF_MAIR_x value above, any combined value
 * is invalid
 */
#define UKPLAT_MEMRF_MAIR_IS_VALID(x) (UKPLAT_MEMRF_EXTRACT_MAIR(x) <= 6)

/* ---- Shareability attributes ---- */
#define UKPLAT_MEMRF_SHAREABLE_MASK 0x3
#define UKPLAT_MEMRF_SHAREABLE_SHIFT 9

#define UKPLAT_MEMRF_SHAREABLE_NS 0 /* Non-Shareable. */
#define UKPLAT_MEMRF_SHAREABLE_IS 1 /* Inner-Shareable. */
#define UKPLAT_MEMRF_SHAREABLE_OS 2 /* Outer-Shareable. */

/* use this macro to generate shareable flags, x is one of the
 * UKPLAT_MEMRF_SHAREABLE_x value above
 */
#define UKPLAT_MEMRF_SHAREABLE(x) ((x) << UKPLAT_MEMRF_SHAREABLE_SHIFT)

/* use this macro to extract shareable value from flags */
#define UKPLAT_MEMRF_EXTRACT_SHAREABLE(x) \
	(((x) >> UKPLAT_MEMRF_SHAREABLE_SHIFT) & UKPLAT_MEMRF_SHAREABLE_MASK)

/* valid flag is one of the UKPLAT_MEMRF_SHAREABLE_x value above, any combined
 * value is invalid
 */
#define UKPLAT_MEMRF_SHAREABLE_IS_VALID(x) \
	(UKPLAT_MEMRF_EXTRACT_SHAREABLE(x) <= 2)

/* ---- Additional attributes ---- */
#define UKPLAT_MEMRF_ACCESS_MASK 0x7
#define UKPLAT_MEMRF_ACCESS_SHIFT 11
#define UKPLAT_MEMRF_ACCESS_AF 0x1 /* Access Flag: Memory is accessed. */
#define UKPLAT_MEMRF_ACCESS_nG 0x2 /* Not-Global: Private memory. */
#define UKPLAT_MEMRF_ACCESS_CONTIGUOUS 0x4 /* Contiguous memory region. */

/* use this macro to generate access flags, x is one of the
 * UKPLAT_MEMRF_ACCESS_x value above
 */
#define UKPLAT_MEMRF_ACCESS(x) ((x) << UKPLAT_MEMRF_ACCESS_SHIFT)

/* use this macro to extract access value from flags */
#define UKPLAT_MEMRF_EXTRACT_ACCESS(x) \
	(((x) >> UKPLAT_MEMRF_ACCESS_SHIFT) & UKPLAT_MEMRF_ACCESS_MASK)

/* 0 or 1 of any bit is valid */
#define UKPLAT_MEMRF_ACCESS_IS_VALID(x) 1

/* ---- Granularity levels ---- */
#define UKPLAT_MEMRF_LEVEL_MASK 0x3
#define UKPLAT_MEMRF_LEVEL_SHIFT 14

#define UKPLAT_MEMRF_LEVEL_PAGE 0 /* PAGE: 4KB */
#define UKPLAT_MEMRF_LEVEL_PMD 1  /* PMD: 2MB. */
#define UKPLAT_MEMRF_LEVEL_PUD 2  /* PUD: 1GB. */

/* use this macro to generate level flags, x is one of the UKPLAT_MEMRF_LEVEL_x
 * value above
 */
#define UKPLAT_MEMRF_LEVEL(x) ((x) << UKPLAT_MEMRF_LEVEL_SHIFT)

/* use this macro to extract level value from flags */
#define UKPLAT_MEMRF_EXTRACT_LEVEL(x) \
	(((x) >> UKPLAT_MEMRF_LEVEL_SHIFT) & UKPLAT_MEMRF_LEVEL_MASK)

/* valid flag is one of the UKPLAT_MEMRF_LEVEL_x value above, any combined value
 * is invalid
 */
#define UKPLAT_MEMRF_LEVEL_IS_VALID(x) (UKPLAT_MEMRF_EXTRACT_LEVEL(x) <= 2)

/* The default memory attributes of the page table item when creating the page
 */
#define UKPLAT_MEMRF_VALUE_IS_WR                                              \
	(UKPLAT_MEMRF_ACCESS(UKPLAT_MEMRF_ACCESS_AF) |                            \
	 UKPLAT_MEMRF_SHAREABLE(UKPLAT_MEMRF_SHAREABLE_IS) | UKPLAT_MEMRF_WRITE | \
	 UKPLAT_MEMRF_READ)

#endif /* CONFIG_ARCH_ARM_64 */

/**
 * Descriptor of a memory region
 */
struct ukplat_memregion_desc {
	/** Physical page-aligned base address of the region */
	__paddr_t pbase;
	/** Virtual page-aligned base address of the region */
	__vaddr_t vbase;
	/** Offset where the resource starts in the region's first page */
	__off pg_off;
	/** Length in bytes of the resource inside this region */
	__sz len;
	/** Number of pages the end-to-end aligned region occupies */
	__sz pg_count;
	/** Memory region type (see UKPLAT_MEMRT_*) */
	__u16 type;
	/** Memory region flags (see UKPLAT_MEMRF_*) */
	__u16 flags;
#ifdef CONFIG_UKPLAT_MEMRNAME
	/** Region name */
	char name[36];
#endif /* CONFIG_UKPLAT_MEMRNAME */
} __packed __align(__SIZEOF_LONG__);

extern struct ukplat_memregion_desc bpt_memregion[];
extern struct ukplat_memregion_desc bpt_unmap_mrd;
extern __u32						bpt_memregion_count;

/** UK_ASSERT_VALID_MRD_TYPE(mrd) macro
 *
 * Ensure a given memory region descriptor has one of the following defined
 * types only:
 *	UKPLAT_MEMRT_FREE		Uninitialized memory
 *	UKPLAT_MEMRT_RESERVED		In use by platform
 *	UKPLAT_MEMRT_KERNEL		Kernel binary segment
 *	UKPLAT_MEMRT_INITRD		Initramdisk
 *	UKPLAT_MEMRT_CMDLINE		Command line
 *	UKPLAT_MEMRT_DEVICETREE		Device tree
 *	UKPLAT_MEMRT_STACK		Thread stack
 * @param mrd pointer to the memory region descriptor whose type to validate
 */
#define UK_ASSERT_VALID_MRD_TYPE(mrd)                         \
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
		default:                                              \
			UK_CRASH("Invalid mrd type: %hu\n", (mrd)->type); \
		}                                                     \
	} while (0)

/** UK_ASSERT_VALID_MRD_FLAGS(mrd) macro
 *
 * Ensure a given memory region descriptor has one of the following defined
 * flags only:
 *	UKPLAT_MEMRF_READ		Region is readable
 *	UKPLAT_MEMRF_WRITE		Region is writable
 *	UKPLAT_MEMRF_EXECUTE		Region is executable
 *	UKPLAT_MEMRF_UNMAP		Must be unmapped at boot
 *	UKPLAT_MEMRF_MAP		Must be mapped at boot
 *
 * @param mrd pointer to the memory region descriptor whose type to validate
 */
#if defined(CONFIG_ARCH_ARM_64)
#define UK_ASSERT_VALID_MRD_FLAGS(mrd)                            \
	do {                                                          \
		UK_ASSERT(UKPLAT_MRMRF_MAP_IS_VALID((mrd)->flags));       \
		UK_ASSERT(UKPLAT_MEMRF_EXECUTE_IS_VALID((mrd)->flags));   \
		UK_ASSERT(UKPLAT_MEMRF_MAIR_IS_VALID((mrd)->flags));      \
		UK_ASSERT(UKPLAT_MEMRF_SHAREABLE_IS_VALID((mrd)->flags)); \
		UK_ASSERT(UKPLAT_MEMRF_LEVEL_IS_VALID((mrd)->flags));     \
	} while (0)
#else
#define UK_ASSERT_VALID_MRD_FLAGS(mrd)                       \
	do {                                                     \
		UK_ASSERT(UKPLAT_MEMRF_PERM_IS_VALID((mrd)->flags)); \
		UK_ASSERT(UKPLAT_MEMRF_MAP_IS_VALID((mrd)->flags));  \
	} while (0)
#endif

/** UK_ASSERT_VALID_MRD(mrd) macro
 *
 * Ensure memory region descriptor general correctness:
 * - must be of only one valid type as per UK_ASSERT_VALID_MRD_TYPE
 * - must only have valid flags as per UK_ASSERT_VALID_MRD_FLAGS
 * - memory region is not empty or of length 0
 * - virtual/physical base addresses are page-aligned
 * - resource in-page offset must be in the range [0, PAGE_SIZE)
 *
 * @param mrd pointer to the free memory region descriptor to validate
 */
#define UK_ASSERT_VALID_MRD(mrd)                                           \
	do {                                                                   \
		UK_ASSERT_VALID_MRD_TYPE((mrd));                                   \
		UK_ASSERT_VALID_MRD_FLAGS((mrd));                                  \
		UK_ASSERT(PAGE_ALIGNED((mrd)->vbase));                             \
		UK_ASSERT(PAGE_ALIGNED((mrd)->pbase));                             \
		UK_ASSERT((mrd)->pg_off >= 0 && (mrd)->pg_off < (__off)PAGE_SIZE); \
	} while (0)

/** UK_ASSERT_VALID_FREE_MRD(mrd) macro
 *
 * Ensure free memory region descriptor particular correctness:
 * - must meet the criteria of a general valid memory region descriptor
 * - virtual/physical base addresses are equal
 * - region is aligned end-to-end, therefore length is multiple of
 * PAGE_SIZE times region's page count and the resource's
 * in-page offset must be 0
 *
 * @param mrd pointer to the free memory region descriptor to validate
 */
#define UK_ASSERT_VALID_FREE_MRD(mrd)                         \
	do {                                                      \
		UK_ASSERT_VALID_MRD((mrd));                           \
		UK_ASSERT((mrd)->type == UKPLAT_MEMRT_FREE);          \
		UK_ASSERT((mrd)->vbase == (mrd)->pbase);              \
		UK_ASSERT(!(mrd)->pg_off);                            \
	} while (0)

/** UK_ASSERT_VALID_KERNEL_MRD(mrd) macro
 *
 * Ensure kernel memory region descriptor particular correctness:
 * - must meet the criteria of a general valid memory region descriptor
 * - region is aligned end-to-end, therefore length is multiple of
 * PAGE_SIZE times region's page count and the resource's
 * in-page offset must be 0
 *
 * @param mrd pointer to the kernel memory region descriptor to validate
 */
#define UK_ASSERT_VALID_KERNEL_MRD(mrd)                       \
	do {                                                      \
		UK_ASSERT_VALID_MRD((mrd));                           \
		UK_ASSERT((mrd)->type == UKPLAT_MEMRT_KERNEL);        \
		UK_ASSERT((mrd)->pg_count * PAGE_SIZE == (mrd)->len); \
		UK_ASSERT(!(mrd)->pg_off);                            \
	} while (0)

/**
 * Check whether the memory region descriptor overlaps with [pstart, pend) in
 * the physical address space.
 *
 * @param mrd
 *   Pointer to the memory region descriptor to check against
 * @param pstart
 *   Start of the physical memory region
 * @param pend
 *   End of the physical memory region
 * @return
 *   Zero if the two specified regions have no overlap, a non-zero value
 *   otherwise
 */
static inline int
ukplat_memregion_desc_overlap(const struct ukplat_memregion_desc *mrd,
			      __paddr_t pstart, __paddr_t pend)
{
	return RANGE_OVERLAP(mrd->pbase, mrd->len, pstart, pend - pstart);
}

/**
 * Returns the number of available memory regions
 */
int ukplat_memregion_count(void);

/**
 * Returns a pointer to the requested memory region descriptor
 *
 * @param i
 *   Memory region number
 * @param[out] mrd
 *   A pointer to a memory region descriptor that will be updated
 *
 * @return
 *   0 on success, < 0 otherwise
 */
int ukplat_memregion_get(int i, struct ukplat_memregion_desc **mrd);

/**
 * Searches for the next memory region after i that fulfills the given search
 * criteria.
 *
 * @param i
 *   Memory region number to start searching. Use -1 to start from the
 *   beginning.
 * @param type
 *   The set of memory region types to look for. Can be UKPLAT_MEMRT_ANY or a
 *   combination of specific types (UKPLAT_MEMRT_*). If 0 is specified, the
 *   type is ignored.
 * @param flags
 *   Find only memory regions that have the specified flags set
 * @param fmask
 *   Only consider the flags provided in this mask when searching for a region
 * @param[out] mrd
 *   Pointer to a memory region descriptor that will be updated on success
 *
 * @return
 *   On success the function returns the next region after i that has any of
 *   the specified types and fulfills the given flags. A value < 0 is returned
 *   if no more region could be found that fulfills the search criteria. In
 *   that case mrd is not changed.
 */
static inline int
ukplat_memregion_find_next(int i, __u32 type, __u32 flags, __u32 fmask,
			   struct ukplat_memregion_desc **mrd)
{
	struct ukplat_memregion_desc *desc;
	__u32 stype, sflags;
	int rc;

	do {
		rc = ukplat_memregion_get(++i, &desc);
		if (rc < 0)
			return -1;

		stype  = desc->type & type;
		sflags = desc->flags & fmask;
	} while ((type && !stype) || (sflags != flags));

	*mrd = desc;
	return i;
}

/**
 * Iterates over all memory regions that fulfill the given search criteria.
 *
 * @param[out] mrd
 *   Pointer to memory region descriptor
 * @param type
 *   The set of memory region types to look for. Can be UKPLAT_MEMRT_ANY or
 *   a combination of specific types (UKPLAT_MEMRT_*). If 0 is specified, the
 *   type is ignored.
 * @param flags
 *   Find only memory regions that have the specified flags set
 * @param fmask
 *   Only consider the flags provided in this mask when searching for a region
 */
#define ukplat_memregion_foreach(mrd, type, flags, fmask)		\
	for (int __ukplat_memregion_foreach_i				\
		     = ukplat_memregion_find_next(-1, type, flags, fmask, mrd);\
	     __ukplat_memregion_foreach_i >= 0;				\
	     __ukplat_memregion_foreach_i				\
		     = ukplat_memregion_find_next(__ukplat_memregion_foreach_i,\
						  type, flags, fmask, mrd))

/**
 * Searches for the first initrd module.
 *
 * @param[out] mrd
 *   Pointer to memory region descriptor that will be updated on success
 *
 * @return
 *   On success, returns the region number of the first initrd module. A
 *   return value < 0 means that there is no initrd module.
 */
#define ukplat_memregion_find_initrd0(mrd) \
	ukplat_memregion_find_next(-1, UKPLAT_MEMRT_INITRD, 0, 0, mrd)

/**
 * Sets the platform memory allocator and triggers the platform memory mappings
 * for which an allocator is needed.
 *
 * @param a
 *   Memory allocator to use within the platform
 * @return
 *   0 on success, < 0 otherwise
 */
int ukplat_memallocator_set(struct uk_alloc *a);

/**
 * Returns the platform memory allocator
 */
struct uk_alloc *ukplat_memallocator_get(void);

/**
 * Allocates page-aligned memory by taking it away from the free physical
 * memory. Only memory up to the platform's static page table mapped
 * maximum address is used so that it is accessible.
 * Note, the memory cannot be released!
 *
 * @param size
 *   The size to allocate. Will be rounded up to next multiple of page size.
 * @param type
 *   Memory region type to use for the allocated memory. Can be 0.
 * @param flags
 *   Flags of the allocated memory region.
 *
 * @return
 *   A pointer to the allocated memory on success, NULL otherwise.
 */
void *ukplat_memregion_alloc(__sz size, int type, __u16 flags);

/**
 * Initializes the memory mapping based on the platform or architecture defined
 * unmapping memory region descriptor (named `bpt_unmap_mrd`). Based on this
 * descriptor, the function surrounds the kernel image with the unmappings,
 * adding an unmapping region before and after the kernel. Therefore,
 * `bpt_unmap_mrd`'s range must contain the kernel image range.
 *
 * @param bi
 *   Pointer to the image's `struct ukplat_bootinfo` structure.
 *
 * @return
 *   0 on success, not 0 otherwise.
 */
int ukplat_mem_init(void);

/* Allocates and returns an auxiliary stack that can be used in emergency cases
 * such as when switching system call stacks. The size is that given by
 * (1 << CONFIG_AUXSP_PAGE_ORDER) * PAGE_SIZE.
 *
 * @param a
 *   The allocator to use for the auxiliary stack
 * @param vas
 *   The virtual address space to use for the mapping of the auxiliary stack.
 *   This should be used in conjunction with CONFIG_LIBUKVMEM to ensure that
 *   accesses to the auxiliary stack do not generate page faults in more
 *   fragile system states.
 * @param auxsp_len
 *   The custom length of the auxiliary stack. If 0, then
 *   CONFIG_UKPLAT_AUXSP_PAGE_ORDER is used instead as the default length.
 * @param auxstack
 *   Pointer to the allocated auxiliary stack, used to store the start address.
 *
 * @return
 *   Pointer to the allocated auxiliary stack
 */
static inline __uptr ukplat_auxsp_alloc(struct uk_alloc __maybe_unused *a,
#if CONFIG_LIBUKVMEM
					struct uk_vas __maybe_unused *vas,
#endif /* CONFIG_LIBUKVMEM */
					__sz auxsp_len,
					__uptr * auxstack)
{
	__vaddr_t auxsp;

	/**
	 * Why does the auxiliary stack have to be end-to-end aligned to ECTX
	 * alignment?
	 * Because we may want to be able to save the ECTX on it during
	 * more fragile states of execution and on architectures such as x86
	 * this is done through specialized instructions that require start
	 * of the save area to be aligned to a variable alignment dependent
	 * on what the CPU supports (see comment from x86 UKARCH_ECTX_SIZE).
	 * Therefore, the allocation returned address must have the same
	 * alignment as well because when we add to it the auxiliary stack
	 * length the resulted stack pointer should on its own be ECTX aligned.
	 */
	if (!auxsp_len)
		auxsp_len = ALIGN_UP(PAGE_SIZE *
				     (1 << CONFIG_UKPLAT_AUXSP_PAGE_ORDER),
				     UKARCH_ECTX_ALIGN);

#if CONFIG_LIBUKVMEM
	int rc;

	/* Have the whole stack always backed by physical memory */
	auxsp = __VADDR_ANY;
	/* Allocation through uk_vma_map_stack() will result in a page-aligned
	 * address which is more than enough to be ECTX aligned.
	 */
	rc = uk_vma_map_stack(vas,
			      &auxsp,
			      auxsp_len,
			      UK_VMA_MAP_POPULATE,
			      "auxiliary_stack",
			      0);
	if (unlikely(rc)) {
		uk_pr_err("Failed to map auxiliary stack\n");
		return 0;
	}
#else /* !CONFIG_LIBUKVMEM */
	/* Again, make sure that allocation resulted start address is ECTX
	 * aligned.
	 */
	auxsp = (__vaddr_t)uk_memalign(a, UKARCH_ECTX_ALIGN,
				       auxsp_len);
	if (unlikely(!auxsp)) {
		uk_pr_err("Failed to allocate auxiliary stack\n");
		return 0;
	}
#endif /* !CONFIG_LIBUKVMEM */

	if (auxstack)
		*auxstack = auxsp;

	/* If auxsp resulted from the previous allocations is ECTX aligned
	 * and auxsp_len is ECTX aligned, then the function call below will
	 * result in an ECTX aligned stack pointer.
	 */
	return (__uptr)ukarch_gen_sp((__uptr)auxsp, auxsp_len);
}

/* Free an auxiliary stack that created by ukplat_auxsp_alloc.
 * The size is that given by (1 << CONFIG_AUXSP_PAGE_ORDER) * PAGE_SIZE.
 *
 * @param a
 *   The allocator to use for the auxiliary stack
 * @param vas
 *   The virtual address space to use for the mapping of the auxiliary stack.
 *   This should be used in conjunction with CONFIG_LIBUKVMEM to ensure that
 *   accesses to the auxiliary stack do not generate page faults in more
 *   fragile system states.
 * @param auxstack
 *   Pointer to the allocated auxiliary stack, used to store the start address.
 * @param auxstack_len
 *   The custom length of the auxiliary stack. If 0, then
 *   CONFIG_UKPLAT_AUXSP_PAGE_ORDER is used instead as the default length.
 */
static inline void ukplat_auxsp_free(struct uk_alloc __maybe_unused *a,
#if CONFIG_LIBUKVMEM
				     struct uk_vas __maybe_unused *vas,
#endif /* CONFIG_LIBUKVMEM */
				     __uptr auxstack,
				     __sz __maybe_unused auxstack_len)
{
#if CONFIG_LIBUKVMEM
	int rc;

	/* Compitable with the behavior provided by ukplat_auxsp_alloc */
	if (!auxstack_len)
		auxstack_len =
		    ALIGN_UP(PAGE_SIZE * (1 << CONFIG_UKPLAT_AUXSP_PAGE_ORDER),
			     UKARCH_ECTX_ALIGN);

	rc = uk_vma_unmap(vas, auxstack, auxstack_len, 0);
	if (rc) {
		uk_pr_err("Failed to unmap auxiliary stack\n");
		return;
	}
#else  /* !CONFIG_LIBUKVMEM */
	uk_free(a, (void *)auxstack);
#endif /* !CONFIG_LIBUKVMEM */
}

#ifdef __cplusplus
}
#endif

#endif /* __PLAT_MEMORY_H__ */
