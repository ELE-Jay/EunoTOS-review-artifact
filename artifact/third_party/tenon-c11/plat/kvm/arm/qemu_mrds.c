/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#include <uk/config.h>
#include <uk/plat/memory.h>

/* ------------------------- Memory Map of QEMU virt -----------------------
 *
 * 0x0000000000000000 - 0x0000000007ffffff	Hole:          0    - 128MiB
 * 0x0000000008000000 - 0x000000003fffffff	Devices:     128MiB -   1GiB
 * 0x0000000040000000 - 0x0000007fffffffff	Kernel:        1GiB - 512GiB
 * 0x0000008000000000 - 0x000000ffffffffff	PCIe hi mem: 512GiB -   1TiB
 *
 * Notice: The page tables below use the Unikraft indexing convention (x86).
 */
struct ukplat_memregion_desc bpt_unmap_mrd __section(".data") = {
	.pbase	= ALIGN_DOWN(0x40000000UL, __PAGE_SIZE),
	.vbase	= ALIGN_DOWN(0x40000000UL, __PAGE_SIZE),
	.pg_off = 0x0UL,
	/* QEMU-VIRT's legacy RAM max is 255 GiB, but it can also depend on the
	 * settings, see QEMU upstream commit:
	 * 50a17297e2f0c ("hw/arm/virt: Bump the 255GB initial RAM limit").
	 * In our case, here we assume that the RAM can only go up to the PCIe
	 * high memory.
	 */
	.len	  = (255 - 1) * 0x40000000UL,
	.pg_count = PAGE_COUNT((255 - 1) * 0x40000000UL),
	.type	  = UKPLAT_MEMRT_RESERVED,
	.flags	  = UKPLAT_MEMRF_UNMAP
#ifdef CONFIG_UKPLAT_MEMRNAME
	,
	.name = { 0 }
#endif
};

#ifdef CONFIG_STATIC_PGTABLE
struct ukplat_memregion_desc
	bpt_memregion[] __section(".tn_static_memregion") = {
		/* RAM
		 * Virtual address:	0x0000000040000000 - 0x00000000401fffff
		 * Physical address:	0x0000000040000000 - 0x00000000401fffff
		 */
		{ .pbase  = ALIGN_DOWN(0x40000000UL, __PAGE_SIZE),
		  .vbase  = ALIGN_DOWN(0x40000000UL, __PAGE_SIZE),
		  .pg_off = 0x0,
#ifdef CONFIG_VIRTUALIZE_PLAT_MEM_SIZE
		  .len		= CONFIG_VIRTUALIZE_PLAT_MEM_SIZE,
		  .pg_count = PAGE_COUNT(CONFIG_VIRTUALIZE_PLAT_MEM_SIZE),
#else
		  .len		= 0x8000000UL,
		  .pg_count = PAGE_COUNT(0x8000000UL),
#endif
		  .type	 = UKPLAT_MEMRT_FREE,
		  .flags = UKPLAT_MEMRF_VALUE_IS_WR | UKPLAT_MEMRF_UXN |
				   UKPLAT_MEMRF_MAIR(UKPLAT_MEMRF_MAIR_NORMAL_WB) |
				   UKPLAT_MEMRF_LEVEL(UKPLAT_MEMRF_LEVEL_PMD)
#ifdef CONFIG_UKPLAT_MEMRNAME
			  ,
		  .name = { 0 }
#endif /* CONFIG_UKPLAT_MEMRNAME */
		},
		/* Devices
		 * Virtual address:	0x0000000008000000 - 0x000000003fffffff
		 * Physical address:	0x0000000008000000 - 0x000000003fffffff
		 */
		{ .pbase	= ALIGN_DOWN(0x8000000UL, __PAGE_SIZE),
		  .vbase	= ALIGN_DOWN(0x8000000UL, __PAGE_SIZE),
		  .pg_off	= 0x0,
		  .len		= 0x38000000UL,
		  .pg_count = PAGE_COUNT(0x38000000UL),
		  .type		= UKPLAT_MEMRT_RESERVED,
		  .flags	= UKPLAT_MEMRF_VALUE_IS_WR |
				   UKPLAT_MEMRF_MAIR(UKPLAT_MEMRF_MAIR_DEVICE_nGnRE) |
				   UKPLAT_MEMRF_LEVEL(UKPLAT_MEMRF_LEVEL_PMD)
#ifdef CONFIG_UKPLAT_MEMRNAME
			  ,
		  .name = { 0 }
#endif /* CONFIG_UKPLAT_MEMRNAME */
		},
		/* PCIe ECAM
		 * Virtual address:	0x0000004000000000 - 0x0000007fffffffff
		 * Physical address:	0x0000004000000000 - 0x0000007fffffffff
		 */
		{ .pbase	= ALIGN_DOWN(0x4000000000UL, __PAGE_SIZE),
		  .vbase	= ALIGN_DOWN(0x4000000000UL, __PAGE_SIZE),
		  .pg_off	= 0x0,
		  .len		= 0x4000000000UL,
		  .pg_count = PAGE_COUNT(0x4000000000UL),
		  .type		= UKPLAT_MEMRT_RESERVED,
		  .flags	= UKPLAT_MEMRF_VALUE_IS_WR |
				   UKPLAT_MEMRF_MAIR(UKPLAT_MEMRF_MAIR_DEVICE_nGnRnE) |
				   UKPLAT_MEMRF_LEVEL(UKPLAT_MEMRF_LEVEL_PUD)
#ifdef CONFIG_UKPLAT_MEMRNAME
			  ,
		  .name = { 0 }
#endif /* CONFIG_UKPLAT_MEMRNAME */
		},
		/* PCIe hi-mem
		 * virtual address:	0x0000008000000000 - 0x000000ffffffffff
		 * physical address:	0x0000008000000000 - 0x000000ffffffffff
		 */
		{ .pbase	= ALIGN_DOWN(0x8000000000UL, __PAGE_SIZE),
		  .vbase	= ALIGN_DOWN(0x8000000000UL, __PAGE_SIZE),
		  .pg_off	= 0x0,
		  .len		= 0x8000000000UL,
		  .pg_count = PAGE_COUNT(0x8000000000UL),
		  .type		= UKPLAT_MEMRT_RESERVED,
		  .flags	= UKPLAT_MEMRF_VALUE_IS_WR |
				   UKPLAT_MEMRF_MAIR(UKPLAT_MEMRF_MAIR_DEVICE_nGnRE) |
				   UKPLAT_MEMRF_LEVEL(UKPLAT_MEMRF_LEVEL_PUD)
#ifdef CONFIG_UKPLAT_MEMRNAME
			  ,
		  .name = { 0 }
#endif /* CONFIG_UKPLAT_MEMRNAME */
		}
	};

#ifdef CONFIG_PAGING
struct ukplat_memregion_desc
	direct_map_mrd __section(".tn_direct_memregion") = {
	/* Direct-mapped
	 * Virtual address:  0x0000ff8000000000 - 0x0000ffffffffffff
	 * Physical address: 0x0000000000000000 - 0x0000008000000000
	 */
	.pbase    = ALIGN_DOWN(0x0UL, __PAGE_SIZE),
	.vbase    = ALIGN_DOWN(0xff8000000000UL, __PAGE_SIZE),
	.pg_off   = 0x0,
	.len      = 0x8000000000UL,
	.pg_count = PAGE_COUNT(0x8000000000UL),
	.type     = UKPLAT_MEMRT_RESERVED,
	.flags    = UKPLAT_MEMRF_VALUE_IS_WR |
			UKPLAT_MEMRF_MAIR(UKPLAT_MEMRF_MAIR_NORMAL_WB) |
			UKPLAT_MEMRF_LEVEL(UKPLAT_MEMRF_LEVEL_PUD)
#ifdef CONFIG_UKPLAT_MEMRNAME
			  ,
	.name = { 0 }
#endif /* CONFIG_UKPLAT_MEMRNAME */
};
#endif

__u32 bpt_memregion_count =
	sizeof(bpt_memregion) / sizeof(struct ukplat_memregion_desc);

#endif
