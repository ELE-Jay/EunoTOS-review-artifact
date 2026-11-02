/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <uk/essentials.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/plat/common/sections.h>
#include <uk/ofw/fdt.h>

#define ukplat_bootinfo_crash(s)		ukplat_crash()

#ifdef CONFIG_STATIC_PGTABLE
static void
fdt_bootinfo_static_mem_mrd(struct ukplat_bootinfo		 *bi,
							struct ukplat_memregion_desc *static_memr,
							int							  static_memr_count)
{
	int							  rc;
	int							  i;
	struct ukplat_memregion_desc *mrdp;

	for (i = 0; i < static_memr_count; ++i) {
		mrdp = &static_memr[i];

		rc = ukplat_memregion_list_insert(&bi->mrds, mrdp);
		if (unlikely(rc < 0))
			ukplat_bootinfo_crash("Initialize static memregion failed!");
	}
}
#else
static void fdt_bootinfo_mem_mrd(struct ukplat_bootinfo *bi, void *fdtp)
{
	struct ukplat_memregion_desc mrd = {0};
	__u64 mem_base, mem_sz;
	int len, ranges, range_index;
	int parent_offset, naddr, nsize;
	int nmem;
	int rc;

	nmem = fdt_node_offset_by_prop_value(fdtp, -1, "device_type",
					     "memory", sizeof("memory"));
	if (unlikely(nmem < 0))
		ukplat_bootinfo_crash("No memory found in DTB");

	/*
	 * The property must contain at least the start address
	 * and size, each length of which is defined in
	 * #address-cells/#size-cells of root node.
	 * For now, we only support one memory bank.
	 * TODO: Support more than one memory@ node/regs/ranges properties.
	 */

	parent_offset = fdt_parent_offset(fdtp, nmem);
	naddr = fdt_address_cells(fdtp, parent_offset);
	nsize = fdt_size_cells(fdtp, parent_offset);

	fdt_getprop(fdtp, nmem, "reg", &len);
	ranges = len / (sizeof(fdt32_t) * (nsize + naddr));

	for (range_index = 0; range_index < ranges; range_index++) {
		rc = fdt_get_address(fdtp, nmem, range_index,
					&mem_base, &mem_sz);
		if (unlikely(rc))
			ukplat_bootinfo_crash(
				"Get memory device address/size failed");

		if (unlikely(!RANGE_CONTAIN(mem_base, mem_sz,
					    __BASE_ADDR, __END - __BASE_ADDR))){
			mrd.len	= mem_sz;
			if (!mrd.len)
				continue;

			mrd.pbase	 = (__paddr_t)PAGE_ALIGN_DOWN(mem_base);
			mrd.vbase	 = (__vaddr_t)PAGE_ALIGN_DOWN(mem_base);
			mrd.pg_off	 = mem_base - mrd.pbase;
			mrd.type	 = UKPLAT_MEMRT_FREE;
			mrd.flags	 = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;
			mrd.pg_count = PAGE_COUNT(mrd.pg_off + mrd.len);

			rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
			if (unlikely(rc < 0))
				ukplat_bootinfo_crash(
					"Could not add free memory descriptor");

			continue;

		}

		/*
		 * Check that we are not placed at the top of
		 * the memory region
		 */
		mrd.len   = __BASE_ADDR - mem_base;
		if (!mrd.len)
			goto end_mrd;

		mrd.pbase	 = (__paddr_t)PAGE_ALIGN_DOWN(mem_base);
		mrd.vbase	 = (__vaddr_t)PAGE_ALIGN_DOWN(mem_base);
		mrd.pg_off	 = mem_base - mrd.pbase;
		mrd.type	 = UKPLAT_MEMRT_FREE;
		mrd.flags	 = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;
		mrd.pg_count = PAGE_COUNT(mrd.pg_off + mrd.len);

		rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
		if (unlikely(rc < 0))
			ukplat_bootinfo_crash(
				"Could not add free memory descriptor");

end_mrd:
		/*
		 * Check that we are not placed at the end of
		 * the memory region
		 */
		mrd.len   = mem_base + mem_sz - __END;
		if (!mrd.len)
			return;

		mrd.pbase	 = (__paddr_t)PAGE_ALIGN_DOWN(__END);
		mrd.vbase	 = (__vaddr_t)PAGE_ALIGN_DOWN(__END);
		mrd.pg_off	 = __END - mrd.pbase;
		mrd.type	 = UKPLAT_MEMRT_FREE;
		mrd.flags	 = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;
		mrd.pg_count = PAGE_COUNT(mrd.pg_off + mrd.len);

		rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
		if (unlikely(rc < 0))
			ukplat_bootinfo_crash(
				"Could not add free memory descriptor");
	}
}
#endif

static void fdt_bootinfo_cmdl_mrd(struct ukplat_bootinfo *bi, void *fdtp)
{
	const void *fdt_cmdl;
	int fdt_cmdl_len;
	__sz cmdl_len;
	int nchosen;
	char *cmdl;

	nchosen = fdt_path_offset(fdtp, "/chosen");
	if (unlikely(nchosen < 0))
		return;

	fdt_cmdl = fdt_getprop(fdtp, nchosen, "bootargs", &fdt_cmdl_len);
	if (unlikely(!fdt_cmdl || fdt_cmdl_len <= 0))
		return;

	cmdl = ukplat_memregion_alloc(fdt_cmdl_len + sizeof(CONFIG_UK_NAME) + 1,
				      UKPLAT_MEMRT_CMDLINE,
				      UKPLAT_MEMRF_READ |
				      UKPLAT_MEMRF_MAP);
	if (unlikely(!cmdl))
		ukplat_bootinfo_crash("Command-line alloc failed\n");

	cmdl_len = sizeof(CONFIG_UK_NAME);
	strncpy(cmdl, CONFIG_UK_NAME, cmdl_len);
	cmdl[cmdl_len - 1] = ' ';
	strncpy(cmdl + cmdl_len, fdt_cmdl, fdt_cmdl_len);
	cmdl_len += fdt_cmdl_len;
	cmdl[cmdl_len] = '\0';

	bi->cmdline = (__u64)cmdl;
	bi->cmdline_len = (__u64)cmdl_len;
}

/* Ideally the initrd nodes would use #address-cells, yet these nodes are not
 * defined by the device-tree spec, and as such there is no formal requirement
 * that they do so. In fact, QEMU virt uses a 32-bit address here, despite
 * defining 2 address cells. To handle such cases, use the property length to
 * determine the correct address.
 */
#define initrd_addr(val, len)                          \
	(len == 4 ? fdt32_to_cpu(val) : fdt64_to_cpu(val))

static void fdt_bootinfo_initrd_mrd(struct ukplat_bootinfo *bi, void *fdtp)
{
	struct ukplat_memregion_desc mrd = {0};
	const __u64 *fdt_initrd_start;
	const __u64 *fdt_initrd_end;
	int start_len, end_len;
	__u64 initrd_base;
	int nchosen;
	int rc;

	nchosen = fdt_path_offset(fdtp, "/chosen");
	if (unlikely(nchosen < 0))
		return;

	fdt_initrd_start = fdt_getprop(fdtp, nchosen, "linux,initrd-start",
				       &start_len);
	if (unlikely(!fdt_initrd_start || start_len <= 0))
		return;

	fdt_initrd_end = fdt_getprop(fdtp, nchosen, "linux,initrd-end",
				     &end_len);
	if (unlikely(!fdt_initrd_end || end_len <= 0))
		return;

	initrd_base	 = initrd_addr(fdt_initrd_start[0], start_len);
	mrd.pbase	 = PAGE_ALIGN_DOWN(initrd_base);
	mrd.vbase	 = mrd.pbase;
	mrd.pg_off	 = initrd_base - mrd.pbase;
	mrd.len		 = initrd_addr(fdt_initrd_end[0], end_len) - initrd_base;
	mrd.pg_count = PAGE_COUNT(mrd.pg_off + mrd.len);
	mrd.type	 = UKPLAT_MEMRT_INITRD;
	mrd.flags	 = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP;

	rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
	if (unlikely(rc < 0))
		ukplat_bootinfo_crash("Could not add initrd memory descriptor");
}

static void fdt_bootinfo_fdt_mrd(struct ukplat_bootinfo *bi, void *fdtp)
{
	struct ukplat_memregion_desc mrd = {0};
	int rc;

	mrd.pbase	 = (__paddr_t)PAGE_ALIGN_DOWN((__uptr)fdtp);
	mrd.vbase	 = (__vaddr_t)PAGE_ALIGN_DOWN((__uptr)fdtp);
	mrd.pg_off	 = (__u64)fdtp - mrd.pbase;
	mrd.len		 = fdt_totalsize(fdtp);
	mrd.pg_count = PAGE_COUNT(mrd.pg_off + mrd.len);
	mrd.type	 = UKPLAT_MEMRT_DEVICETREE;
	mrd.flags	 = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_MAP;

	rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
	if (unlikely(rc < 0))
		ukplat_bootinfo_crash("Could not insert DT memory descriptor");
}

void ukplat_bootinfo_fdt_setup(void *fdtp)
{
	struct ukplat_bootinfo *bi;

	bi = ukplat_bootinfo_get();
	if (unlikely(!bi))
		ukplat_bootinfo_crash("Invalid bootinfo");

	if (unlikely(fdt_check_header(fdtp)))
		ukplat_bootinfo_crash("Invalid DTB");

	fdt_bootinfo_fdt_mrd(bi, fdtp);
#ifdef CONFIG_STATIC_PGTABLE
	fdt_bootinfo_static_mem_mrd(bi, bpt_memregion, bpt_memregion_count);
#else
	fdt_bootinfo_mem_mrd(bi, fdtp);
#endif
	fdt_bootinfo_initrd_mrd(bi, fdtp);
	ukplat_memregion_list_coalesce(&bi->mrds);

	/* We use this after coalescing/sorted because this calls
	 * `ukplat_memregion_alloc()` which would be unsafe to do so before
	 * knowing that the memory region descriptor list has been coalesced
	 * and sorted.
	 */
	fdt_bootinfo_cmdl_mrd(bi, fdtp);

	bi->dtb = (__u64)fdtp;
}
