/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#include <libfdt.h>
#include <arm/smccc.h>
#include <arm/psci.h>

smccc_conduit_fn_t smccc_psci_call;

int get_psci_method(struct ukplat_bootinfo *bi)
{
	const char *fdtmethod;
	int			fdtpsci, len;
	void	   *fdt;

	fdt = (void *)bi->dtb;
	UK_ASSERT(bi->dtb);

	/*
	 * We just support PSCI-0.2 and PSCI-1.0, the PSCI-0.1 would not
	 * be supported.
	 */
	fdtpsci = fdt_node_offset_by_compatible(fdt, -1, "arm,psci-1.0");
	if (unlikely(fdtpsci < 0))
		fdtpsci = fdt_node_offset_by_compatible(fdt, -1, "arm,psci-0.2");

	if (unlikely(fdtpsci < 0)) {
		uk_pr_info("No PSCI conduit found in DTB\n");
		goto enomethod;
	}

	fdtmethod = fdt_getprop(fdt, fdtpsci, "method", &len);
	if (unlikely(!fdtmethod || len <= 0)) {
		uk_pr_info("No PSCI method found\n");
		goto enomethod;
	}

	if (!strcmp(fdtmethod, "hvc"))
		smccc_psci_call = smccc_hvc;
	else if (!strcmp(fdtmethod, "smc"))
		smccc_psci_call = smccc_smc;
	else {
		uk_pr_info("Invalid PSCI conduit method: %s\n", fdtmethod);
		goto enomethod;
	}
	uk_pr_info("PSCI method: %s\n", fdtmethod);

	return 0;

enomethod:
	uk_pr_info("PSCI versions above 0.2 are supported\n");
	smccc_psci_call = NULL;

	return -ENOENT;
}
