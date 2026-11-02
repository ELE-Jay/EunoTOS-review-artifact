/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

SECTIONS {
	. = ALIGN(8);
	.tn_static_memregion :
	{
		KEEP(*(.tn_static_memregion))
	}
}
INSERT AFTER .data
