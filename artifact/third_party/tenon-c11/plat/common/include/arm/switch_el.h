/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#ifdef __ASSEMBLY__
.macro	switch_el, xreg, el2_label, el1_label
	mrs	\xreg, CurrentEL
	cmp	\xreg, 0x8
	beq	\el2_label
	cmp	\xreg, 0x4
	beq	\el1_label
.endm
#endif /* !__ASSEMBLY__ */
