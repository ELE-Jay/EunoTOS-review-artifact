/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */
#include <uk/arch/lcpu.h>
#include <uk/asm.h>

ENTRY(do_syscall)
	mov	x8, x0
	svc #0
	ret
END(do_syscall)
