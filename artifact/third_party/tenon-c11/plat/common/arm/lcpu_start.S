/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Răzvan Vîrtan <virtanrazvan@gmail.com>
 *          Justin He     <justin.he@arm.com>
 *
 * Copyright (c) 2021, Arm Ltd. All rights reserved.
 * Copyright (c) 2021, University Politehnica of Bucharest. All rights reserved.
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

 #include <arm/switch_el.h>
 #include <uk/asm.h>
 #include <uk/plat/offset.h>
 #include <uk/reloc.h>
 #include <uk/asm/arch.h>

.extern bootstrap_cpu_record
.text
/* void _lcpu_start(lcpu_boot_args *bootargs) */
ENTRY(lcpu_start)
	/* save x0 */
	mov	x9, x0

	/* Disable interrupts */
	msr	daifset, #2

	/* detect EL level */
	switch_el x0, el2_entry, el1_entry

el2_entry:
	ldr	x0, =SCTLR_EL2_DEFAULT
	msr	sctlr_el2, x0
	isb

	// Disable coprocessor traps
	ldr	x0, =CPACR_EL1_DEFAULT
	msr	cpacr_el1, x0

	// define register width, el1: aarch64, el0: by code. other bits are 0.
	ldr	x0, =HCR_EL2_DEFAULT
	msr	hcr_el2, x0

	// Set the SPSR state to restore when returning from EL2 to EL1
	ldr	x0, =SPSR_EL2_DEFAULT
	msr	spsr_el2, x0

	adr	x0, el1_entry
	msr	elr_el2, x0

	eret

el1_entry:
	// disable mmu and cache
	mrs	x2, sctlr_el1
	mov	x3, #SCTLR_EL1_M_BIT|SCTLR_EL1_C_BIT
	bic	x2, x2, x3
	msr	sctlr_el1, x2

	// Disable coprocessor traps
	ldr	x0, =CPACR_EL1_DEFAULT
	msr	cpacr_el1, x0

	/* Set the context id */
	msr	contextidr_el1, xzr

	/* Setup exception vector table address before enable MMU */
	ur_ldr  x29, vectors_el1
	msr     VBAR_EL1, x29

	ldr	x0, =_start_ram_addr
	ldr	x1, =_end
	sub	x1, x1, x0
	bl	clean_and_invalidate_dcache_range

	/* Enable the mmu */
	bl	start_mmu

	/* restore x0 */
	mov	x0, x9

	/* Load the stack pointer */
	ldr	x9, [x0, #BOOT_ARGS_SARGS_STACKP_OFFSET]
	mov	sp, x9

	/* Load the entry address and jump to it */
	ldr	x9, [x0, #BOOT_ARGS_SARGS_ENTRY_OFFSET]

	/* Load the lcpu pointer as parameter passed */
	ldr	x0, [x0, #BOOT_ARGS_SARGS_CPU_OFFSET]
	msr	tpidr_el1, x0

	br	x9
END(lcpu_start)

ENTRY(set_bootstrap_cpu)
	/* Only one cpu can continue executing as the primary core */
	ldr	x1, =bootstrap_cpu_record

	/* Store primary core's hardware ID
	 * But before that, convert it into format like aff3/aff2/aff1/aff0
	 */
	mrs	x2, mpidr_el1
	mov	w3, w2
	and	x3, x3, #MPIDR_AFF2_MASK|MPIDR_AFF1_MASK|MPIDR_AFF0_MASK
	and	x2, x2, #MPIDR_AFF3_MASK
	orr	x3, x3, x2, LSR #MPIDR_AFF3_SHIFT
	ldr	x2, =BOOTSTRAP_CPU_PHYSICAL_ID_OFFSET
	add	x4, x1, x2
	str	x3, [x4]

	ret
END(set_bootstrap_cpu)
