/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#include <uk/plat/offset.h>
#include <uk/syscall.h>

.macro EXCHANGE_SP_WITH_X0
	add sp, sp, x0	// new_sp = sp + x0
	sub x0, sp, x0	// new_x0 = new_sp - x0 = sp + x0 - x0 = sp
	sub sp, sp, x0	// new_sp = new_sp - new_x0 = sp + x0 - sp = x0
.endm

.macro SAVE_REGS

	/* Save general purpose registers */
	stp	x0, x1, [sp, #16 * 0]
	stp	x2, x3, [sp, #16 * 1]
	stp	x4, x5, [sp, #16 * 2]
	stp	x6, x7, [sp, #16 * 3]
	stp	x8, x9, [sp, #16 * 4]
	stp	x10, x11, [sp, #16 * 5]
	stp	x12, x13, [sp, #16 * 6]
	stp	x14, x15, [sp, #16 * 7]
	stp	x16, x17, [sp, #16 * 8]
	stp	x18, x19, [sp, #16 * 9]
	stp	x20, x21, [sp, #16 * 10]
	stp	x22, x23, [sp, #16 * 11]
	stp	x24, x25, [sp, #16 * 12]
	stp	x26, x27, [sp, #16 * 13]
	stp	x28, x29, [sp, #16 * 14]

	/* Save LR and exception PC */
	mrs	x21, elr_el1
	stp	x30, x21, [sp, #16 * 15]

	/* Save pstate and exception status register */
	mrs	x22, spsr_el1
	mrs	x23, esr_el1
	stp	x22, x23, [sp, #16 * 16]
.endm

.macro RESTORE_REGS

	/* Restore pstate and exception status register */
	ldp	x22, x23, [sp, #16 * 16]
	msr	spsr_el1, x22
	msr	esr_el1, x23

	/* Restore LR and exception PC */
	ldp	x30, x21, [sp, #16 * 15]
	msr	elr_el1, x21

	/* Restore general purpose registers */
	ldp	x28, x29, [sp, #16 * 14]
	ldp	x26, x27, [sp, #16 * 13]
	ldp	x24, x25, [sp, #16 * 12]
	ldp	x22, x23, [sp, #16 * 11]
	ldp	x20, x21, [sp, #16 * 10]
	ldp	x18, x19, [sp, #16 * 9]
	ldp	x16, x17, [sp, #16 * 8]
	ldp	x14, x15, [sp, #16 * 7]
	ldp	x12, x13, [sp, #16 * 6]
	ldp	x10, x11, [sp, #16 * 5]
	ldp	x8, x9, [sp, #16 * 4]
	ldp	x6, x7, [sp, #16 * 3]
	ldp	x4, x5, [sp, #16 * 2]
	ldp	x2, x3, [sp, #16 * 1]
	ldp	x0, x1, [sp, #16 * 0]
.endm

/*
 * Maintain interrupt nesting level.
 *
 * Input
 *   flag: 0 increase nesting level, 1 decrease nesting level
 * returns
 *   reg0: lcpu
 *   reg1: old interrupt nesting level
 *   reg2: new interrupt nesting level
 */
.macro MATNTAIN_IRQ_FLAG reg0, reg1, reg2, flag
	mrs	\reg0, tpidr_el1
	ldr	\reg1, [\reg0, #LCPU_INTERRUPT_NESTED_OFFSET]
	.if \flag == 0
		add	\reg2, \reg1, #1
	.else
		sub	\reg2, \reg1, #1
	.endif
	str	\reg2, [\reg0, #LCPU_INTERRUPT_NESTED_OFFSET]
.endm

/*  Independent stack area:
 *  CPU_EXCEPT_STACK_SIZE  CPU_EXCEPT_STACK_SIZE
 * <---------------------><--------------------->
 * |============================================|
 * |                     |                      |
 * |       trap stack    |        IRQ stack     |
 * |                     |                      |
 * |=============================================
 */
.macro SAVE_IRQ_CONTEXT reg_to_save_ctx_addr
	/* Use TPIDRRO_EL0 as scratch register. It is fine to do so because
	 * it will always hold a value the application can't modify and we will
	 * always be able to restore it to its desired known value anytime we
	 * want. Thus, temporarily store x0.
	 */
	msr	tpidrro_el0, x0
	mov	x0, sp
	sub	sp, sp, #__TRAP_STACK_SIZE
	str	x0, [sp, #__SP_OFFSET]
	mrs	x0, tpidrro_el0
	SAVE_REGS
	/* must modify reg after context saved */
	mov	\reg_to_save_ctx_addr, sp
.endm

.macro SAVE_SYNC_CONTEXT
	msr	tpidrro_el0, x0

	/* Is this trap a system call? */
	mrs	x0, esr_el1
	and	x0, x0, #ESR_EC_MASK
	orr	x0, xzr, x0, lsr #ESR_EC_SHIFT
	cmp	x0, #ESR_EL1_EC_SVC64
	/* Load exception stack pointer */
	mrs	x0, tpidr_el1
	ldr	x0, [x0, #LCPU_EXCEPTION_SP_OFFSET]
	bne	2f
1:
	/* NOTE: We should normally align the stack before doing this
	 * subtraction because we must ensure that the `ectx` field
	 * is aligned to the corresponding ECTX alignment.
	 */
	sub	x0, x0, #UK_SYSCALL_CTX_SIZE
	b	3f
2:
	sub	x0, x0, #__TRAP_STACK_SIZE
3:
	EXCHANGE_SP_WITH_X0
	/* Store old SP in exception stack */
	str	x0, [sp, #__SP_OFFSET]
	/* Restore x0 */
	mrs	x0, tpidrro_el0
	SAVE_REGS
.endm

.macro RESTORE_IRQ_CONTEXT
	/* x19 <- lcpu,
	 * w1 <- old interrupt nesting level,
	 * w2 <- new interrupt nesting level
	 */
	MATNTAIN_IRQ_FLAG x19, w1, w2, 1
	cbnz	w2, restore

	/* Any pending secheduling request? */
	ldrb	w1, [x19, #LCPU_PENGDING_SWITCH_OFFSET]

	/* Switch to thread stack */
	ldr x0, [sp]
	mov	sp, x0
	cbz	w1, restore

exit_irq_with_ctx_switch:
	/* clear pending switch flag */
	ldr	x20, [x19, #LCPU_PENGDING_SWITCH_OFFSET]
	sub	x20, x20, #1
	str	x20, [x19, #LCPU_PENGDING_SWITCH_OFFSET]
#ifdef CONFIG_HAVE_SCHED
	/* Get current thread */
	ldr	x20, [x19, #LCPU_CURRENT_THREAD_OFFSET]
	mov	x0, x20
	/* tn_sched_next_to_run return best thread */
	bl	tn_sched_next_to_run
	/* Best thread is current one? */
	cmp	x0, x20
	b.eq	restore
	mov	x1, x0
	mov	x0, x20
	mov	x2, #1
	ldr	x4, =tn_sched_thread_switch
#else
	/* This context-switching API is typically used
	 * only in scenarios without a scheduler,
	 * where secondary cores wake up and switch to user-defined threads.
	 * It is not recommended for use in other scenarios.
	 */
	ldr	x4, =lcpu_switch_to
#endif
	br x4
restore:
	RESTORE_REGS

	/* Restore old thread sp */
	add	sp, sp, #__TRAP_STACK_SIZE
	eret

.endm

/*
 * Switch to the interrupt stack.
 *
 * inputs:
 *   reg_of_lcpu: Register holding the address of lcpu.
 *   tmp_reg0: Temporary register used to store the current stack pointer.
 *   tmp_reg1: Temporary register used to load the interrupt stack pointer.
 */
.macro SWITCH_TO_INTERRUPT_SP reg_of_lcpu, tmp_reg0, tmp_reg1
	ldr	\tmp_reg1, [\reg_of_lcpu, #LCPU_INTERRUPT_SP_OFFSET]
	/* record old sp */
	mov	\tmp_reg0, sp
	/* switch to new sp */
	mov	sp, \tmp_reg1
	/* store the old sp on interrupt stack,
	 * the old sp is needed when switching back to thread stack
	 */
	str	\tmp_reg0, [sp, #-16]!
.endm

/* Bad Abort numbers */
#define BAD_SYNC  0
#define BAD_IRQ   1
#define BAD_FIQ   2
#define BAD_ERROR 3

/**
 * TODO:
 * Here we use SAVE_SYNC_CONTEXT for forward compatibility.
 * Change this behavior when we determined which stack to use for invalid exception.
 */
#define el_invalid(name, reason, el)	\
.align 6;				\
name##_invalid:				\
	SAVE_SYNC_CONTEXT;		\
	mov x0, sp;			\
	mov x1, el;			\
	mov x2, #(reason);		\
	mrs x3, far_el1;		\
	b   invalid_trap_handler;	\
ENDPROC(name##_invalid);		\

el_invalid(el1_sync, BAD_SYNC, 1);
el_invalid(el0_sync, BAD_SYNC, 0);
el_invalid(el1_irq, BAD_IRQ, 1);
el_invalid(el0_irq, BAD_IRQ, 0);
el_invalid(el1_fiq, BAD_FIQ, 1);
el_invalid(el0_fiq, BAD_FIQ, 0);
el_invalid(el1_error, BAD_ERROR, 1);
el_invalid(el0_error, BAD_ERROR, 0);

/*
 * Macro for Exception vectors.
 */
.macro	ventry	label
.align	7
b	\label
.endm

/*
 * Exception vectors.
 */
.align	11
.globl vectors_el1
vectors_el1:
	ventry el1_sync_invalid			/* Synchronous EL1t       */
	ventry el1_irq_invalid			/* IRQ EL1t               */
	ventry el1_fiq_invalid			/* FIQ EL1t               */
	ventry el1_error_invalid		/* Error EL1t             */

	ventry el1_sync				/* Synchronous EL1h       */
	ventry el1_irq				/* IRQ EL1h               */
	ventry el1_fiq_invalid			/* FIQ EL1h               */
	ventry el1_error_invalid		/* Error EL1h             */

	ventry el0_sync_invalid			/* Synchronous 64-bit EL0 */
	ventry el0_irq_invalid			/* IRQ 64-bit EL0         */
	ventry el0_fiq_invalid			/* FIQ 64-bit EL0         */
	ventry el0_error_invalid		/* Error 64-bit EL0       */

	ventry el0_sync_invalid			/* Synchronous 32-bit EL0 */
	ventry el0_irq_invalid			/* IRQ 32-bit EL0         */
	ventry el0_fiq_invalid			/* FIQ 32-bit EL0         */
	ventry el0_error_invalid		/* Error 32-bit EL0       */

.align 6
el1_sync:
	SAVE_SYNC_CONTEXT
	mov	x0, sp
	mrs	x1, FAR_EL1
	bl	trap_el1_sync
	RESTORE_REGS
	/* Restore stack pointer for exception from EL1 */
	msr	tpidrro_el0, x0
	ldr	x0, [sp, #__SP_OFFSET]
	mov	sp, x0
	mrs	x0, tpidrro_el0
	eret

.align 6
el1_irq:
	/* x0 = __regs, the address of the saved context,
	 * will be used as argument of trap_el1_irq, don't modify it!
	 */
	SAVE_IRQ_CONTEXT x0

	/* x3 <- lcpu,
	 * w1 <- old interrupt nesting level,
	 * w2 <- new interrupt nesting level
	 */
	MATNTAIN_IRQ_FLAG x3, w1, w2, 0

	/*
	 * If there is no nested interrupt, need to switch from thread sp to
	 * interrupt sp, otherwize call trap_el1_irq
	 */
	cbnz	w1, do_trap

	/* x3: lcpu,
	 * x1/x2: temporary registers
	 */
	SWITCH_TO_INTERRUPT_SP x3, x1, x2

do_trap:
	bl	trap_el1_irq
	RESTORE_IRQ_CONTEXT
