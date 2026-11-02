/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Sharan Santhanam <sharan.santhanam@neclab.eu>
 *          Simon Kuenzer <simon@unikraft.io>
 *
 * Copyright (c) 2019, NEC Europe Ltd., NEC Corporation. All rights reserved.
 * Copyright (c) 2022, Unikraft GmbH. All rights reserved.
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
#ifndef _UK_INIT_H
#define _UK_INIT_H

#include <uk/config.h>
#include <uk/plat/bootstrap.h>
#include <uk/essentials.h>
#include <uk/prio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uk_init_ctx {
	struct {
		int    argc;
		char **argv;
	} cmdline;

	/* reserved for future additions */
};

struct uk_term_ctx {
	enum ukplat_gstate target;

	/* reserved for future additions */
};

typedef int (*uk_init_func_t)(struct uk_init_ctx *);
typedef void (*uk_term_func_t)(const struct uk_term_ctx *);

struct uk_inittab_entry {
	uk_init_func_t init;
	uk_term_func_t term;
};

/**
 * Register a Unikraft init function that is
 * called during bootstrap (uk_inittab)
 *
 * @param fn
 *   Initialization function to be called
 * @param class
 *   Initialization class (1 (earliest) to 6 (latest))
 * @param prio
 *   Priority level (0 (earliest) to 9 (latest)), must be a constant.
 *   Use the UK_PRIO_AFTER() helper macro for computing priority dependencies.
 *   Note: Any other value for level will be ignored
 */
#define __UK_INITTAB_ENTRY(init_fn, term_fn, base, prio, ...)		\
	static const struct uk_inittab_entry				\
	__used __section(".uk_inittab" #base #prio __VA_ARGS__) __align(8)		\
		__uk_inittab ## base ## prio ## _ ## init_fn ## _ ## term_fn = {\
		.init = (init_fn),					\
		.term = (term_fn)					\
	}

#define _UK_INITTAB(init_fn, term_fn, base, prio)		\
	__UK_INITTAB_ENTRY(init_fn, term_fn, base, prio)

#define uk_initcall_class_prio(init_fn, term_fn, class, prio)	\
	_UK_INITTAB(init_fn, term_fn, class, prio)


#define uk_initcall_class_prio_critical(init_fn, term_fn, class, prio)	\
	__UK_INITTAB_ENTRY(init_fn, term_fn, class, prio, "~")
/*******************************************************************/
/* Define initializer running order                                */
/* NOTE: running order in the same CLASS and PRIORITY level is not */
/* guarented. This means every installed initializer must be in-  */
/* dependent with each other when both class and priority are same.*/
/*******************************************************************/

/* Stage for earlest initialization. If an initializer is depended by many
 * other initializers, and must run as earlest as possible, put it in this
 * class. USE WITH CAUTION.
 */
#define UK_INIT_CLASS_EARLY 1

/**
 * Stage for platform component initialization, like some bus abstraction.
 * 'Platform' here means some component functionality across the entire system,
 * NOT 'ukplat'.
 */
#define UK_INIT_CLASS_PLAT 2

/* Stage for performing per-lib initialization. */
#define UK_INIT_CLASS_LIB 3

/* Stage for filesystem initialization. */
#define UK_INIT_CLASS_ROOTFS 4

/* Stage for system software component initialization, like system environment
 * initializing.
 */
#define UK_INIT_CLASS_SYS 5

/* Stage for latest initialization. If an intializer should run only before
 * the main thread, put it in this class.
 */
#define UK_INIT_CLASS_LATE 6

/**
 * Interface to install initializers in specific class and priority level.
 */
#define uk_early_initcall_prio(init_fn, term_fn, prio)		\
	uk_initcall_class_prio(init_fn, term_fn, UK_INIT_CLASS_EARLY, prio)
#define uk_plat_initcall_prio(init_fn, term_fn, prio)		\
	uk_initcall_class_prio(init_fn, term_fn, UK_INIT_CLASS_PLAT, prio)
#define uk_lib_initcall_prio(init_fn, term_fn, prio)		\
	uk_initcall_class_prio(init_fn, term_fn, UK_INIT_CLASS_LIB, prio)
#define uk_rootfs_initcall_prio(init_fn, term_fn, prio)		\
	uk_initcall_class_prio(init_fn, term_fn, UK_INIT_CLASS_ROOTFS, prio)
#define uk_sys_initcall_prio(init_fn, term_fn, prio)		\
	uk_initcall_class_prio(init_fn, term_fn, UK_INIT_CLASS_SYS, prio)
#define uk_late_initcall_prio(init_fn, term_fn, prio)		\
	uk_initcall_class_prio(init_fn, term_fn, UK_INIT_CLASS_LATE, prio)

/**
 * Interface to install initializers with default priority.
 */
#define uk_early_initcall(init_fn, term_fn)			\
	uk_early_initcall_prio(init_fn, term_fn, UK_PRIO_LATEST)
#define uk_plat_initcall(init_fn, term_fn)			\
	uk_plat_initcall_prio(init_fn, term_fn, UK_PRIO_LATEST)
#define uk_lib_initcall(init_fn, term_fn)			\
	uk_lib_initcall_prio(init_fn, term_fn, UK_PRIO_LATEST)
#define uk_rootfs_initcall(init_fn, term_fn)			\
	uk_rootfs_initcall_prio(init_fn, term_fn, UK_PRIO_LATEST)
#define uk_sys_initcall(init_fn, term_fn)			\
	uk_sys_initcall_prio(init_fn, term_fn, UK_PRIO_LATEST)
#define uk_late_initcall(init_fn, term_fn)			\
	uk_late_initcall_prio(init_fn, term_fn, UK_PRIO_LATEST)

extern const struct uk_inittab_entry uk_inittab_start[];
extern const struct uk_inittab_entry uk_inittab_end;

/**
 * Helper macro for iterating over init pointer tables
 * Please note that the table may contain NULL pointer entries
 *
 * @param itr
 *   Iterator variable (struct uk_inittab_entry *) which points to the
 *   individual table entries during iteration
 * @param inittab_start
 *   Start address of table (type: const struct uk_inittab_entry[])
 * @param inittab_end
 *   End address of table (type: const struct uk_inittab_entry)
 */
#define uk_inittab_foreach(itr, inittab_start, inittab_end)		\
	for ((itr) = DECONST(struct uk_inittab_entry *, inittab_start);	\
	     (itr) < &(inittab_end);					\
	     (itr)++)

/*
 * Reverse iteration
 * NOTE: The reverse iteration is intended for calling the termination functions
 *       according to their priorities.
 */
#define uk_inittab_foreach_reverse(itr, inittab_start, inittab_end)	\
	for ((itr) = (DECONST(struct uk_inittab_entry *,		\
			      (&(inittab_end)))) - 1);			\
	     (itr) >= DECONST(struct uk_inittab_entry *, inittab_start); \
	     (itr)--)

/*
 * Start reverse iteration from itr
 * NOTE: Iteration includes itr start position.
 */
#define uk_inittab_foreach_reverse2(itr, inittab_start)			\
	for (;								\
	     (itr) >= DECONST(struct uk_inittab_entry *, inittab_start); \
	     (itr)--)

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _UK_INIT_H */
