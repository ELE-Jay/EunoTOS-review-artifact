/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#ifndef _TN_ENTRY_H
#define _TN_ENTRY_H

#include <uk/plat/lcpu.h>
#include <uk/assert.h>
#include <uk/thread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uk_thread_fn0_t tn_lcpu_entry_fn0_t;

typedef struct tn_lcpu_entry_fn1 {
	uk_thread_fn1_t entry;
	void *argp;
} tn_lcpu_entry_fn1_t;

typedef struct tn_lcpu_entry_fn2 {
	uk_thread_fn2_t entry;
	void *argp0;
	void *argp1;
} tn_lcpu_entry_fn2_t;

typedef enum entry_type {
	ENTRY_NO_ARG,
	ENTRY_ARG_ONE,
	ENTRY_ARG_TWO,
} entry_type_t;

typedef union entrypoint {
	tn_lcpu_entry_fn0_t fn0;
	tn_lcpu_entry_fn1_t fn1;
	tn_lcpu_entry_fn2_t fn2;
} entrypoint_t;

struct tn_lcpu_entry {
	/* Entry point structure for the CPU */
	entrypoint_t ep;
	/* Entry point structure type, supports up to 2 parameters */
	entry_type_t type;
	/* Logical CPU ID */
	__lcpuid cpu_id;
	/* Number of logical CPUs starting from cpu_id*/
	uint32_t num;
};

/**
 * Register a user-defined cpu entry function,
 * that is called by each cpu after booting-up are finished.
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn0_t'
 *   containing the CPU entry that take no arguments.
 * @param lcpu_id
 *   Logical CPU ID
 * @param lcpu_num
 *   Logical CPU number, number of cpus
 *   counting from lcpu_id that use the same entrypoint
 */
#define __TN_ENTRYTAB_FN0(entry_fn, lcpu_id, lcpu_num)			\
	static const struct tn_lcpu_entry				\
	__used __section(".tn_entrytab" #lcpu_id) __align(8)		\
	__tn_entrytab_ ## lcpu_id = {					\
		.ep.fn0 = (entry_fn),					\
		.type = ENTRY_NO_ARG,					\
		.cpu_id = (lcpu_id),					\
		.num = (lcpu_num)					\
	}

/**
 * Register a user-defined cpu entry function,
 * that is called by each cpu after booting-up are finished.
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn1_t'
 *   containing the CPU entry that take one arguments.
 * @param lcpu_id
 *   Logical CPU ID
 * @param func_argp
 *   user-defined function argument
 * @param lcpu_num
 *   Logical CPU number, number of cpus
 *   counting from lcpu_id that use the same entrypoint
 */
#define __TN_ENTRYTAB_FN1(entry_fn, func_argp, lcpu_id, lcpu_num)	\
	static const struct tn_lcpu_entry				\
	__used __section(".tn_entrytab" #lcpu_id) __align(8)		\
	__tn_entrytab_ ## lcpu_id = {					\
		.ep.fn1.entry = (entry_fn),				\
		.ep.fn1.argp = (func_argp),				\
		.type = ENTRY_ARG_ONE,					\
		.cpu_id = (lcpu_id),					\
		.num = (lcpu_num)					\
	}

/**
 * Register a user-defined cpu entry function,
 * that is called by each cpu after booting-up are finished.
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn2_t'
 *   containing the CPU entry that take two arguments.
 * @param lcpu_id
 *   Logical CPU ID
 * @param func_argp0
 *   user-defined function argument 0
 * @param func_argp1
 *   user-defined function argument 1
 * @param lcpu_num
 *   Logical CPU number, number of cpus
 *   counting from lcpu_id that use the same entrypoint
 */
#define __TN_ENTRYTAB_FN2(entry_fn, func_argp0, func_argp1, lcpu_id, lcpu_num)\
	static const struct tn_lcpu_entry				\
	__used __section(".tn_entrytab" #lcpu_id) __align(8)		\
	__tn_entrytab_ ## lcpu_id = {					\
		.ep.fn2.entry = (entry_fn),				\
		.ep.fn2.argp0 = (func_argp0),				\
		.ep.fn2.argp1 = (func_argp1),				\
		.type = ENTRY_ARG_TWO,					\
		.cpu_id = (lcpu_id),					\
		.num = (lcpu_num)					\
	}

/**
 * Register the entry function to the specified single logical cpu.
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn0_t'
 *   containing the CPU entry that take no arguments.
 * @param lcpu_id
 *   Logical CPU ID
 */
#define tn_lcpu_entrypoint_fn0_register(entry_fn, lcpu_id)	\
	do {							\
		UK_ASSERT((lcpu_id) < (int)ukplat_lcpu_count());	\
		__TN_ENTRYTAB_FN0(entry_fn, lcpu_id, 1);		\
	} while (0)

/**
 * Register the entry function to the specified single logical cpu.
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn1_t'
 *   containing the CPU entry that take one arguments.
 * @param lcpu_id
 *   Logical CPU ID
 * @param argp
 *   user-defined function argument
 */
#define tn_lcpu_entrypoint_fn1_register(entry_fn, argp, lcpu_id)	\
	do {							\
		UK_ASSERT((lcpu_id) < (int)ukplat_lcpu_count());	\
		__TN_ENTRYTAB_FN1(entry_fn, argp, lcpu_id, 1);		\
	} while (0)

/**
 * Register the entry function to the specified single logical cpu.
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn2_t'
 *   containing the CPU entry that take two arguments.
 * @param argp0
 *   user-defined function argument 0
 * @param argp1
 *   user-defined function argument 1
 * @param lcpu_id
 *   Logical CPU ID
 */
#define tn_lcpu_entrypoint_fn2_register(entry_fn, argp0, argp1, lcpu_id)\
	do {							\
		UK_ASSERT((lcpu_id) < (int)ukplat_lcpu_count());	\
		__TN_ENTRYTAB_FN2(entry_fn, argp0, argp1, lcpu_id, 1);	\
	} while (0)

/**
 * register the same entry function for the specified consecutive N CPUs
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn0_t'
 *   containing the CPU entry that take no arguments.
 * @param lcpu_id
 *   logical CPU ID
 * @param num
 *   Logical CPU number, number of cpus
 *   counting from lcpu_id that use the same entrypoint
 */
#define tn_multi_lcpu_entrypoint_fn0_register(entry_fn, lcpu_id, num)	\
	do {	\
		UK_ASSERT(((lcpu_id) + (num) - 1) <			\
				(int)ukplat_lcpu_count());		\
		__TN_ENTRYTAB_FN0(entry_fn, lcpu_id, num);		\
	} while (0)

/**
 * register the same entry function for the specified consecutive N CPUs
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn1_t'
 *   containing the CPU entry that take one arguments.
 * @param argp
 *   user-defined function argument
 * @param lcpu_id
 *   logical CPU ID
 * @param num
 *   Logical CPU number, number of cpus
 *   counting from lcpu_id that use the same entrypoint
 */
#define tn_multi_lcpu_entrypoint_fn1_register(entry_fn, argp, lcpu_id, num)\
	do {	\
		UK_ASSERT(((lcpu_id) + (num) - 1) <			\
				(int)ukplat_lcpu_count());		\
		__TN_ENTRYTAB_FN1(entry_fn, argp, lcpu_id, num);	\
	} while (0)

/**
 * register the same entry function for the specified consecutive N CPUs
 *
 * @param entry_fn
 *   Pointer to a structure 'tn_lcpu_entry_fn2_t'
 *   containing the CPU entry that take two arguments.
 * @param argp0
 *   user-defined function argument 0
 * @param argp1
 *   user-defined function argument 1
 * @param lcpu_id
 *   logical CPU ID
 * @param num
 *   Logical CPU number, number of cpus
 *   counting from lcpu_id that use the same entrypoint
 */
#define tn_multi_lcpu_entrypoint_fn2_register(entry_fn,	\
				argp0, argp1, lcpu_id, num)\
	do {	\
		UK_ASSERT(((lcpu_id) + (num) - 1) <			\
				(int)ukplat_lcpu_count());		\
		__TN_ENTRYTAB_FN2(entry_fn, argp0, argp1, lcpu_id, num);\
	} while (0)

/**
 * Helper macro for iterating over entrytab tables
 * Please note that the table may contain NULL pointer entries
 *
 * @param itr
 *   Iterator variable (struct tn_lcpu_entry *) which points to the
 *   individual table entries during iteration
 * @param entrytab_start
 *   Start address of table (type: const struct tn_lcpu_entry[])
 * @param entrytab_end
 *   End address of table (type: const struct tn_lcpu_entry)
 */
#define tn_entrytab_foreach(itr, entrytab_start, entrytab_end)		\
	for ((itr) = DECONST(struct tn_lcpu_entry *, entrytab_start);\
		(itr) < &(entrytab_end);				\
		(itr)++)

extern const struct tn_lcpu_entry tn_entrytab_start[];
extern const struct tn_lcpu_entry tn_entrytab_end;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*  _TN_ENTRY_H */

