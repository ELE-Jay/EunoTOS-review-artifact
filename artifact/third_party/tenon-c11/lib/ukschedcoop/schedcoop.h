/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */
#ifndef __UK_SCHEDCOOP_SCHEDCOOP_H__
#define __UK_SCHEDCOOP_SCHEDCOOP_H__

#include <uk/schedcoop.h>

struct schedcoop {
	struct uk_sched sched;
	struct uk_thread_list run_queue;

	__nsec ts_prev_switch;
};

static inline int schedcoop_prio_cmp(struct uk_thread *t1 __unused,
									 struct uk_thread *t2 __unused)
{
	return 0;
}

static inline struct schedcoop *uksched2schedcoop(struct uk_sched *s)
{
	UK_ASSERT(s);

	return __containerof(s, struct schedcoop, sched);
}

#endif /* __UK_SCHEDCOOP_SCHEDCOOP_H__ */
