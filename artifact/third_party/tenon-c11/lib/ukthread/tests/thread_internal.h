/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */
#ifndef __UK_THREAD_INTERNAL_H__
#define __UK_THREAD_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <uk/thread.h>

void uk_thread_container_init_bare(struct uk_thread *t, uintptr_t ip);

void uk_thread_container_init_fn0(struct uk_thread *t, uk_thread_fn0_t fn);

void uk_thread_container_init_fn1(struct uk_thread *t, uk_thread_fn1_t fn,
								  void *argp);

void uk_thread_container_init_fn2(struct uk_thread *t, uk_thread_fn2_t fn,
								  void *argp0, void *argp1);

#ifdef __cplusplus
}
#endif

#endif /* __UK_THREAD_INTERNAL_H__ */
