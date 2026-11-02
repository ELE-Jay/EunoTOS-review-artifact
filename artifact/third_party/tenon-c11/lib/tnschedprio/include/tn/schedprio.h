/* Copyright 2023 Hangzhou Yingyi Technology Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Preemptive priority scheduler.
 */

#ifndef __TN_SCHEDPRIO_H__
#define __TN_SCHEDPRIO_H__

#include <uk/sched.h>
#include <uk/alloc.h>

#ifdef __cplusplus
extern "C" {
#endif

void tn_sched_thread_set_priority(struct uk_thread *thread, int32_t priority);

struct uk_thread *
tn_sched_thread_create_prio(struct uk_sched *s, uk_thread_fn1_t fn, void *argp,
							size_t stack_len, size_t auxstack_len,
							bool no_uktls, bool no_ectx, const char *name,
							int32_t prio, void *priv, uk_thread_dtor_t dtor);

struct uk_sched *tn_schedprio_create(struct uk_alloc *a);

#ifdef __cplusplus
}
#endif

#endif /* __TN_SCHEDPRIO_H__ */
