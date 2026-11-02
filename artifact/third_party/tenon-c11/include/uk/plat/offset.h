/* Copyright 2024 Hangzhou Yingyi Technology Co., Ltd
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

#ifndef __UKPLAT_OFFSET_H__
#define __UKPLAT_OFFSET_H__

#include <uk/config.h>
#include <uk/essentials.h>
#include <uk/arch/lcpu.h>

#ifndef LCPU_ARCH_SIZE
#define LCPU_ARCH_SIZE 0x00
#endif /* !LCPU_ARCH_SIZE */

/*
 * LCPU Startup Arguments Offset
 */
#define BOOT_ARGS_SARGS_ENTRY_OFFSET 0x00
#define BOOT_ARGS_SARGS_STACKP_OFFSET (BOOT_ARGS_SARGS_ENTRY_OFFSET + 0x08)
#define BOOT_ARGS_SARGS_CPU_OFFSET (BOOT_ARGS_SARGS_STACKP_OFFSET + 0x08)
#define BOOT_ARGS_ERR_OFFSET (BOOT_ARGS_SARGS_ENTRY_OFFSET + 0X00)
#ifdef CONFIG_HAVE_SMP
#define BOOT_ARGS_FUNC_OFFSET (BOOT_ARGS_SARGS_ENTRY_OFFSET + 0X00)
#endif /* CONFIG_HAVE_SMP */

/*
 * Logical CPU (LCPU) Offset
 */
#define LCPU_CURRENT_THREAD_OFFSET 0x00
#define LCPU_CRITICAL_NESTED_OFFSET (LCPU_CURRENT_THREAD_OFFSET + 0x08)
#define LCPU_INTERRUPT_NESTED_OFFSET (LCPU_CRITICAL_NESTED_OFFSET + 0x04)
#define LCPU_EXCEPTION_SP_OFFSET (LCPU_INTERRUPT_NESTED_OFFSET + 0x04)
#define LCPU_INTERRUPT_SP_OFFSET (LCPU_EXCEPTION_SP_OFFSET + 0x08)
#ifdef CONFIG_HAVE_SCHED
#define LCPU_IDLE_OFFSET (LCPU_INTERRUPT_SP_OFFSET + 0x08)
#define LCPU_PENGDING_SWITCH_OFFSET (LCPU_IDLE_OFFSET + 0x08)
#else
#define LCPU_SWITCH_TO_OFFSET (LCPU_INTERRUPT_SP_OFFSET + 0x08)
#define LCPU_SWITCH_BACK_OFFSET (LCPU_INTERRUPT_SP_OFFSET + 0x08)
#define LCPU_PENGDING_SWITCH_OFFSET (LCPU_SWITCH_TO_OFFSET + 0x08)
#endif
#define LCPU_ID_OFFSET (LCPU_PENGDING_SWITCH_OFFSET + 0x04)
#define LCPU_PHYSICAL_ID_OFFSET (LCPU_ID_OFFSET + 0x04)
#define LCPU_STATE_OFFSET (LCPU_PHYSICAL_ID_OFFSET + 0x08)
#define LCPU_ARCH_OFFSET (LCPU_STATE_OFFSET + 0x04)

#define LCPU_MEMBERS_SIZE (LCPU_ARCH_OFFSET + LCPU_ARCH_SIZE)
#define LCPU_SIZE ALIGN_UP(LCPU_MEMBERS_SIZE, CACHE_LINE_SIZE)

/*
 * Thread Control Block Offset
 */
#ifdef CONFIG_HAVE_SCHED
#define UK_THREAD_AUXSP_OFFSET 0x38
#else
#define UK_THREAD_AUXSP_OFFSET 0x28
#endif

/*
 * Bootstrap CPU Arguments Offset
 */
#define BOOTSTRAP_CPU_PHYSICAL_ID_OFFSET 0x00

#endif /* __UKPLAT_LCPU_H__ */
