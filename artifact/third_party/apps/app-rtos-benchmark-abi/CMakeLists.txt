# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(performance_test)

target_sources(app PRIVATE main.c)

target_sources(app PRIVATE src/rst_interrupt_latency.c)

target_sources(app PRIVATE src/rst_semaphore_shuffle.c)

target_sources(app PRIVATE src/rst_task_preempt.c)

target_sources(app PRIVATE src/rst_task_switch.c)

target_sources(app PRIVATE src/rst_task_switch_multi_threaded.c)

target_sources(app PRIVATE src/rst_set_timer_offset.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_isr.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_task.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_sem.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_mutex.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_yield.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_irq.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_reschedule.c)

target_sources(app PRIVATE adapter/os/zephyr/rst_tick.c)

target_sources(app PRIVATE adapter/time/armcycle/rst_time.c)

target_include_directories(app PRIVATE include)
