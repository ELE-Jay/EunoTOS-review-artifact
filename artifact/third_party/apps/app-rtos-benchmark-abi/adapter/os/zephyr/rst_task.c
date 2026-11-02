#include "rst_def.h"
#include "rst_ipc.h"
#include "rst_cfg.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/irq_offload.h>
#include <zephyr/kernel_structs.h>

typedef void (*zephyr_task_func)(void *, void *, void *);
rst_status rst_task_create(rst_task_id *task, rst_task_func func, void *arg,
			   rst_task_attr *attr)
{
	struct k_thread *zephyr_thread_data = k_malloc(sizeof(struct k_thread));
	k_thread_stack_t *stack = k_malloc(RST_TASK_STACK_SIZE);
	*task = (rst_task_id)k_thread_create(
	    zephyr_thread_data, stack, RST_TASK_STACK_SIZE,
	    (zephyr_task_func)func, NULL, NULL, NULL, attr->priority, 0,
	    K_NO_WAIT);
	return RST_OK;
}

rst_status rst_task_suspend(rst_task_id task)
{
	k_thread_suspend((k_tid_t)task);
	return RST_OK;
}

rst_status rst_task_resume(rst_task_id task)
{
	k_thread_resume((k_tid_t)task);
	return RST_OK;
}

void rst_task_delete(rst_task_id task)
{
	if (task == NULL) {
		return;
	}
	k_thread_abort((k_tid_t)task);
}

rst_task_id rst_get_current_task(void)
{
	return k_current_get();
}

void rst_set_task_priority(rst_task_id task, uint32_t priority)
{
	k_thread_priority_set(task, priority);
}

void rst_task_sleep(uint64_t ticks)
{
	z_impl_k_sleep(Z_TIMEOUT_TICKS(ticks));
}
