#include <tn/schedprio.h>
#include <uk/sched.h>
#include <uk/thread.h>

#include "rst_def.h"
#include "rst_ipc.h"

rst_status rst_task_create(rst_task_id *task, rst_task_func func, void *arg,
                           rst_task_attr *attr) {
  *task = (rst_task_id)uk_thread_create_prio_fn1(
      uk_alloc_get_default(), func, arg, uk_alloc_get_default(),
      attr->stack_size, uk_alloc_get_default(), 0, NULL,
      false, attr->name, attr->priority, NULL, NULL);

  if (*task == NULL || uk_sched_thread_add(uk_sched_get(), *task) != 0) {
    RST_LOGE("RST: task create failed");
    return RST_ERROR;
  }

  return RST_OK;
}

rst_status rst_task_suspend(rst_task_id task) {
  uk_sched_thread_blocked((struct uk_thread *)task, 0);
  uk_sched_reschedule();
  return RST_OK;
}

rst_status rst_task_resume(rst_task_id task) {
  uk_sched_thread_woken((struct uk_thread *)task);
  uk_sched_reschedule();
  return RST_OK;
}

void rst_task_delete(rst_task_id task) {
  if (task == NULL) {
    uk_sched_thread_exit();
  }
  uk_sched_thread_terminate((struct uk_thread *)task);
}

rst_task_id rst_get_current_task(void)
{
	return uk_thread_current();
}

void rst_set_task_priority(rst_task_id task, uint32_t priority)
{
	tn_sched_thread_set_priority(task, priority);
}

void rst_task_sleep(uint64_t ticks) {
	uk_sched_thread_sleep_tick(ticks);
}
