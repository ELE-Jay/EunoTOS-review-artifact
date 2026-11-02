#include <uk/sched.h>

#include "rst_def.h"
#include "rst_ipc.h"

rst_status rst_task_reschedule(void) {
  uk_sched_reschedule();
  return RST_OK;
}
