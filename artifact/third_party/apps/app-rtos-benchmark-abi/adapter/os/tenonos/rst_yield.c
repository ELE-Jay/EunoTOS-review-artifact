#include <uk/sched.h>

#include "rst_def.h"
#include "rst_ipc.h"

rst_status rst_task_yield(void) {
  uk_sched_yield();
  return RST_OK;
}
