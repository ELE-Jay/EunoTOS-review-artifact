
#include "rst_def.h"
#include "rst_ipc.h"

#include <zephyr/kernel.h>

rst_status rst_task_yield(void) {
  k_yield();
  return RST_OK;
}
