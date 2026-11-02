#include <uk/semaphore.h>

#include "rst_def.h"
#include "rst_ipc.h"

rst_sem_id rst_sem_create(uint32_t value) {
  struct uk_semaphore* sem = malloc(sizeof(struct uk_semaphore));
  uk_semaphore_init(sem, (long)value);
  return (rst_sem_id)sem;
}

rst_status rst_sem_lock(rst_sem_id sem, rst_time_t timeout) {
  uk_semaphore_down_to((struct uk_semaphore *)sem, timeout);
  return RST_OK;
}

rst_status rst_sem_unlock(rst_sem_id sem) {
  uk_semaphore_up((struct uk_semaphore *)sem);
  return RST_OK;
}

void rst_sem_delete(rst_sem_id sem) {}


