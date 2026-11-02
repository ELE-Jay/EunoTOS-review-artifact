#include "rst_def.h"
#include "rst_ipc.h"
#include <zephyr/kernel.h>

/* 定义互斥锁 */
K_MUTEX_DEFINE(rst_mutex);

/* 创建互斥锁 */
rst_sem_id rst_mutex_create(uint32_t value)
{
	/* Zephyr中不需要显式地创建互斥锁 */
	return &rst_mutex;
}

/* 申请互斥锁 */
rst_status rst_mutex_lock(rst_sem_id mutex, rst_time_t timeout)
{
	/* 在Zephyr中使用 k_mutex_lock 函数来申请互斥锁 */
	k_timeout_t zephyr_timeout = K_FOREVER;

	if (timeout != RST_WAIT_FOREVER) {
		zephyr_timeout = K_MSEC(timeout);
	}

	int result = k_mutex_lock((struct k_mutex *)mutex, zephyr_timeout);
	return result == 0 ? RST_OK : RST_ERROR;
}

/* 释放互斥锁 */
rst_status rst_mutex_unlock(rst_sem_id mutex)
{
	/* 在Zephyr中使用 k_mutex_unlock 函数来释放互斥锁 */
	int result = k_mutex_unlock((struct k_mutex *)mutex);
	return result == 0 ? RST_OK : RST_ERROR;
}

/* 删除互斥锁 */
void rst_mutex_delete(rst_sem_id mutex)
{
	/* 在Zephyr中不需要显式地删除互斥锁 */
}
