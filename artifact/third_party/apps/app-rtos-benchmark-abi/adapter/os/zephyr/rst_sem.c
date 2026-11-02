#include "rst_def.h"
#include "rst_ipc.h"

rst_sem_id rst_sem_create(uint32_t value)
{
	static K_SEM_DEFINE(rst_sem, 1, 1); // 初始化一个信号量
	return (rst_sem_id)&rst_sem;
}

rst_status rst_sem_lock(rst_sem_id sem, rst_time_t timeout)
{
	if (k_sem_take((struct k_sem *)sem, K_MSEC(timeout)) == 0) {
		return RST_OK;
	} else {
		return RST_ERROR; // 超时返回错误状态
	}
}

rst_status rst_sem_unlock(rst_sem_id sem)
{
	k_sem_give((struct k_sem *)sem);
	return RST_OK;
}

void rst_sem_delete(rst_sem_id sem) {}
