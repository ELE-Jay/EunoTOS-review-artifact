#include "rst_def.h"
#include "rst_ipc.h"
#include "rtthread.h"

rst_status rst_task_create(rst_task_id *task, rst_task_func func,
                           void *arg, rst_task_attr *attr)
{
    *task = (rst_task_id)rt_thread_create(attr->name, func, arg, attr->stack_size, attr->priority, 5);
    rt_thread_startup(*task);
    return RST_OK;
}

rst_status rst_task_suspend(rst_task_id task)
{
    rt_thread_suspend((rt_thread_t)task);
    rt_schedule();
    return RST_OK;
}

rst_status rst_task_resume(rst_task_id task)
{
    rt_thread_resume((rt_thread_t)task);
    rt_schedule();
    return RST_OK;
}

void rst_task_delete(rst_task_id task)
{
    if(task == NULL)
    {
        return;
    }
    rt_thread_delete((rt_thread_t)task);
}

rst_task_id rst_get_current_task(void)
{
	return rt_thread_self();
}

void rst_set_task_priority(rst_task_id task, uint32_t priority)
{
	rt_thread_control(task, RT_THREAD_CTRL_CHANGE_PRIORITY, &priority);
}

void rst_task_sleep(uint64_t ticks)
{
    rt_thread_delay(ticks);
}
