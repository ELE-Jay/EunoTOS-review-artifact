#include "rst.h"
#include "rst_ipc.h"
#include "rst_time.h"

static float isr_enter_time = 0.0;

static rst_task_id rst_main = NULL;
static rst_task_id rst_task1 = NULL;

static rst_task_attr rst_task1_attr = {
    .name = "task1",
#if RST_BIG_NUM_HIGH_PRIORITY
    .priority = RST_TASK_LOWEST_PRIORITY + 1,
#else
    .priority = RST_TASK_LOWEST_PRIORITY - 1,
#endif
    .stack_size = RST_TASK_STACK_SIZE,
};

volatile static bool isr_handled = false;

void rst_isr_handler(void *param)
{
	isr_enter_time = rst_benchmark_time_read();
	isr_handled = true;
}

static void rst_task1_func(void *arg)
{
	rst_isr_install(RST_ISR_NUM, rst_isr_handler, NULL);
	/* Benchmark code */
	rst_benchmark_time_init();
	/* goes to Isr_handler */
	rst_isr_trigger(RST_ISR_NUM);
	while (!isr_handled) {
	}
	RST_PRINT_TIME("R-Rhealstone: interrupt_latency_time, in cpu cycles",
		       isr_enter_time, 1, 0, 0);
	rst_task_resume(rst_main);
}

rst_status rst_interrupt_latency_init(void)
{
	RST_PRINT("RST: interrupt latency benchmark\r\n");
	rst_main = rst_get_current_task();
	rst_task_create(&rst_task1, rst_task1_func, NULL, &rst_task1_attr);
	if (rst_task1 == NULL) {
		RST_LOGE("RST: task1 create failed");
		return RST_ERROR;
	}
	rst_task_suspend(rst_main);
	rst_task_delete(rst_task1);

	return RST_OK;
}
