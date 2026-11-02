#include "rst.h"
#include "rst_ipc.h"
#include "rst_time.h"
#include <stdio.h>
#define RST_TASK_COUNT 50
#define RST_BENCHMARKS_COUNT_ALL RST_TASK_COUNT *RST_BENCHMARKS_COUNT
static int64_t loop_overhead = 0;
static int64_t telapsed = 0;

static uint32_t count = 0;

static rst_task_id rst_main = NULL;
static rst_task_id rst_task_head = NULL;
static rst_task_id rst_task[RST_TASK_COUNT] = {NULL};

static rst_task_attr rst_task_multi = {
    .name = "task",
#if RST_BIG_NUM_HIGH_PRIORITY
    .priority = RST_TASK_HIGHEST_PRIORITY - 1,
#else
    .priority = RST_TASK_HIGHEST_PRIORITY + 1,
#endif
    .stack_size = RST_TASK_STACK_SIZE,
};

static void rst_task_head_func(void *arg)
{
	rst_benchmark_time_init();
	/* All overhead accounted for now, we can begin benchmark */

	for (count = 0; count < RST_BENCHMARKS_COUNT_ALL; count++) {
		rst_task_yield();
	}

	telapsed = rst_benchmark_time_read();

	RST_PRINT_TIME(
	    "R-Rhealstone: average_multi_task_switch_time, in cpu cycles",
	    telapsed,		      /* Total time of all benchmarks */
	    RST_BENCHMARKS_COUNT_ALL, /* BENCHMARKS total benchmarks */
	    loop_overhead,	      /* Overhead of loop */
	    0			      /* Overhead of rst_task_yield directive */
	);
	for (int i = 0; i < RST_TASK_COUNT; i++) {
		rst_task_delete(rst_task[i]);
	}
	rst_task_resume(rst_main);
}
static void rst_task_func_multi(void *arg __unused)
{
	for (; count < RST_BENCHMARKS_COUNT_ALL; count++) {
		rst_task_yield();
	}
	rst_set_task_priority(rst_task_head, RST_TASK_HIGHEST_PRIORITY);
	rst_task_yield();
}

rst_status rst_task_switch_multi_threaded_init(void)
{
	RST_PRINT("RST: %d task switch benchmark\r\n", RST_TASK_COUNT);
	rst_main = rst_get_current_task();
	/* find overhead of routine (no task switches) */
	rst_benchmark_time_init();
	for (count = 0; count < RST_BENCHMARKS_COUNT_ALL; count++) {
	}
	loop_overhead = rst_benchmark_time_read();
	count = 0;
	for (int i = 0; i < RST_TASK_COUNT; i++) {
		rst_task_create(&(rst_task[i]), rst_task_func_multi, NULL,
				&rst_task_multi);
		if (rst_task[i] == NULL) {
			RST_LOGE("RST: task create failed");
			return RST_ERROR;
		}
	}
	rst_task_create(&rst_task_head, rst_task_head_func, NULL,
			&rst_task_multi);
	if (rst_task_head == NULL) {
		RST_LOGE("RST: task create failed");
		return RST_ERROR;
	}
	rst_task_suspend(rst_main);
	return RST_OK;
}
