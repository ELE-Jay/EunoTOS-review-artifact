#include "rst.h"
#include "rst_ipc.h"
#include "rst_time.h"

static int64_t loop_overhead = 0.0;
static int64_t telapsed = 0.0;

static uint32_t count = 0;

static rst_task_id rst_main = NULL;
static rst_task_id rst_task1 = NULL;
static rst_task_id rst_task2 = NULL;

static rst_task_attr rst_task1_attr = {
    .name = "task1",
#if RST_BIG_NUM_HIGH_PRIORITY
    .priority = RST_TASK_HIGHEST_PRIORITY - 3,
#else
    .priority = RST_TASK_HIGHEST_PRIORITY + 3,
#endif
    .stack_size = RST_TASK_STACK_SIZE,
};

static rst_task_attr rst_task2_attr = {
    .name = "task2",
#if RST_BIG_NUM_HIGH_PRIORITY
    .priority = RST_TASK_HIGHEST_PRIORITY - 1,
#else
    .priority = RST_TASK_HIGHEST_PRIORITY + 1,
#endif
    .stack_size = RST_TASK_STACK_SIZE,
};

static void rst_task2_func(void *arg);

static void rst_task1_func(void *arg __unused)
{
	rst_benchmark_time_init();
	/* Benchmark code */
	for (; count < RST_BENCHMARKS_COUNT; count++) {
		rst_task_resume(rst_task2);
	}
}

static void rst_task2_func(void *arg __unused)
{
    /* Benchmark code */
    for (count = 0; count < RST_BENCHMARKS_COUNT - 1;) {
	    rst_task_suspend(rst_task2);
    }

    telapsed = rst_benchmark_time_read();

    RST_PRINT_TIME("R-Rhealstone: average_task_preempt_time, in cpu cycles",
		   telapsed,		 /* Total time of all benchmarks */
		   RST_BENCHMARKS_COUNT, /* BENCHMARKS - 1 total benchmarks */
		   loop_overhead,	 /* Overhead of loop */
		   0			 /* Overhead */
    );
    rst_task_resume(rst_main);
}

rst_status rst_task_preempt_init(void)
{
	RST_PRINT("RST: task preempt benchmark\r\n");
	rst_main = rst_get_current_task();
	/* Find loop overhead */
	rst_benchmark_time_init();
	for (count = 0; count < ((RST_BENCHMARKS_COUNT * 2) - 1); count++) {
	}
    loop_overhead = rst_benchmark_time_read();

    rst_task_create(&rst_task1, rst_task1_func, NULL, &rst_task1_attr);
    if (rst_task1 == NULL) {
	    RST_LOGE("RST: task1 create failed");
	    return RST_ERROR;
    }
    rst_task_create(&rst_task2, rst_task2_func, NULL, &rst_task2_attr);
    if (rst_task2 == NULL) {
	    RST_LOGE("RST: task2 create failed");
	    return RST_ERROR;
    }
    rst_task_suspend(rst_main);
    rst_task_delete(rst_task1);
    rst_task_delete(rst_task2);
    return RST_OK;
}
