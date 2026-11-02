#include "rst.h"
#include "rst_ipc.h"
#include "rst_time.h"
#include <stdio.h>

static uint64_t mask_irq_tick = 5;
static uint64_t enable_irq_tick = 15;
static uint64_t timer_tick = 10;

static uint32_t count;
static uint64_t start_tick, end_tick;
static uint64_t start_count, end_count;

static int64_t overhead = 0;
static int64_t telapsed_tick = 0;
static int64_t telapsed_count = 0;
static int64_t single_tick_delay = 0;
static int64_t single_count_delay = 0;
static int64_t max_tick_delay = -0x3f3f3f3f;
static int64_t min_tick_delay = 0x3f3f3f3f;
static int64_t max_count_delay = -0x3f3f3f3f;
static int64_t min_count_delay = 0x3f3f3f3f;

static rst_task_id rst_main = NULL;
static rst_task_id rst_task1 = NULL;
static rst_task_id rst_task2 = NULL;

const char *tick_offset_unit = "tick";
const char *count_offset_unit = "count";

static rst_task_attr rst_task1_attr = {
    .name = "task1",
#if RST_BIG_NUM_HIGH_PRIORITY
    .priority = RST_TASK_HIGHEST_PRIORITY - 1,
#else
    .priority = RST_TASK_HIGHEST_PRIORITY + 1,
#endif
    .stack_size = RST_TASK_STACK_SIZE,
};

static rst_task_attr rst_task2_attr = {
    .name = "task2",
#if RST_BIG_NUM_HIGH_PRIORITY
    .priority = RST_TASK_HIGHEST_PRIORITY - 2,
#else
    .priority = RST_TASK_HIGHEST_PRIORITY + 2,
#endif
    .stack_size = RST_TASK_STACK_SIZE,
};

static void rst_task1_func(void *arg __unused)
{
	for (count = 0; count < RST_BENCHMARKS_COUNT; count++) {
		start_tick = rst_tick_get();
		while (rst_tick_get() - start_tick < 10) {
		}
		start_count = rst_count_get();
		rst_task_sleep(timer_tick);
		end_count = rst_count_get();
		end_tick = rst_tick_get();
		single_tick_delay = end_tick - start_tick - timer_tick - 10;
		single_count_delay =
		    end_count - start_count - rst_ticks_to_counts(timer_tick);

		max_tick_delay = max_tick_delay > single_tick_delay
				     ? max_tick_delay
				     : single_tick_delay;
		min_tick_delay = min_tick_delay < single_tick_delay
				     ? min_tick_delay
				     : single_tick_delay;

		max_count_delay = max_count_delay > single_count_delay
				      ? max_count_delay
				      : single_count_delay;
		min_count_delay = min_count_delay < single_count_delay
				      ? min_count_delay
				      : single_count_delay;

		telapsed_tick += single_tick_delay;
		telapsed_count += single_count_delay;
	}
	RST_LOGD("iterations: %d", RST_BENCHMARKS_COUNT);
	RST_LOGD("max_tick_delay: %ld %s", max_tick_delay, tick_offset_unit);
	RST_LOGD("min_tick_delay: %ld %s", min_tick_delay, tick_offset_unit);
	RST_LOGD("offset_tick: %ld %s", telapsed_tick, tick_offset_unit);
	RST_LOGD("%s - %ld %s\r\n",
		 "R-Rhealstone: timer deviation under interrupt interference, "
		 "in count of generic timer",
		 ((telapsed_tick) / ((RST_BENCHMARKS_COUNT))),
		 tick_offset_unit);
	RST_LOGD("max_count_delay: %ld %s", max_count_delay, count_offset_unit);
	RST_LOGD("min_count_delay: %ld %s", min_count_delay, count_offset_unit);
	RST_LOGD("offset_count: %ld %s", telapsed_count, count_offset_unit);
	RST_PRINT("\033[32;22m%s - %ld %s\033[0m\r\n",
		  "R-Rhealstone: timer_deviation_under_interrupt_interference, "
		  "in count of generic timer",
		  (((telapsed_count) / ((RST_BENCHMARKS_COUNT))) - overhead),
		  count_offset_unit);
	rst_task_resume(rst_main);
}

static void rst_task2_func(void *arg __unused)
{
	uint64_t mask_irq_count;
	uint64_t cur_count;
	uint64_t cur_tick;
	while (1) {
		mask_irq_count = rst_ticks_to_counts(mask_irq_tick);
		cur_count = rst_count_get();
		rst_irq_mask();
		while (rst_count_get() - cur_count < mask_irq_count) {
		}
		rst_irq_unmask();
		cur_tick = rst_tick_get();
		while (rst_tick_get() - cur_tick < enable_irq_tick)
			rst_task_reschedule();
	}
}

rst_status rst_set_timer_offset_init(void)
{
	RST_PRINT("RST: timer deviation under interrupt interference\r\n");
	rst_main = rst_get_current_task();

	overhead = rst_count_get();
	overhead = rst_count_get() - overhead;
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
