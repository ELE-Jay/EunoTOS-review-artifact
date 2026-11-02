#include "rst_time.h"
#include "rst_cfg.h"
#include "rst_def.h"
#include "rst_ipc.h"
#include "rst.h"

int main(int argc __unused, char *argv[] __unused)
{
	RST_PRINT("Rhealstone Benchmark Start\r\n");

	rst_set_task_priority(rst_get_current_task(),
			      RST_TASK_HIGHEST_PRIORITY);

	rst_task_switch_init();

	rst_task_switch_multi_threaded_init();

	rst_task_preempt_init();

	rst_semaphore_shuffle_init();

	rst_interrupt_latency_init();

	rst_set_timer_offset_init();

	return 0;
}
