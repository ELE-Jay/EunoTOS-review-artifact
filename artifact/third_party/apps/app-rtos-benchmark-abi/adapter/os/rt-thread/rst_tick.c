#include "rst_def.h"
#include "rst_ipc.h"
#include "rtthread.h"

uint64_t rst_tick_get(void)
{
	return rt_tick_get();
}
uint64_t rst_count_get(void)
{
	uint64_t count;
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(count));
	return count;
}
uint64_t rst_ticks_to_counts(uint64_t ticks) {
	return ticks * BOARD_CLOCK_FREQUENCY / RT_TICK_PER_SECOND;
}

uint64_t rst_counts_to_ticks(uint64_t counts) {
	return counts * RT_TICK_PER_SECOND / BOARD_CLOCK_FREQUENCY;
}
