#include <tn/systick.h>

#include "rst_def.h"
#include "rst_ipc.h"

uint64_t rst_tick_get(void) {
	return tn_systick_get_tick();
}

uint64_t rst_count_get(void)
{
	uint64_t count;
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(count));
	return count;
}

uint64_t rst_ticks_to_counts(uint64_t ticks) {
	return ticks * BOARD_CLOCK_FREQUENCY / CONFIG_LIBTNSYSTICK_FREQ;
}

uint64_t rst_counts_to_ticks(uint64_t counts) {
	return counts * CONFIG_LIBTNSYSTICK_FREQ / BOARD_CLOCK_FREQUENCY;
}
