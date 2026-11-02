#include "rst_def.h"

static uint64_t first_cnt = 0, tmp_cnt = 0;

void rst_benchmark_time_init(void)
{
	__asm__ volatile("msr pmcr_el0, %0" : : "r"(17));
	__asm__ volatile("msr PMCNTENSET_EL0, %0" : : "r"(0x8000000f));
	__asm__ volatile("msr PMOVSCLR_EL0, %0" : : "r"(0x8000000f));

	__asm__ volatile("mrs %0, PMCCNTR_EL0" : "=r"(first_cnt));
}

rst_time_t rst_benchmark_time_read(void)
{
	if (first_cnt == 0) {
		__asm__ volatile("mrs %0, PMCCNTR_EL0" : "=r"(tmp_cnt));
		return tmp_cnt;
	}
	__asm__ volatile("mrs %0, PMCCNTR_EL0" : "=r"(tmp_cnt));
	tmp_cnt = (rst_time_t)(tmp_cnt - first_cnt);
	first_cnt = 0;
	return tmp_cnt;
}

const char *rst_time_unit = "cycle";

uint64_t rst_time_to_ns(rst_time_t time)
{
	return (uint64_t)time;
}
