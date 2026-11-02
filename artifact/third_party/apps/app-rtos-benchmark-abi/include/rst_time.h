#ifndef __RST_BTIME_H__
#define __RST_BTIME_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "rst_def.h"

void rst_benchmark_time_init(void);

rst_time_t rst_benchmark_time_read(void);

uint64_t rst_time_to_ns(rst_time_t time);

uint64_t rst_time_to_count(rst_time_t time);

extern const char *rst_time_unit;

#ifdef __cplusplus
}
#endif

#endif
