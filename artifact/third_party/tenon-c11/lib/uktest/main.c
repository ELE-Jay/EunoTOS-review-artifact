/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#include <stdio.h>
#include <uk/test.h>

/* test main */
int main(int argc __unused, char *argv[] __unused)
{
#ifdef CONFIG_LIBUKTEST_LOG_STATS
	uk_test_print_stats();
#endif
	return 0;
}
