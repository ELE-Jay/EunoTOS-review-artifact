#include <uk/intctlr.h>>

#if defined(CONFIG_LIBTNTRACE_FORMAT)
void tn_trace_isr_handle_enter_format(unsigned int irq)
{
	printf("%s %u\n", __func__, irq);
}

void tn_trace_isr_handle_exit_format(unsigned int irq)
{
	printf("%s %u\n", __func__, irq);
}

#elif defined(CONFIG_LIBTNTRACE_CUSTOM)

void __weak tn_trace_isr_handle_enter_custom(void) {}
void __weak tn_trace_isr_handle_exit_custom(void) {}

#endif /* CONFIG_LIBTNTRACE_CUSTOM */
