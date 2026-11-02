#ifndef __TN_TRACE_H__
#define __TN_TRACE_H__

#if defined(CONFIG_LIBTNTRACE_FORMAT)
#define TN_TRACE_FUNC(name, func, ...) \
	tn_trace_ ## name ## _ ## func ## _format(__VA_ARGS__)
#define TN_TRACE_FUNC_ENTER(name, func, ...) \
	tn_trace_ ## name ## _ ## func ## _enter_format(__VA_ARGS__)
#define TN_TRACE_FUNC_EXIT(name, func, ...) \
	tn_trace_ ## name ## _ ## func ## _exit_format(__VA_ARGS__)
#define TN_TRACE_OBJ_FUNC(name, func, obj, ...) \
	tn_trace_ ## name ## _ ## func ## _format(obj, ##__VA_ARGS__)
#define TN_TRACE_OBJ_FUNC_ENTER(name, func, obj, ...) \
	tn_trace_ ## name ## _ ## func ## _enter_format(obj, ##__VA_ARGS__)
#define TN_TRACE_OBJ_FUNC_EXIT(name, func, obj, ...) \
	tn_trace_ ## name ## _ ## func ## _exit_format(obj, ##__VA_ARGS__)


#elif defined(CONFIG_LIBTNTRACE_CUSTOM)

#define TN_TRACE_FUNC(name, func, ...) \
	tn_trace_ ## name ## _ ## func ## _custom(__VA_ARGS__)
#define TN_TRACE_FUNC_ENTER(name, func, ...) \
	tn_trace_ ## name ## _ ## func ## _enter_custom(__VA_ARGS__)
#define TN_TRACE_FUNC_EXIT(name, func, ...) \
	tn_trace_ ## name ## _ ## func ## _exit_custom(__VA_ARGS__)
#define TN_TRACE_OBJ_FUNC(name, func, obj, ...) \
	tn_trace_ ## name ## _ ## func ## _custom(obj, ##__VA_ARGS__)
#define TN_TRACE_OBJ_FUNC_ENTER(name, func, obj, ...) \
	tn_trace_ ## name ## _ ## func ## _enter_custom(obj, ##__VA_ARGS__)
#define TN_TRACE_OBJ_FUNC_EXIT(name, func, obj, ...) \
	tn_trace_ ## name ## _ ## func ## _exit_custom(obj, ##__VA_ARGS__)


#endif /* CONFIG_LIBTNTRACE_CUSTOM */

#endif /* __TN_TRACE_H__ */
