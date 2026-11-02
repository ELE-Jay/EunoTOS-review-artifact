#ifndef __TN_TRACE_MACROS_H__
#define __TN_TRACE_MACROS_H__

#ifndef CONFIG_LIBTNTRACE

#define TN_TRACE_FUNC(type, func, ...) do { } while (0)
#define TN_TRACE_FUNC_ENTER(type, func, ...) do { } while (0)
#define TN_TRACE_FUNC_EXIT(type, func, ...) do { } while (0)
#define TN_TRACE_OBJ_FUNC(type, func, obj, ...) do { } while (0)
#define TN_TRACE_OBJ_FUNC_ENTER(type, func, obj, ...) do { } while (0)
#define TN_TRACE_OBJ_FUNC_EXIT(type, func, obj, ...) do { } while (0)

#else /* !CONFIG_LIBTNTRACE */

#include <tn/trace.h>

#endif /* CONFIG_LIBTNTRACE */

#endif /* __TN_TRACE_MACROS_H__ */
