#ifndef __RST_IPC_H__
#define __RST_IPC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "rst_def.h"

/**
 * @brief System schedule API
 *
 */
rst_status rst_task_yield(void);
rst_status rst_task_reschedule(void);

/**
 * @brief Task API
 *
 */
typedef void *rst_task_id;

typedef struct rst_task_attr{
    char *name;                 // name of the task
    uint32_t stack_size;        // size of stack
    int32_t priority;           // task priority
} rst_task_attr;

typedef void (*rst_task_func)(void *arg);

rst_status rst_task_create(rst_task_id *task, rst_task_func func,
                           void *arg, rst_task_attr *attr);
rst_status rst_task_suspend(rst_task_id task);
rst_status rst_task_resume(rst_task_id task);
void rst_task_delete(rst_task_id task);
rst_task_id rst_get_current_task(void);
void rst_set_task_priority(rst_task_id task, uint32_t priority);
void rst_task_sleep(uint64_t ticks);

/**
 * @brief Sem API
 *
 */
typedef void *rst_sem_id;

rst_sem_id rst_sem_create(uint32_t value);
rst_status rst_sem_lock(rst_sem_id sem, rst_time_t time);
rst_status rst_sem_unlock(rst_sem_id sem);
void rst_sem_delete(rst_sem_id sem);

/**
 * @brief Mutex API
 *
 */
typedef void *rst_mutex_id;

rst_mutex_id rst_mutex_create(uint32_t value);
rst_status rst_mutex_lock(rst_sem_id mutex, rst_time_t time);
rst_status rst_mutex_unlock(rst_sem_id mutex);
void rst_mutex_delete(rst_sem_id mutex);

/**
 * @brief Queue API
 *
 */
typedef void *rst_queue_id;

rst_queue_id rst_queue_create(int size, int count);
rst_status rst_queue_send(rst_queue_id queue, const void *msg,
                          uint32_t size, rst_time_t timeout);
rst_status rst_queue_recv(rst_queue_id queue, void *msg, uint32_t size);
void rst_queue_delete(rst_queue_id queue);


/**
 * @brief Interrupt API
 *
 */
typedef void (*rst_isr_func)(void *param);

void rst_irq_mask(void);

void rst_irq_unmask(void);

rst_status rst_isr_install(int vector, rst_isr_func handler, void *param);

void rst_isr_trigger(int vector);

extern void rst_isr_handler(void *param);

/**
 * @brief TICK API
 *
 */
uint64_t rst_tick_get(void);
uint64_t rst_count_get(void);
uint64_t rst_ticks_to_counts(uint64_t ticks);
uint64_t rst_counts_to_ticks(uint64_t counts);

#ifdef __cplusplus
}
#endif

#endif
