/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_TIMER_H
#define CCNET_TIMER_H

/* return TRUE to reschedule the timer, return FALSE to cancle the timer */
typedef int (*TimerCB) (void *data);

struct CcnetTimer;

typedef struct CcnetTimer CcnetTimer;

/**
 * Calls timer_func(user_data) after the specified interval.
 * The timer is freed if timer_func returns zero.
 * Otherwise, it's called again after the same interval.
 */
CcnetTimer* ccnet_timer_new (TimerCB           func,
                             void             *user_data,
                             uint64_t          timeout_milliseconds);

/**
 * Frees a timer and sets the timer pointer to NULL.
 */
void ccnet_timer_free (CcnetTimer **timer);


#endif
