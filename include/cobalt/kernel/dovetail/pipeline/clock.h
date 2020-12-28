/*
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _COBALT_KERNEL_DOVETAIL_CLOCK_H
#define _COBALT_KERNEL_DOVETAIL_CLOCK_H

#include <linux/tick.h>
#include <linux/clockchips.h>

static inline u64 pipeline_read_cycle_counter(void)
{
	return  ktime_get_mono_fast_ns();
}

inline void xnproxy_timer_set(unsigned long delta, ktime_t tdata);

static inline void pipeline_set_timer_shot(unsigned long cycles,
		ktime_t tdata)
{
	xnproxy_timer_set(cycles, tdata);
}

static inline const char *pipeline_timer_name(void)
{
//chz: NTD double check what should return
	return "?";
}

static inline const char *pipeline_clock_name(void)
{
//chz: NTD double check waht should return
	return "?";
}

int pipeline_get_host_time(struct timespec64 *tp);

void pipeline_update_clock_freq(unsigned long long freq);

void pipeline_init_clock(void);

#endif /* !_COBALT_KERNEL_DOVETAIL_CLOCK_H */
