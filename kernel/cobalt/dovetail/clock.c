/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
 */

#include <cobalt/kernel/clock.h>
#include <cobalt/kernel/vdso.h>
#include <cobalt/kernel/arith.h>
#include <pipeline/machine.h>

static unsigned long long clockfreq;

long long xnclock_core_ns_to_ticks(long long ns)
{
	return ns;
}

xnsticks_t xnclock_core_ticks_to_ns_rounded(xnsticks_t ticks)
{
	return ticks;
}

xnsticks_t xnclock_core_ticks_to_ns(xnsticks_t ticks)
{
	return ticks;
}
EXPORT_SYMBOL_GPL(xnclock_core_ticks_to_ns);
EXPORT_SYMBOL_GPL(xnclock_core_ticks_to_ns_rounded);
EXPORT_SYMBOL_GPL(xnclock_core_ns_to_ticks);

int pipeline_get_host_time(struct timespec64 *tp)
{
	return -EINVAL;
}

void pipeline_update_clock_freq(unsigned long long freq)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	clockfreq = freq;
//chz NTD
	cobalt_pipeline.clock_freq = freq;
	xnlock_put_irqrestore(&nklock, s);
}

void pipeline_init_clock(void)
{
	pipeline_update_clock_freq(cobalt_pipeline.clock_freq);
}
