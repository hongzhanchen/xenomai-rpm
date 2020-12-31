/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2001,2002,2003,2007,2012 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 */
#include <linux/sched.h>
#include <linux/tick.h>
#include <linux/clockchips.h>
#include <cobalt/kernel/sched.h>
#include <cobalt/kernel/timer.h>
#include <cobalt/kernel/intr.h>
#include <cobalt/kernel/clock.h>
#include <cobalt/kernel/arith.h>

extern struct xnintr nktimer;
static DEFINE_PER_CPU(struct clock_proxy_device *, proxy_device);

inline void xnproxy_timer_set(unsigned long delta, ktime_t tdata)
{
	struct clock_proxy_device *dev = __this_cpu_read(proxy_device);
	struct clock_event_device *real_dev = dev->real_device;
	int ret;
	u64 cycles;

	/* these code are ported from evl_program_proxy_tick */
	if (real_dev->features & CLOCK_EVT_FEAT_KTIME) {
		real_dev->set_next_ktime(tdata, real_dev);
	} else {
		if (delta <= 0)
			delta = real_dev->min_delta_ns;
		else {
			delta = min_t(int64_t, delta,
					(int64_t)real_dev->max_delta_ns);
			delta = max_t(int64_t, delta,
					(int64_t)real_dev->min_delta_ns);
		}
		//if (delta == real_dev->min_delta_ns)
		//	delta *= 2;
		cycles = ((u64)delta * real_dev->mult) >> real_dev->shift;

		ret = real_dev->set_next_event(cycles, real_dev);
		if (ret) {
			ret = real_dev->set_next_event(real_dev->min_delta_ticks,
					real_dev);
		}
	}
}

static int proxy_set_next_ktime(ktime_t expires,
				struct clock_event_device *proxy_dev)
{
	struct xnsched *sched;
	ktime_t delta;
	//spl_t s;
	unsigned long flags;
	int ret;

	/*
	 * Negative delta have been observed. evl_start_timer()
	 * will trigger an immediate shot in such an event.
	 */
	delta = ktime_sub(expires, ktime_get_mono_fast_ns());
	if (delta < 0)
		delta = 0;

	flags = hard_local_irq_save(); /* Prevent CPU migration. */
	sched = xnsched_current();
	ret = xntimer_start(&sched->htimer, delta, XN_INFINITE, XN_RELATIVE);
	hard_local_irq_restore(flags);

	return ret ? -ETIME : 0;
}

void xn_core_tick(struct clock_event_device *dummy) /* hard irqs off */
{
	xnintr_core_clock_handler();
}

static int proxy_set_oneshot_stopped(struct clock_event_device *proxy_dev)
{
	struct clock_event_device *real_dev;
	struct clock_proxy_device *dev;
	struct xnsched *sched;
	spl_t s;

	dev = container_of(proxy_dev, struct clock_proxy_device, proxy_device);

	/*
	 * In-band wants to disable the clock hardware on entering a
	 * tickless state, so we have to stop our in-band tick
	 * emulation. Propagate the request for shutting down the
	 * hardware to the real device only if we have no outstanding
	 * OOB timers. CAUTION: the in-band timer is counted when
	 * assessing the RQ_IDLE condition, so we need to stop it
	 * prior to testing the latter.
	 */
	xnlock_get_irqsave(&nklock, s);
	sched = xnsched_current();
	xntimer_stop(&sched->htimer);
	sched->lflags |= XNTSTOP;

	if (sched->lflags & XNIDLE) {
		real_dev = dev->real_device;
		real_dev->set_state_oneshot_stopped(real_dev);
	}

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}


static void setup_proxy(struct clock_proxy_device *dev)
{
	struct clock_event_device *proxy_dev = &dev->proxy_device;

	dev->handle_oob_event = xn_core_tick;
	proxy_dev->features |= CLOCK_EVT_FEAT_KTIME;
	proxy_dev->set_next_ktime = proxy_set_next_ktime;
	if (proxy_dev->set_state_oneshot_stopped)
		proxy_dev->set_state_oneshot_stopped = proxy_set_oneshot_stopped;
	__this_cpu_write(proxy_device, dev);
}

/**
 * @fn int pipeline_install_tick_proxy(void)
 * @brief Grab the hardware timer on all real-time CPUs.
 *
 * pipeline_install_tick_proxy() grabs and tunes the hardware timer for all
 * real-time CPUs.
 *
 * Host tick emulation is performed for sharing the clock chip between
 * Linux and Xenomai.
 *
 * @return a positive value is returned on success, representing the
 * duration of a Linux periodic tick expressed as a count of
 * nanoseconds; zero should be returned when the Linux kernel does not
 * undergo periodic timing on the given CPU (e.g. oneshot
 * mode). Otherwise:
 *
 * - -EBUSY is returned if the hardware timer has already been
 * grabbed.  xntimer_release_hardware() must be issued before
 * pipeline_install_tick_proxy() is called again.
 *
 * - -ENODEV is returned if the hardware timer cannot be used.  This
 * situation may occur after the kernel disabled the timer due to
 * invalid calibration results; in such a case, such hardware is
 * unusable for any timing duties.
 *
 * @coretags{secondary-only}
 */

int pipeline_install_tick_proxy(void)
{
	int ret;

	nkclock.wallclock_offset =
		ktime_to_ns(ktime_get_real()) - xnclock_read_monotonic(&nkclock);

	ret = xntimer_setup_ipi();
	if (ret)
		return ret;
	ret = tick_install_proxy(setup_proxy, &xnsched_realtime_cpus);
	if (ret)
		goto fail_proxy;

	return 0;

fail_proxy:
	xntimer_release_ipi();

	return ret;
}

/**
 * @fn void pipeline_uninstall_tick_proxy(void)
 * @brief Release hardware timers.
 *
 * Releases hardware timers previously grabbed by a call to
 * pipeline_install_tick_proxy().
 *
 * @coretags{secondary-only}
 */
void pipeline_uninstall_tick_proxy(void)
{
	/*
	 * We must not hold the nklock while stopping the hardware
	 * timer, since this could cause deadlock situations to arise
	 * on SMP systems.
	 */

	tick_uninstall_proxy(&xnsched_realtime_cpus);

	xntimer_release_ipi();

#ifdef CONFIG_XENO_OPT_STATS_IRQS
	xnintr_destroy(&nktimer);
#endif /* CONFIG_XENO_OPT_STATS_IRQS */
}
