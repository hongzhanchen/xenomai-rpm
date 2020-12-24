/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2005,2006 Dmitry Adamushko <dmitry.adamushko@gmail.com>.
 * Copyright (C) 2007 Jan Kiszka <jan.kiszka@web.de>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <linux/mutex.h>
#include <cobalt/kernel/sched.h>
#include <cobalt/kernel/intr.h>
#include <cobalt/kernel/stat.h>
#include <cobalt/kernel/clock.h>
#include <cobalt/kernel/assert.h>
#include <trace/events/cobalt-core.h>


int xnintr_init(struct xnintr *intr, const char *name,
		unsigned int irq, xnisr_t isr, xniack_t iack,
		int flags)
{
//chz NTD: would be called by rdtm
	return 0;
}

EXPORT_SYMBOL_GPL(xnintr_init);

int xnintr_attach(struct xnintr *intr, void *cookie)
{
	int ret;
	return ret;
}

EXPORT_SYMBOL_GPL(xnintr_attach);

void xnintr_destroy(struct xnintr *intr)
{
}
EXPORT_SYMBOL_GPL(xnintr_destroy);

void xnintr_enable(struct xnintr *intr)
{
}
EXPORT_SYMBOL_GPL(xnintr_enable);

void xnintr_host_tick(struct xnsched *sched) /* Interrupts off. */
{
	sched->lflags &= ~XNHTICK;
	/* use proxy tick to replace host tick */
	tick_notify_proxy();
}

/*
 * Low-level core clock irq handler. This one forwards ticks from the
 * Xenomai platform timer to nkclock exclusively.
 */
void xnintr_core_clock_handler(void)
{
	struct xnsched *sched = xnsched_current();
	int cpu  __maybe_unused = xnsched_cpu(sched);

	if (XENO_WARN_ON_ONCE(CORE, !hard_irqs_disabled()))
		hard_local_irq_disable();

	if (!xnsched_supported_cpu(cpu)) {
		tick_notify_proxy();
		return;
	}

	xnlock_get(&nklock);
	xnclock_tick(&nkclock);
	xnlock_put(&nklock);

	/*
	 * If the core clock interrupt preempted a real-time thread,
	 * any transition to the root thread has already triggered a
	 * host tick propagation from xnsched_run(), so at this point,
	 * we only need to propagate the host tick in case the
	 * interrupt preempted the root thread.
	 */
	if ((sched->lflags & XNHTICK) &&
	    xnthread_test_state(sched->curr, XNROOT))
		xnintr_host_tick(sched);
}

int __init xnintr_mount(void)
{
	return 0;
}

#ifdef CONFIG_XENO_OPT_VFILE

#include <cobalt/kernel/vfile.h>

#warning TODO
#if 0
static inline int format_irq_proc(unsigned int irq,
				  struct xnvfile_regular_iterator *it)
{
	struct xnintr *intr;
	struct irq_desc *d;
	int cpu;

	for_each_realtime_cpu(cpu)
		if (xnintr_is_timer_irq(irq)) {
			xnvfile_printf(it, "         [timer/%d]", cpu);
			return 0;
		}

#ifdef CONFIG_SMP
	/*
	 * IPI numbers on ARM are not compile time constants, so do
	 * not use switch/case here.
	 */
	if (irq == IPIPE_HRTIMER_IPI) {
		xnvfile_puts(it, "         [timer-ipi]");
		return 0;
	}
	if (irq == IPIPE_RESCHEDULE_IPI) {
		xnvfile_puts(it, "         [reschedule]");
		return 0;
	}
	if (irq == IPIPE_CRITICAL_IPI) {
		xnvfile_puts(it, "         [sync]");
		return 0;
	}
#endif /* CONFIG_SMP */
	if (ipipe_virtual_irq_p(irq)) {
		xnvfile_puts(it, "         [virtual]");
		return 0;
	}

	mutex_lock(&intrlock);

	if (!cobalt_owns_irq(irq)) {
		xnvfile_puts(it, "         ");
		d = irq_to_desc(irq);
		xnvfile_puts(it, d && d->name ? d->name : "-");
	} else {
		intr = xnintr_vec_first(irq);
		if (intr) {
			xnvfile_puts(it, "        ");

			do {
				xnvfile_putc(it, ' ');
				xnvfile_puts(it, intr->name);
				intr = xnintr_vec_next(intr);
			} while (intr);
		}
	}

	mutex_unlock(&intrlock);

	return 0;
}
#endif

static int irq_vfile_show(struct xnvfile_regular_iterator *it,
			  void *data)
{
#warning TODO
#if 0
	int cpu, irq;

	/* FIXME: We assume the entire output fits in a single page. */

	xnvfile_puts(it, "  IRQ ");

	for_each_realtime_cpu(cpu)
		xnvfile_printf(it, "        CPU%d", cpu);

	for (irq = 0; irq < IPIPE_NR_IRQS; irq++) {
		if (__ipipe_irq_handler(&xnsched_realtime_domain, irq) == NULL)
			continue;

		xnvfile_printf(it, "\n%5d:", irq);

		for_each_realtime_cpu(cpu) {
			xnvfile_printf(it, "%12lu",
				       __ipipe_cpudata_irq_hits(&xnsched_realtime_domain, cpu,
								irq));
		}

		format_irq_proc(irq, it);
	}

	xnvfile_putc(it, '\n');
#endif

	return 0;
}

static struct xnvfile_regular_ops irq_vfile_ops = {
	.show = irq_vfile_show,
};

static struct xnvfile_regular irq_vfile = {
	.ops = &irq_vfile_ops,
};

void xnintr_init_proc(void)
{
	xnvfile_init_regular("irq", &irq_vfile, &cobalt_vfroot);
}

void xnintr_cleanup_proc(void)
{
	xnvfile_destroy_regular(&irq_vfile);
}

#endif /* CONFIG_XENO_OPT_VFILE */

