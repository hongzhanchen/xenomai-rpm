/*
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _COBALT_KERNEL_DOVETAIL_PIPELINE_H
#define _COBALT_KERNEL_DOVETAIL_PIPELINE_H

#include <linux/interrupt.h>
#include <linux/irq_pipeline.h>
#include <pipeline/machine.h>

#define xnsched_realtime_domain  cobalt_pipeline.domain

#define PIPELINE_NR_IRQS  IPIPE_NR_IRQS

typedef unsigned long spl_t;

#define splhigh(x) ((x) = oob_irq_save())
#define splexit(x)  oob_irq_restore(x)
#define splmax()    oob_irq_disable()
#define splnone()   oob_irq_enable()
#define spltest()   oob_irqs_disabled()

#define is_secondary_domain()   running_inband()
#define is_primary_domain()     running_oob()

#ifdef CONFIG_SMP

static void (*resched_ipi_handler)(void);
static void (*timer_ipi_handler)(void);

static irqreturn_t timer_ipi_interrupt(int irq, void *dev_id)
{
	if (timer_ipi_handler)
		(*timer_ipi_handler)();

	return IRQ_HANDLED;
}

static irqreturn_t reschedule_interrupt(int irq, void *dev_id)
{
	if (resched_ipi_handler)
		(*resched_ipi_handler)();

	return IRQ_HANDLED;
}

static inline int pipeline_request_resched_ipi(void (*handler)(void))
{

	resched_ipi_handler = handler;

	return __request_percpu_irq(RESCHEDULE_OOB_IPI,
			reschedule_interrupt,
			IRQF_OOB,
			"Xenomai reschedule",
			&cobalt_machine_cpudata);
}

static inline void pipeline_free_resched_ipi(void)
{
	free_percpu_irq(RESCHEDULE_OOB_IPI, &cobalt_machine_cpudata);
}

static inline void pipeline_send_resched_ipi(const struct cpumask *dest)
{
	irq_pipeline_send_remote(RESCHEDULE_OOB_IPI, dest);
}

static inline int pipeline_request_timer_ipi(void (*handler)(void))
{
#ifdef CONFIG_SMP
	timer_ipi_handler = handler;

	return __request_percpu_irq(TIMER_OOB_IPI,
			timer_ipi_interrupt,
			IRQF_OOB, "Xenomai timer IPI",
			&cobalt_machine_cpudata);
#else
	return 0;
#endif
}

static inline void pipeline_free_timer_ipi(void)
{
#ifdef CONFIG_SMP
	return free_percpu_irq(TIMER_OOB_IPI,
			&cobalt_machine_cpudata);
#else
	return;
#endif
}

static inline void pipeline_send_timer_ipi(const struct cpumask *dest)
{
	irq_pipeline_send_remote(TIMER_OOB_IPI, dest);
}

#endif

static inline void pipeline_prepare_panic(void)
{
 //chz: NTD pipeline_prepare_panic
	//ipipe_prepare_panic();
}

#endif /* !_COBALT_KERNEL_DOVETAIL_PIPELINE_H */
