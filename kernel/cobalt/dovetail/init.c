/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 Philippe Gerum  <rpm@xenomai.org>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <pipeline/machine.h>
#include <cobalt/kernel/sched.h>
#include <cobalt/kernel/clock.h>

static irqreturn_t escalate_interrupt(int irq, void *dev_id)
{
	__xnsched_run_handler();

	return IRQ_HANDLED;
}
int __init pipeline_init(void)
{
	int ret, virq;


	cobalt_pipeline.timer_freq = 1;
	cobalt_pipeline.clock_freq = 1;

	enable_oob_stage("Xenomai");

	virq = irq_create_direct_mapping(synthetic_irq_domain);
	if (virq == 0)
		goto fail_escalate;

	cobalt_pipeline.escalate_virq = virq;

	ret = __request_percpu_irq(virq,
			escalate_interrupt,
			IRQF_OOB,
			"Escalate interrupt",
			&cobalt_machine_cpudata);
	
	if (ret)
		goto fail_mapping;

	ret = xnclock_init();
	if (ret)
		goto fail_clock;

	return 0;

fail_clock:
	free_percpu_irq(virq,
			&cobalt_machine_cpudata);
fail_mapping:
	irq_dispose_mapping(virq);
fail_escalate:
	disable_oob_stage();

	return ret;
}

int __init pipeline_late_init(void)
{
//chz: NTD check if there is late init
	return 0;
}

__init void pipeline_cleanup(void)
{
	free_percpu_irq(cobalt_pipeline.escalate_virq,
			&cobalt_machine_cpudata);
	irq_dispose_mapping(cobalt_pipeline.escalate_virq);
	disable_oob_stage();
	xnclock_cleanup();
}
