/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020 Philippe Gerum  <rpm@xenomai.org>
 */

#ifndef _COBALT_KERNEL_DOVETAIL_SIRQ_H
#define _COBALT_KERNEL_DOVETAIL_SIRQ_H

#include <pipeline/machine.h>

/*
 * Wrappers to create "synthetic IRQs" the I-pipe way (used to be
 * called "virtual IRQs" there). Those interrupt channels can only be
 * trigged by software, in order to run a handler on the proper
 * execution stage (in-band or out-band). We reuse the Dovetail naming
 * convention: in-band means "secondary mode", out-of-band means
 * "primary mode" in the old lingo.
 */

static inline
int pipeline_create_inband_sirq(irqreturn_t (*handler)(int irq, void *dev_id))
{
	int sirq, ret;

	sirq = irq_create_direct_mapping(synthetic_irq_domain);
	if (sirq == 0)
		return -EAGAIN;
	ret = __request_percpu_irq(sirq,
			handler,
			IRQF_OOB,
			"Inband sirq",
			&cobalt_machine_cpudata);

	if (ret) {
		irq_dispose_mapping(sirq);
		return ret;
	}

	return sirq;
}

static inline
void pipeline_delete_inband_sirq(int sirq)
{
	free_percpu_irq(sirq,
		&cobalt_machine_cpudata);

	irq_dispose_mapping(sirq);
}

static inline
int pipeline_create_oob_sirq(irqreturn_t (*handler)(int irq, void *dev_id))
{
	int sirq, ret;

	sirq = irq_create_direct_mapping(synthetic_irq_domain);
	if (sirq == 0)
		return -EAGAIN;

	ret = __request_percpu_irq(sirq,
			handler,
			IRQF_OOB,
			"OOB sirq",
			&cobalt_machine_cpudata);

	if (ret) {
		irq_dispose_mapping(sirq);
		return ret;
	}

	return sirq;
}

static inline
void pipeline_delete_oob_sirq(int sirq)
{
	free_percpu_irq(sirq,
		&cobalt_machine_cpudata);

	irq_dispose_mapping(sirq);
}

static inline void pipeline_post_sirq(int sirq)
{
	irq_inject_pipeline(sirq);
}

#endif /* !_COBALT_KERNEL_DOVETAIL_SIRQ_H */
