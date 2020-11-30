/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020 Philippe Gerum  <rpm@xenomai.org>
 */

#ifndef _COBALT_KERNEL_IPIPE_SIRQ_H
#define _COBALT_KERNEL_IPIPE_SIRQ_H

#include <linux/ipipe.h>
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
	int sirq = ipipe_alloc_virq(), ret;

	if (sirq == 0)
		return -EAGAIN;

	/*
	 * ipipe_irq_handler_t is close enough to the signature of a
	 * regular IRQ handler: use the latter in the generic code
	 * shared with Dovetail.  The extraneous return code will be
	 * ignored by the I-pipe core.
	 */
	ret = ipipe_request_irq(ipipe_root_domain, sirq,
				(ipipe_irq_handler_t)handler,
				NULL, NULL);
	if (ret) {
		ipipe_free_virq(sirq);
		return ret;
	}

	return sirq;
}

static inline
void pipeline_delete_inband_sirq(int sirq)
{
	ipipe_free_irq(ipipe_root_domain, sirq);
	ipipe_free_virq(sirq);
}

static inline
int pipeline_create_oob_sirq(irqreturn_t (*handler)(int irq, void *dev_id))
{
	int sirq = ipipe_alloc_virq(), ret;

	if (sirq == 0)
		return -EAGAIN;

	ret = ipipe_request_irq(&cobalt_pipeline.domain, sirq,
				(ipipe_irq_handler_t)handler,
				NULL, NULL);
	if (ret) {
		ipipe_free_virq(sirq);
		return ret;
	}

	return sirq;
}

static inline
void pipeline_delete_oob_sirq(int sirq)
{
	ipipe_free_irq(&cobalt_pipeline.domain, sirq);
	ipipe_free_virq(sirq);
}

static inline void pipeline_post_sirq(int sirq)
{
	ipipe_post_irq_root(sirq);
}

#endif /* !_COBALT_KERNEL_IPIPE_SIRQ_H */
