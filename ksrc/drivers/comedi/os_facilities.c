/**
 * @file
 * Comedi for RTDM, OS facilities
 *
 * Copyright (C) 1997-2000 David A. Schleef <ds@schleef.org>
 * Copyright (C) 2008 Alexis Berlemont <alexis.berlemont@free.fr>
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef DOXYGEN_CPP

#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <asm/atomic.h>

#include <comedi/os_facilities.h>

/* --- Time section --- */

static unsigned long long comedi_clkofs;

void comedi_init_time(void)
{
	unsigned long long t1, t2;
	struct timeval tv;
	t1 = comedi_get_rawtime();
	do_gettimeofday(&tv);
	t2 = 1000000000 * ((unsigned long long)tv.tv_sec) +
	    1000000 * ((unsigned long long)tv.tv_usec);
	comedi_clkofs = t2 - t1;
}

unsigned long long comedi_get_time(void)
{
	return comedi_clkofs + comedi_get_rawtime();
}

/* --- IRQ section --- */

static int comedi_handle_irq(rtdm_irq_t * irq_handle)
{
	comedi_irq_desc_t *dsc =
	    rtdm_irq_get_arg(irq_handle, comedi_irq_desc_t);

	if (dsc->handler((unsigned int)irq_handle->irq, dsc->cookie) == 0)
		return RTDM_IRQ_HANDLED;
	else
		return RTDM_IRQ_NONE;
}

int __comedi_request_irq(comedi_irq_desc_t * dsc,
			 unsigned int irq,
			 comedi_irq_hdlr_t handler,
			 unsigned long flags, void *cookie)
{
	/* Fills the IRQ descriptor */
	dsc->handler = handler;
	dsc->cookie = cookie;
	dsc->irq = irq;

	/* Registers the RT IRQ handler */
	return rtdm_irq_request(&dsc->rtdm_desc,
				(int)irq,
				comedi_handle_irq, flags, "Comedi device", dsc);
}

int __comedi_free_irq(comedi_irq_desc_t * dsc)
{
	return rtdm_irq_free(&dsc->rtdm_desc);
}

/* --- Synchronization section --- */

static void comedi_nrt_sync_handler(rtdm_nrtsig_t nrt_sig, void *arg)
{
	comedi_sync_t *snc = (comedi_sync_t *) arg;
	wake_up_interruptible(&snc->wq);
}

int comedi_init_sync(comedi_sync_t * snc)
{
	int ret = 0;

	/* Initializes the flags field */
	snc->status = 0;

	/* If the process is NRT, we need a wait queue structure */
	init_waitqueue_head(&snc->wq);

	/* Initializes the RTDM event */
	rtdm_event_init(&snc->rtdm_evt, 0);

	/* Initializes the gateway to NRT context */
	ret = rtdm_nrtsig_init(&snc->nrt_sig, comedi_nrt_sync_handler, snc);

	return ret;
}

void comedi_cleanup_sync(comedi_sync_t * snc)
{
	rtdm_nrtsig_destroy(&snc->nrt_sig);
	rtdm_event_destroy(&snc->rtdm_evt);
}

int comedi_wait_sync(comedi_sync_t * snc, int rt)
{
	int ret = 0;

	if (test_bit(__EVT_PDING, &snc->status))
		goto out_wait;

	if (rt != 0) {
		/* If the calling process is in primary mode,
		   we can use RTDM API ... */
		set_bit(__RT_WAITER, &snc->status);
		ret = rtdm_event_wait(&snc->rtdm_evt);
	} else {
		/* ... else if the process is NRT, 
		   the Linux wait queue system is used */
		set_bit(__NRT_WAITER, &snc->status);
		ret = wait_event_interruptible(snc->wq,
					       test_bit(__EVT_PDING,
							&snc->status));
	}

      out_wait:

	clear_bit(__EVT_PDING, &snc->status);

	return ret;
}

int comedi_timedwait_sync(comedi_sync_t * snc,
			  int rt, unsigned long long ns_timeout)
{
	int ret = 0;
	unsigned long timeout;

	if (test_bit(__EVT_PDING, &snc->status))
		goto out_wait;

	if (rt != 0) {
		/* If the calling process is in primary mode,
		   we can use RTDM API ... */
		set_bit(__RT_WAITER, &snc->status);
		ret = rtdm_event_timedwait(&snc->rtdm_evt, ns_timeout, NULL);
	} else {
		/* ... else if the process is NRT, 
		   the Linux wait queue system is used */

		timeout = do_div(ns_timeout, 1000);

		/* We consider the Linux kernel cannot tick at a frequency
		   higher than 1 MHz 
		   If the timeout value is lower than 1us, we round up to 1us */
		timeout = (timeout == 0) ? 1 : usecs_to_jiffies(timeout);

		set_bit(__NRT_WAITER, &snc->status);

		ret = wait_event_interruptible_timeout(snc->wq,
						       test_bit(__EVT_PDING,
								&snc->status),
						       timeout);
	}

      out_wait:

	clear_bit(__EVT_PDING, &snc->status);

	return ret;
}

void comedi_signal_sync(comedi_sync_t * snc)
{
	int hit = 0;

	set_bit(__EVT_PDING, &snc->status);

	/* comedi_signal_sync() is bound not to be called upon the right
	   user process context; so, the status flags stores its mode.
	   Thus the proper event signaling function is called */

	if (test_and_clear_bit(__RT_WAITER, &snc->status))
		rtdm_event_signal(&snc->rtdm_evt);

	if (test_and_clear_bit(__NRT_WAITER, &snc->status))
		rtdm_nrtsig_pend(&snc->nrt_sig);

	if (hit == 0) {
		/* At first signaling, we may not know the proper way
		   to send the event */
		rtdm_event_signal(&snc->rtdm_evt);
		rtdm_nrtsig_pend(&snc->nrt_sig);
	}
}

#endif /* !DOXYGEN_CPP */
