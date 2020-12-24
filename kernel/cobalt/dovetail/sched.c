/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2001-2020 Philippe Gerum <rpm@xenomai.org>.
 */

#include <cobalt/kernel/thread.h>
#include <cobalt/kernel/sched.h>
#include <pipeline/sched.h>
#include <trace/events/cobalt-core.h>

void pipeline_prep_switch_oob(struct xnthread *root)
{
	struct xnarchtcb *rootcb = xnthread_archtcb(root);
	struct task_struct *p = current;

	rootcb->core.host_task = p;
	rootcb->core.tsp = &p->thread;
	rootcb->core.mm = rootcb->core.active_mm = current->active_mm;
	rootcb->core.tip = task_thread_info(p);
}

static inline void giveup_fpu(struct xnthread *thread)
{
}


bool pipeline_switch_to(struct xnthread *prev, struct xnthread *next,
			bool leaving_inband)
{
	dovetail_context_switch(&prev->altsched,
					&next->altsched, leaving_inband);
	/*
	 * Test whether we transitioned from OOB to in-band
	 * over a shadow thread, caused by a call to xnthread_relax().
	 * In such a case, we are running over the regular schedule()
	 * tail code, so we have to tell the caller to skip the Cobalt
	 * tail code.
	 */
	if (!leaving_inband && running_inband()) {
//chz: NTD double check __ipipe_complete_domain_migratiddon
		//__ipipe_complete_domain_migratiddon();
		XENO_BUG_ON(COBALT, xnthread_current() == NULL);
		/*
		 * Interrupts must be disabled here (has to be done on
		 * entry of the Linux [__]switch_to function), but it
		 * is what callers expect, specifically the reschedule
		 * of an IRQ handler that hit before we call
		 * xnsched_run in xnthread_suspend() when relaxing a
		 * thread.
		 */
		XENO_BUG_ON(COBALT, !hard_irqs_disabled());
		return true;
	}
	return false;
}

void pipeline_init_shadow_tcb(struct xnthread *thread)
{
	struct xnarchtcb *tcb = xnthread_archtcb(thread);
	struct task_struct *p = current;

	dovetail_init_altsched(&thread->altsched);

	tcb->core.host_task = p;
	tcb->core.tsp = &p->thread;
	tcb->core.mm = p->mm;
	tcb->core.active_mm = p->mm;
	tcb->core.tip = task_thread_info(p);

	trace_cobalt_shadow_map(thread);
}

void pipeline_init_root_tcb(struct xnthread *thread)
{
	struct xnarchtcb *tcb = xnthread_archtcb(thread);
	struct task_struct *p = current;

	tcb->core.host_task = p;
	tcb->core.tsp = &tcb->core.ts;
	tcb->core.mm = p->mm;
	tcb->core.tip = NULL;
}

int pipeline_leave_inband(void)
{
	return dovetail_leave_inband();
}

int pipeline_leave_oob_prepare(void)
{
	dovetail_leave_oob();
//chz: NTD double check what should return
	return 0;
}

void pipeline_leave_oob_finish(void)
{
	dovetail_resume_inband();
}

void pipeline_finalize_thread(struct xnthread *thread)
{
	giveup_fpu(thread);
}

void pipeline_raise_mayday(struct task_struct *tsk)
{
	dovetail_send_mayday(tsk);
}

void pipeline_clear_mayday(void) /* May solely affect current. */
{
	clear_thread_flag(TIF_MAYDAY);
}
