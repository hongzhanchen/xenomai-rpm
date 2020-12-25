/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2001-2014 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2001-2014 The Xenomai project <http://www.xenomai.org>
 * Copyright (C) 2006 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 *
 * SMP support Copyright (C) 2004 The HYADES project <http://www.hyades-itea.org>
 * RTAI/fusion Copyright (C) 2004 The RTAI project <http://www.rtai.org>
 */

#include <linux/ptrace.h>
#include <pipeline/kevents.h>
#include <cobalt/kernel/sched.h>
#include <cobalt/kernel/thread.h>
#include <cobalt/kernel/clock.h>
#include <cobalt/kernel/vdso.h>
#include <rtdm/driver.h>
#include <trace/events/cobalt-core.h>
#include "../posix/process.h"
#include "../posix/thread.h"
#include "../posix/memory.h"

static void detach_current(void);

static inline struct cobalt_process *
process_from_thread(struct xnthread *thread)
{
	return container_of(thread, struct cobalt_thread, threadbase)->process;
}

static inline void stop_debugged_process(struct xnthread *thread)
{
}

static inline void resume_debugged_process(struct cobalt_process *process)
{
}

/* called with nklock held */
static void register_debugged_thread(struct xnthread *thread)
{
	struct cobalt_process *process = process_from_thread(thread);

	xnthread_set_state(thread, XNSSTEP);

	stop_debugged_process(thread);
	process->debugged_threads++;

	if (xnthread_test_state(thread, XNRELAX))
		xnthread_suspend(thread, XNDBGSTOP, XN_INFINITE, XN_RELATIVE,
				 NULL);
}

/* called with nklock held */
static void unregister_debugged_thread(struct xnthread *thread)
{
	struct cobalt_process *process = process_from_thread(thread);

	process->debugged_threads--;
	xnthread_clear_state(thread, XNSSTEP);

	if (process->debugged_threads == 0)
		resume_debugged_process(process);
}

static inline int handle_exception(struct xnarch_fault_data *d)
{
	struct xnthread *thread;
	struct xnsched *sched;

	sched = xnsched_current();
	thread = sched->curr;

//	trace_cobalt_thread_fault(xnarch_fault_pc(d),
//				  xnarch_fault_trap(d));

	if (xnthread_test_state(thread, XNROOT))
		return 0;

#ifdef IPIPE_KEVT_USERINTRET
	if (xnarch_fault_bp_p(d) && user_mode(d->regs)) {
		spl_t s;

		XENO_WARN_ON(CORE, xnthread_test_state(thread, XNRELAX));
		xnlock_get_irqsave(&nklock, s);
		xnthread_set_info(thread, XNCONTHI);
		ipipe_enable_user_intret_notifier();
		stop_debugged_process(thread);
		xnlock_put_irqrestore(&nklock, s);
		xnsched_run();
	}
#endif

	if (xnarch_fault_fpu_p(d)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
		printk("invalid use of FPU in Xenomai context at %pS\n",
		       (void *)xnarch_fault_pc(d));
#else
		print_symbol("invalid use of FPU in Xenomai context at %s\n",
			     xnarch_fault_pc(d));
#endif
	}

	/*
	 * If we experienced a trap on behalf of a shadow thread
	 * running in primary mode, move it to the Linux domain,
	 * leaving the kernel process the exception.
	 */
#if defined(CONFIG_XENO_OPT_DEBUG_COBALT) || defined(CONFIG_XENO_OPT_DEBUG_USER)
	if (!user_mode(d->regs)) {
		xntrace_panic_freeze();
		printk(XENO_WARNING
		       "switching %s to secondary mode after exception #%u in "
		       "kernel-space at 0x%lx (pid %d)\n", thread->name,
		       xnarch_fault_trap(d),
		       xnarch_fault_pc(d),
		       xnthread_host_pid(thread));
		xntrace_panic_dump();
	} else if (xnarch_fault_notify(d)) /* Don't report debug traps */
		printk(XENO_WARNING
		       "switching %s to secondary mode after exception #%u from "
		       "user-space at 0x%lx (pid %d)\n", thread->name,
		       xnarch_fault_trap(d),
		       xnarch_fault_pc(d),
		       xnthread_host_pid(thread));
#endif

	if (xnarch_fault_pf_p(d))
		/*
		 * The page fault counter is not SMP-safe, but it's a
		 * simple indicator that something went wrong wrt
		 * memory locking anyway.
		 */
		xnstat_counter_inc(&thread->stat.pf);

	xnthread_relax(xnarch_fault_notify(d), SIGDEBUG_MIGRATE_FAULT);

	return 0;
}

void handle_oob_trap_entry(unsigned int trapnr, struct pt_regs *regs)
{
	struct xnarch_fault_data data = {
		.exception = trapnr,
		.regs = regs,
	};

	handle_exception(&data);
}

#ifdef CONFIG_SMP

static int handle_setaffinity_event(struct dovetail_migration_data *d)
{
	struct task_struct *p = d->task;
	struct xnthread *thread;
	spl_t s;

	thread = xnthread_from_task(p);
	if (thread == NULL)
		return KEVENT_PROPAGATE;

	/*
	 * Detect a Cobalt thread sleeping in primary mode which is
	 * required to migrate to another CPU by the host kernel.
	 *
	 * We may NOT fix up thread->sched immediately using the
	 * passive migration call, because that latter always has to
	 * take place on behalf of the target thread itself while
	 * running in secondary mode. Therefore, that thread needs to
	 * go through secondary mode first, then move back to primary
	 * mode, so that affinity_ok() does the fixup work.
	 *
	 * We force this by sending a SIGSHADOW signal to the migrated
	 * thread, asking it to switch back to primary mode from the
	 * handler, at which point the interrupted syscall may be
	 * restarted.
	 */
	xnlock_get_irqsave(&nklock, s);

	if (xnthread_test_state(thread, XNTHREAD_BLOCK_BITS & ~XNRELAX))
		xnthread_signal(thread, SIGSHADOW, SIGSHADOW_ACTION_HARDEN);

	xnlock_put_irqrestore(&nklock, s);

	return KEVENT_PROPAGATE;
}

static inline bool affinity_ok(struct task_struct *p) /* nklocked, IRQs off */
{
	struct xnthread *thread = xnthread_from_task(p);
	struct xnsched *sched;
	int cpu = task_cpu(p);

	/*
	 * To maintain consistency between both Cobalt and host
	 * schedulers, reflecting a thread migration to another CPU
	 * into the Cobalt scheduler state must happen from secondary
	 * mode only, on behalf of the migrated thread itself once it
	 * runs on the target CPU.
	 *
	 * This means that the Cobalt scheduler state regarding the
	 * CPU information lags behind the host scheduler state until
	 * the migrated thread switches back to primary mode
	 * (i.e. task_cpu(p) != xnsched_cpu(xnthread_from_task(p)->sched)).
	 * This is ok since Cobalt does not schedule such thread until then.
	 *
	 * check_affinity() detects when a Cobalt thread switching
	 * back to primary mode did move to another CPU earlier while
	 * in secondary mode. If so, do the fixups to reflect the
	 * change.
	 */
	if (!xnsched_threading_cpu(cpu)) {
		/*
		 * The thread is about to switch to primary mode on a
		 * non-rt CPU, which is damn wrong and hopeless.
		 * Whine and cancel that thread.
		 */
		printk(XENO_WARNING "thread %s[%d] switched to non-rt CPU%d, aborted.\n",
		       thread->name, xnthread_host_pid(thread), cpu);
		/*
		 * Can't call xnthread_cancel() from a migration
		 * point, that would break. Since we are on the wakeup
		 * path to hardening, just raise XNCANCELD to catch it
		 * in xnthread_harden().
		 */
		xnthread_set_info(thread, XNCANCELD);
		return false;
	}

	sched = xnsched_struct(cpu);
	if (sched == thread->sched)
		return true;

	/*
	 * The current thread moved to a supported real-time CPU,
	 * which is not part of its original affinity mask
	 * though. Assume user wants to extend this mask.
	 */
	if (!cpumask_test_cpu(cpu, &thread->affinity))
		cpumask_set_cpu(cpu, &thread->affinity);

	xnthread_run_handler_stack(thread, move_thread, cpu);
	xnthread_migrate_passive(thread, sched);

	return true;
}

#else /* !CONFIG_SMP */

static int handle_setaffinity_event(struct dovetail_migration_data *d)
{
	return KEVENT_PROPAGATE;
}

static inline bool affinity_ok(struct task_struct *p)
{
	return true;
}

#endif /* CONFIG_SMP */

static int handle_mayday_event(struct pt_regs *regs)
{
	XENO_BUG_ON(COBALT, !xnthread_test_state(xnthread_current(), XNUSER));

	xnthread_relax(0, 0);

	return KEVENT_PROPAGATE;
}

static void __handle_taskexit_event(struct task_struct *p)
{
	struct cobalt_ppd *sys_ppd;
	struct xnthread *thread;
	spl_t s;

	/*
	 * We are called for both kernel and user shadows over the
	 * root thread.
	 */
	secondary_mode_only();

	thread = xnthread_current();
	XENO_BUG_ON(COBALT, thread == NULL);
	trace_cobalt_shadow_unmap(thread);

	xnlock_get_irqsave(&nklock, s);

	if (xnthread_test_state(thread, XNSSTEP))
		unregister_debugged_thread(thread);

	xnsched_run();

	xnlock_put_irqrestore(&nklock, s);

	xnthread_run_handler_stack(thread, exit_thread);

	if (xnthread_test_state(thread, XNUSER)) {
		cobalt_umm_free(&cobalt_kernel_ppd.umm, thread->u_window);
		thread->u_window = NULL;
		sys_ppd = cobalt_ppd_get(0);
		if (atomic_dec_and_test(&sys_ppd->refcnt))
			cobalt_remove_process(cobalt_current_process());
	}
}

static int handle_taskexit_event(struct task_struct *p) /* p == current */
{
	__handle_taskexit_event(p);

	/*
	 * __xnthread_cleanup() -> ... -> finalize_thread
	 * handler. From that point, the TCB is dropped. Be careful of
	 * not treading on stale memory within @thread.
	 */
	__xnthread_cleanup(xnthread_current());

	detach_current();

	return KEVENT_PROPAGATE;
}
#if 0
static int handle_schedule_event(struct task_struct *next_task)
{
	struct task_struct *prev_task;
	struct xnthread *next;
	sigset_t pending;
	spl_t s;

	cobalt_signal_yield();

	prev_task = current;
	next = xnthread_from_task(next_task);
	if (next == NULL)
		goto out;

	xnlock_get_irqsave(&nklock, s);

	/*
	 * Track tasks leaving the ptraced state.  Check both SIGSTOP
	 * (NPTL) and SIGINT (LinuxThreads) to detect ptrace
	 * continuation.
	 */
	if (xnthread_test_state(next, XNSSTEP)) {
		if (signal_pending(next_task)) {
			/*
			 * Do not grab the sighand lock here: it's
			 * useless, and we already own the runqueue
			 * lock, so this would expose us to deadlock
			 * situations on SMP.
			 */
			sigorsets(&pending,
				  &next_task->pending.signal,
				  &next_task->signal->shared_pending.signal);
			if (sigismember(&pending, SIGSTOP) ||
			    sigismember(&pending, SIGINT))
				goto no_ptrace;
		}

		/*
		 * Do not unregister before the thread migrated.
		 * unregister_debugged_thread will then be called by our
		 * ipipe_migration_hook.
		 */
		if (!xnthread_test_info(next, XNCONTHI))
			unregister_debugged_thread(next);

		xnthread_set_localinfo(next, XNHICCUP);
	}

no_ptrace:
	xnlock_put_irqrestore(&nklock, s);

	/*
	 * Do basic sanity checks on the incoming thread state.
	 * NOTE: we allow ptraced threads to run shortly in order to
	 * properly recover from a stopped state.
	 */
	if (!XENO_WARN(COBALT, !xnthread_test_state(next, XNRELAX),
		       "hardened thread %s[%d] running in Linux domain?! "
		       "(status=0x%x, sig=%d, prev=%s[%d])",
		       next->name, task_pid_nr(next_task),
		       xnthread_get_state(next),
		       signal_pending(next_task),
		       prev_task->comm, task_pid_nr(prev_task)))
		XENO_WARN(COBALT,
			  !(next_task->ptrace & PT_PTRACED) &&
			   !xnthread_test_state(next, XNDORMANT)
			  && xnthread_test_state(next, XNPEND),
			  "blocked thread %s[%d] rescheduled?! "
			  "(status=0x%x, sig=%d, prev=%s[%d])",
			  next->name, task_pid_nr(next_task),
			  xnthread_get_state(next),
			  signal_pending(next_task), prev_task->comm,
			  task_pid_nr(prev_task));
out:
	return KEVENT_PROPAGATE;
}

#endif


static int handle_user_return(struct task_struct *task)
{
	struct xnthread *thread;
	spl_t s;
	int err;

	dovetail_clear_ucall();

	thread = xnthread_from_task(task);
	if (thread == NULL)
		return KEVENT_PROPAGATE;

	if (xnthread_test_info(thread, XNCONTHI)) {
		xnlock_get_irqsave(&nklock, s);
		xnthread_clear_info(thread, XNCONTHI);
		xnlock_put_irqrestore(&nklock, s);

		err = xnthread_harden();

		/*
		 * XNCONTHI may or may not have been re-applied if
		 * harden bailed out due to pending signals. Make sure
		 * it is set in that case.
		 */
		if (err == -ERESTARTSYS) {
			xnlock_get_irqsave(&nklock, s);
			xnthread_set_info(thread, XNCONTHI);
			xnlock_put_irqrestore(&nklock, s);
		}
	}

	return KEVENT_PROPAGATE;
}

void handle_oob_mayday(struct pt_regs *regs)
{
	XENO_BUG_ON(COBALT, !xnthread_test_state(xnthread_current(), XNUSER));

	xnthread_relax(0, 0);
}

static int handle_sigwake_event(struct task_struct *p)
{
	struct xnthread *thread;
	sigset_t pending;
	spl_t s;

	thread = xnthread_from_task(p);
	if (thread == NULL)
		return KEVENT_PROPAGATE;

	xnlock_get_irqsave(&nklock, s);

	/*
	 * CAUTION: __TASK_TRACED is not set in p->state yet. This
	 * state bit will be set right after we return, when the task
	 * is woken up.
	 */
	if ((p->ptrace & PT_PTRACED) && !xnthread_test_state(thread, XNSSTEP)) {
		/* We already own the siglock. */
		sigorsets(&pending,
			  &p->pending.signal,
			  &p->signal->shared_pending.signal);

		if (sigismember(&pending, SIGTRAP) ||
		    sigismember(&pending, SIGSTOP)
		    || sigismember(&pending, SIGINT))
			register_debugged_thread(thread);
	}

	if (xnthread_test_state(thread, XNRELAX))
		goto out;

	/*
	 * If kicking a shadow thread in primary mode, make sure Linux
	 * won't schedule in its mate under our feet as a result of
	 * running signal_wake_up(). The Xenomai scheduler must remain
	 * in control for now, until we explicitly relax the shadow
	 * thread to allow for processing the pending signals. Make
	 * sure we keep the additional state flags unmodified so that
	 * we don't break any undergoing ptrace.
	 */
//	if (p->state & (TASK_INTERRUPTIBLE|TASK_UNINTERRUPTIBLE))
//		cobalt_set_task_state(p, p->state | TASK_NOWAKEUP);

	/*
	 * Allow a thread stopped for debugging to resume briefly in order to
	 * migrate to secondary mode. xnthread_relax will reapply XNDBGSTOP.
	 */
	if (xnthread_test_state(thread, XNDBGSTOP))
		xnthread_resume(thread, XNDBGSTOP);

	__xnthread_kick(thread);
out:
	xnsched_run();

	xnlock_put_irqrestore(&nklock, s);

	return KEVENT_PROPAGATE;
}

static int handle_cleanup_event(struct mm_struct *mm)
{
	struct cobalt_process *old, *process;
	struct cobalt_ppd *sys_ppd;
	struct xnthread *curr;

	/*
	 * We are NOT called for exiting kernel shadows.
	 * cobalt_current_process() is cleared if we get there after
	 * handle_task_exit(), so we need to restore this context
	 * pointer temporarily.
	 */
	process = cobalt_search_process(mm);
	old = cobalt_set_process(process);
	sys_ppd = cobalt_ppd_get(0);
	if (sys_ppd != &cobalt_kernel_ppd) {
		bool running_exec;

		/*
		 * Detect a userland shadow running exec(), i.e. still
		 * attached to the current linux task (no prior
		 * detach_current). In this case, we emulate a task
		 * exit, since the Xenomai binding shall not survive
		 * the exec() syscall. Since the process will keep on
		 * running though, we have to disable the event
		 * notifier manually for it.
		 */
		curr = xnthread_current();
		running_exec = curr && (current->flags & PF_EXITING) == 0;
		if (running_exec) {
			__handle_taskexit_event(current);
			dovetail_stop_altsched();
		}
		if (atomic_dec_and_test(&sys_ppd->refcnt))
			cobalt_remove_process(process);
		if (running_exec) {
			__xnthread_cleanup(curr);
			detach_current();
		}
	}

	/*
	 * CAUTION: Do not override a state change caused by
	 * cobalt_remove_process().
	 */
	if (cobalt_current_process() == process)
		cobalt_set_process(old);

	return KEVENT_PROPAGATE;
}

static inline int handle_clockfreq_event(unsigned int *p)
{
	unsigned int newfreq = *p;

	pipeline_update_clock_freq(newfreq);

	return KEVENT_PROPAGATE;
}

void handle_inband_event(enum inband_event_type event, void *data)
{
	switch (event) {
	case INBAND_TASK_SIGNAL:
		handle_sigwake_event(data);
		break;
	case INBAND_TASK_MIGRATION:
		handle_setaffinity_event(data);
		break;
	case INBAND_TASK_EXIT:
		if (xnthread_current())
			handle_taskexit_event(current);
		break;
	case INBAND_TASK_RETUSER:
		handle_user_return(data);
		break;
	case INBAND_TASK_PTSTEP:
	case INBAND_TASK_PTSTOP:
	case INBAND_TASK_PTCONT:
		break;
	case INBAND_PROCESS_CLEANUP:
		handle_cleanup_event(data);
		break;
	}
}

#ifdef CONFIG_MMU
static inline int disable_ondemand_memory(void)
{
	struct task_struct *p = current;
	kernel_siginfo_t si;

	if ((p->mm->def_flags & VM_LOCKED) == 0) {
		memset(&si, 0, sizeof(si));
		si.si_signo = SIGDEBUG;
		si.si_code = SI_QUEUE;
		si.si_int = SIGDEBUG_NOMLOCK | sigdebug_marker;
		send_sig_info(SIGDEBUG, &si, p);
		return 0;
	}

	return force_commit_memory();
}

int pipeline_prepare_current(void)
{
	return disable_ondemand_memory();
}

static inline int get_mayday_prot(void)
{
	return PROT_READ|PROT_EXEC;
}

#else /* !CONFIG_MMU */

int pipeline_prepare_current(void)
{
	return 0;
}

static inline int get_mayday_prot(void)
{
	/*
	 * Until we stop backing /dev/mem with the mayday page, we
	 * can't ask for PROT_EXEC since the former does not define
	 * mmap capabilities, and default ones won't allow an
	 * executable mapping with MAP_SHARED. In the NOMMU case, this
	 * is (currently) not an issue.
	 */
	return PROT_READ;
}

#endif /* !CONFIG_MMU */

void pipeline_attach_current(struct xnthread *thread)
{
	struct cobalt_threadinfo *p;

	p = pipeline_current();
	p->thread = thread;
	p->process = cobalt_search_process(current->mm);
	dovetail_init_altsched(&thread->altsched);
}

static void detach_current(void)
{
	struct cobalt_threadinfo *p = pipeline_current();
	p->thread = NULL;
	p->process = NULL;
}

int pipeline_trap_kevents(void)
{
	//chz NTD
	return 0;
}

void pipeline_enable_kevents(void)
{
	dovetail_start_altsched();
}
