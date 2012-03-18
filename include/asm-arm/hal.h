/**
 *   @ingroup hal
 *   @file
 *
 *   Real-Time Hardware Abstraction Layer for ARM.
 *
 *   Copyright &copy; 2002-2004 Philippe Gerum.
 *
 *   ARM port
 *     Copyright (C) 2005 Stelian Pop
 *
 *   Xenomai is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, Inc., 675 Mass Ave,
 *   Cambridge MA 02139, USA; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   Xenomai is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Xenomai; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

#ifndef _XENO_ASM_ARM_HAL_H
#define _XENO_ASM_ARM_HAL_H

#include <asm-generic/xenomai/hal.h>	/* Read the generic bits. */
#include <asm/byteorder.h>

#define RTHAL_ARCH_NAME "arm"

#ifdef CONFIG_VFP
#include <asm/vfp.h>
#endif /* CONFIG_VFP */

#ifndef CONFIG_IPIPE_CORE

#if defined(CONFIG_ARCH_AT91)
#include <linux/stringify.h>
#define RTHAL_TIMER_DEVICE	"at91_tc" __stringify(CONFIG_IPIPE_AT91_TC)
#define RTHAL_CLOCK_DEVICE	"at91_tc" __stringify(CONFIG_IPIPE_AT91_TC)
#elif defined(CONFIG_ARCH_IMX)
#define RTHAL_TIMER_DEVICE	"imx_timer1"
#define RTHAL_CLOCK_DEVICE	"imx_timer1"
#elif defined(CONFIG_ARCH_IMX21)
#define RTHAL_TIMER_DEVICE	"TCMP"
#define RTHAL_CLOCK_DEVICE	"TCN"
#elif defined(CONFIG_ARCH_INTEGRATOR)
#define RTHAL_TIMER_DEVICE	"TIMER1"
#define RTHAL_CLOCK_DEVICE	"TIMER1"
#elif defined(CONFIG_ARCH_IXP4XX)
#define RTHAL_TIMER_DEVICE	"ixp4xx timer1"
#define RTHAL_CLOCK_DEVICE	"OSTS"
#elif defined(CONFIG_ARCH_MXC) && !defined(CONFIG_SMP)
#define RTHAL_TIMER_DEVICE	"mxc_timer1"
#define RTHAL_CLOCK_DEVICE	"mxc_timer1"
#elif defined(CONFIG_ARCH_OMAP3)
#ifdef CONFIG_ARCH_OMAP4
#error "xenomai does not support multi-omap configuration"
#endif /* multi-omap */
#define RTHAL_TIMER_DEVICE	"gp timer"
#define RTHAL_CLOCK_DEVICE	"gp timer"
#elif defined(CONFIG_ARCH_OMAP4)
#ifdef CONFIG_ARCH_OMAP3
#error "xenomai does not support multi-omap configuration"
#endif /* multi-omap */
#define RTHAL_TIMER_DEVICE					\
	num_online_cpus() == 1 ? "gp timer" : "local_timer"
#define RTHAL_CLOCK_DEVICE					\
	num_online_cpus() == 1 ? "gp timer" : "global_timer"
#elif defined(CONFIG_PLAT_ORION)
#define RTHAL_TIMER_DEVICE	"orion_tick"
#define RTHAL_CLOCK_DEVICE	"orion_clocksource"
#elif defined(CONFIG_ARCH_PXA)
#define RTHAL_TIMER_DEVICE	"osmr0"
#define RTHAL_CLOCK_DEVICE	"oscr0"
#elif defined(CONFIG_ARCH_S3C2410)
#define RTHAL_TIMER_DEVICE	"TCNTB4"
#define RTHAL_CLOCK_DEVICE	"TCNTO3"
#elif defined(CONFIG_ARCH_SA1100)
#define RTHAL_TIMER_DEVICE	"osmr0"
#define RTHAL_CLOCK_DEVICE	"oscr0"
#elif defined(CONFIG_SMP) && defined(CONFIG_HAVE_ARM_TWD)
#define RTHAL_TIMER_DEVICE	"local_timer"
#define RTHAL_CLOCK_DEVICE	"global_timer"
#else
#error "Unsupported ARM machine"
#endif /* CONFIG_ARCH_SA1100 */

#else /* I-ipipe core */

#define RTHAL_TIMER_DEVICE (ipipe_timer_name())
#define RTHAL_CLOCK_DEVICE "ipipe_tsc"

#endif /* I-ipipe core */

#define RTHAL_HOST_TICK_IRQ RTHAL_TIMER_IRQ

typedef unsigned long long rthal_time_t;

#if __LINUX_ARM_ARCH__ < 5
static inline __attribute_const__ unsigned long ffnz(unsigned long x)
{
	int r = 0;

	if (!x)
		return 0;
	if (!(x & 0xffff)) {
		x >>= 16;
		r += 16;
	}
	if (!(x & 0xff)) {
		x >>= 8;
		r += 8;
	}
	if (!(x & 0xf)) {
		x >>= 4;
		r += 4;
	}
	if (!(x & 3)) {
		x >>= 2;
		r += 2;
	}
	if (!(x & 1)) {
		x >>= 1;
		r += 1;
	}
	return r;
}
#else
static inline __attribute_const__ unsigned long ffnz(unsigned long ul)
{
	int __r;
	__asm__("clz\t%0, %1" : "=r" (__r) : "r"(ul & (-ul)) : "cc");
	return 31 - __r;
}
#endif

#ifndef __cplusplus
#include <asm/system.h>
#include <asm/timex.h>
#include <asm/xenomai/atomic.h>
#include <asm/processor.h>
#include <asm/ipipe.h>
#include <asm/mach/irq.h>
#include <asm/cacheflush.h>

#ifndef RTHAL_TIMER_IRQ
/*
 * Default setting, unless pre-set in the machine-dependent section.
 */
#define RTHAL_TIMER_IRQ		__ipipe_mach_hrtimer_irq
#endif /* RTHAL_TIMER_IRQ */

#ifndef RTHAL_TIMER_IPI
#define RTHAL_TIMER_IPI IPIPE_HRTIMER_IPI
#endif /* RTHAL_TIMER_IPI */

#ifdef CONFIG_IPIPE_CORE
#define RTHAL_TSC_INFO(p)	((p)->arch.tsc)
#else /* !CONFIG_IPIPE_CORE */
#define RTHAL_TSC_INFO(p)	((p)->arch_tsc)
#endif  /* !CONFIG_IPIPE_CORE */

#define RTHAL_SHARED_HEAP_FLAGS (cache_is_vivt() ? XNHEAP_GFP_NONCACHED : 0)

#define rthal_grab_control()     do { } while(0)
#define rthal_release_control()  do { } while(0)

static inline unsigned long long rthal_rdtsc(void)
{
	unsigned long long t;
	ipipe_read_tsc(t);
	return t;
}

static inline struct task_struct *rthal_current_host_task(int cpuid)
{
	return current;
}

static inline void rthal_timer_program_shot(unsigned long delay)
{
#ifndef CONFIG_IPIPE_CORE
	if (delay == 0)
		ipipe_post_irq_head(RTHAL_TIMER_IRQ);
	else
		__ipipe_mach_set_dec(delay);
#else /* I-pipe core */
	ipipe_timer_set(delay);
#endif /* I-pipe core */
}

/* Private interface -- Internal use only */

asmlinkage void rthal_thread_switch(struct task_struct *prev,
				    struct thread_info *out,
				    struct thread_info *in);

asmlinkage void rthal_thread_trampoline(void);

#ifdef CONFIG_XENO_HW_FPU

typedef struct rthal_fpenv {

	/*
	 * This layout must follow exactely the definition of the FPU
	 *  area in the ARM thread_info structure. 'tp_value' is also
	 *  saved even if it is not needed, but it shouldn't matter.
	 */
	__u8                    used_cp[16];    /* thread used copro */
	unsigned long           tp_value;
	struct crunch_state     crunchstate;
	union fp_state          fpstate __attribute__((aligned(8)));
	union vfp_state         vfpstate;
} rthal_fpenv_t;

static inline void rthal_init_fpu(rthal_fpenv_t *fpuenv)
{
	fp_init(&fpuenv->fpstate);
#if defined(CONFIG_VFP)
	/* vfpstate has already been zeroed by xnarch_init_fpu */
	fpuenv->vfpstate.hard.fpexc = FPEXC_EN;
	fpuenv->vfpstate.hard.fpscr = FPSCR_ROUND_NEAREST;
#endif
}

#define rthal_task_fpenv(task)					\
	((rthal_fpenv_t *) &task_thread_info(task)->used_cp[0])

#ifdef CONFIG_VFP
asmlinkage void rthal_vfp_save(union vfp_state *vfp, unsigned fpexc);

asmlinkage void rthal_vfp_load(union vfp_state *vfp, unsigned cpu);

static inline void rthal_save_fpu(rthal_fpenv_t *fpuenv, unsigned fpexc)
{
	rthal_vfp_save(&fpuenv->vfpstate, fpexc);
}

static inline void rthal_restore_fpu(rthal_fpenv_t *fpuenv)
{
	rthal_vfp_load(&fpuenv->vfpstate, ipipe_processor_id());
}

#define rthal_vfp_fmrx(_vfp_) ({					\
			u32 __v;					\
			asm volatile("mrc p10, 7, %0, " __stringify(_vfp_) \
				     ", cr0, 0 @ fmrx %0, " #_vfp_:	\
				     "=r" (__v));			\
			__v;						\
		})

#define rthal_vfp_fmxr(_vfp_,_var_)				\
	asm volatile("mcr p10, 7, %0, " __stringify(_vfp_)	\
		     ", cr0, 0 @ fmxr " #_vfp_ ", %0":		\
		     /* */ : "r" (_var_))

extern union vfp_state *vfp_current_hw_state[NR_CPUS];

static inline rthal_fpenv_t *rthal_get_fpu_owner(void)
{
	union vfp_state *vfp_owner;
	unsigned cpu;
#ifdef CONFIG_SMP
	unsigned fpexc;

	fpexc = rthal_vfp_fmrx(FPEXC);
	if (!(fpexc & FPEXC_EN))
		return NULL;
#endif

	cpu = ipipe_processor_id();
	vfp_owner = vfp_current_hw_state[cpu];
	if (!vfp_owner)
		return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0) && defined(CONFIG_SMP)
	if (vfp_owner->hard.cpu != cpu)
		return NULL;
#endif /* linux >= 3.2.0 */

	return container_of(vfp_owner, rthal_fpenv_t, vfpstate);
}

#define rthal_disable_fpu()						\
	rthal_vfp_fmxr(FPEXC, rthal_vfp_fmrx(FPEXC) & ~FPEXC_EN)

#define RTHAL_VFP_ANY_EXC						\
	(FPEXC_EX|FPEXC_DEX|FPEXC_FP2V|FPEXC_VV|FPEXC_TRAP_MASK)

#define rthal_enable_fpu()						\
	({								\
		unsigned _fpexc = rthal_vfp_fmrx(FPEXC) | FPEXC_EN;	\
		rthal_vfp_fmxr(FPEXC, _fpexc & ~RTHAL_VFP_ANY_EXC);	\
		_fpexc;							\
	})

#else /* !CONFIG_VFP */
static inline void rthal_save_fpu(rthal_fpenv_t *fpuenv)
{
}

static inline void rthal_restore_fpu(rthal_fpenv_t *fpuenv)
{
}

#define rthal_get_fpu_owner(cur) ({					\
			struct task_struct * _cur = (cur);		\
			((task_thread_info(_cur)->used_cp[1] | task_thread_info(_cur)->used_cp[2]) \
			 ? _cur : NULL);				\
		})

#define rthal_disable_fpu()						\
	task_thread_info(current)->used_cp[1] = task_thread_info(current)->used_cp[2] = 0;

#define rthal_enable_fpu()						\
	task_thread_info(current)->used_cp[1] = task_thread_info(current)->used_cp[2] = 1;

#endif /* !CONFIG_VFP */

#endif /* CONFIG_XENO_HW_FPU */

void __rthal_arm_fault_range(struct vm_area_struct *vma);
#define rthal_fault_range(vma) __rthal_arm_fault_range(vma)

static const char *const rthal_fault_labels[] = {
	[IPIPE_TRAP_ACCESS] = "Data or instruction access",
	[IPIPE_TRAP_SECTION] = "Section fault",
	[IPIPE_TRAP_DABT] = "Generic data abort",
	[IPIPE_TRAP_UNKNOWN] = "Unknown exception",
	[IPIPE_TRAP_BREAK] = "Instruction breakpoint",
	[IPIPE_TRAP_FPU] = "Floating point exception",
	[IPIPE_TRAP_VFP] = "VFP Floating point exception",
	[IPIPE_TRAP_UNDEFINSTR] = "Undefined instruction",
#ifdef IPIPE_TRAP_ALIGNMENT
	[IPIPE_TRAP_ALIGNMENT] = "Unaligned access exception",
#endif /* IPIPE_TRAP_ALIGNMENT */
	[IPIPE_NR_FAULTS] = NULL
};

#endif /* !__cplusplus */

#endif /* !_XENO_ASM_ARM_HAL_H */

// vim: ts=4 et sw=4 sts=4
