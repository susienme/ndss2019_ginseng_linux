/*
 *  linux/kernel/sys.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/perf_event.h>
#include <linux/resource.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#include <linux/security.h>
#include <linux/dcookies.h>
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/getcpu.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/seccomp.h>
#include <linux/cpu.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/gfp.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/ctype.h>

#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>
#include <linux/binfmts.h>

#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

#include <linux/kmsg_dump.h>
/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

#include <linux/arm-smccc.h>
#include <linux/ginseng_smc_cmd.h>
#include <linux/ginseng.h>
#include <linux/ginseng_conf.h>
#include <asm/tlbflush.h>

#ifndef SET_UNALIGN_CTL
# define SET_UNALIGN_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_UNALIGN_CTL
# define GET_UNALIGN_CTL(a, b)	(-EINVAL)
#endif
#ifndef SET_FPEMU_CTL
# define SET_FPEMU_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_FPEMU_CTL
# define GET_FPEMU_CTL(a, b)	(-EINVAL)
#endif
#ifndef SET_FPEXC_CTL
# define SET_FPEXC_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_FPEXC_CTL
# define GET_FPEXC_CTL(a, b)	(-EINVAL)
#endif
#ifndef GET_ENDIAN
# define GET_ENDIAN(a, b)	(-EINVAL)
#endif
#ifndef SET_ENDIAN
# define SET_ENDIAN(a, b)	(-EINVAL)
#endif
#ifndef GET_TSC_CTL
# define GET_TSC_CTL(a)		(-EINVAL)
#endif
#ifndef SET_TSC_CTL
# define SET_TSC_CTL(a)		(-EINVAL)
#endif
#ifndef MPX_ENABLE_MANAGEMENT
# define MPX_ENABLE_MANAGEMENT()	(-EINVAL)
#endif
#ifndef MPX_DISABLE_MANAGEMENT
# define MPX_DISABLE_MANAGEMENT()	(-EINVAL)
#endif
#ifndef GET_FP_MODE
# define GET_FP_MODE(a)		(-EINVAL)
#endif
#ifndef SET_FP_MODE
# define SET_FP_MODE(a,b)	(-EINVAL)
#endif

/*
 * this is where the system-wide overflow UID and GID are defined, for
 * architectures that now have 32-bit UID/GID but didn't in the past
 */

int overflowuid = DEFAULT_OVERFLOWUID;
int overflowgid = DEFAULT_OVERFLOWGID;

EXPORT_SYMBOL(overflowuid);
EXPORT_SYMBOL(overflowgid);

/*
 * the same as above, but for filesystems which can only store a 16-bit
 * UID and GID. as such, this is needed on all architectures
 */

int fs_overflowuid = DEFAULT_FS_OVERFLOWUID;
int fs_overflowgid = DEFAULT_FS_OVERFLOWUID;

EXPORT_SYMBOL(fs_overflowuid);
EXPORT_SYMBOL(fs_overflowgid);

/*
 * Returns true if current's euid is same as p's uid or euid,
 * or has CAP_SYS_NICE to p's user_ns.
 *
 * Called with rcu_read_lock, creds are safe
 */
static bool set_one_prio_perm(struct task_struct *p)
{
	const struct cred *cred = current_cred(), *pcred = __task_cred(p);

	if (uid_eq(pcred->uid,  cred->euid) ||
	    uid_eq(pcred->euid, cred->euid))
		return true;
	if (ns_capable(pcred->user_ns, CAP_SYS_NICE))
		return true;
	return false;
}

/*
 * set the priority of a task
 * - the caller must hold the RCU read lock
 */
static int set_one_prio(struct task_struct *p, int niceval, int error)
{
	int no_nice;

	if (!set_one_prio_perm(p)) {
		error = -EPERM;
		goto out;
	}
	if (niceval < task_nice(p) && !can_nice(p, niceval)) {
		error = -EACCES;
		goto out;
	}
	no_nice = security_task_setnice(p, niceval);
	if (no_nice) {
		error = no_nice;
		goto out;
	}
	if (error == -ESRCH)
		error = 0;
	set_user_nice(p, niceval);
out:
	return error;
}

// PLACE MINE HERE NOT TO BE CHANGED TOO MUCH #:)
static void initBlocksForTablesAndNormal(void);
static void _tableWalk(int bVerbose, unsigned long long pgd_addr, unsigned long long findingPageAddr, int bTraceBlock, int bAddToLive, int bUseMyprintk);
static void tableWalk_kernel(void) {
	_tableWalk(1 /*bVerbose*/, (unsigned long long) swapper_pg_dir, 0 /*findingPageAddr*/, 0 /*bTraceBlock*/, 0 /*bAddToLive*/, 1 /*bUseMyprintk*/);
}

static int bUpdateBlockList = 1;
void tableWalk_kernel_allBlocks(void) {
	bUpdateBlockList = 0;
	_tableWalk(0 /*bVerbose*/, (unsigned long long) swapper_pg_dir, 0 /*findingPageAddr*/, 1 /*bTraceBlock*/, 0 /*bAddToLive*/, 0 /*bUseMyprintk*/);
	bUpdateBlockList = 1;
}

unsigned long long findOA(unsigned long long addr, int bKaddr, const char* blanks, const char* who, int bCheckAP, int *pIsBlock, int bSilent, int bUseMyprintk);

#ifdef YMH_USE_SEPARATE_BLOCKS
#define BLOCKINFO_LOG_MASK_ALL			0b1110
#define BLOCKINFO_LOG_MASK_BLOCKS		0b0010
#define BLOCKINFO_LOG_MASK_PTP_PAGES	0b0100
#define BLOCKINFO_LOG_MASK_NORMAL_PAGES	0b1000
extern void printBlocksInfo_LIVE(int bSummary);
#endif /* YMH_USE_SEPARATE_BLOCKS */

static void findme(unsigned long long findingPageAddr);
void findPagetables(int bMakeReadOnly, int bVerbose, int bTraceTablesInBlock, int bUseMyprintk, int bAddToLive);
static int findBlockInPTPBlocks(unsigned long long block_vaddr);
static void findPGDEntries(void);
static void getCacheInfo(void);
#define NR_BLOCKS_FOR_TABLES	2048
#define NR_PAGES_PER_BLOCK		512
typedef struct _blocks {
	void *blocks[NR_BLOCKS_FOR_TABLES];
	int idx_blocks;
	void *pages[NR_BLOCKS_FOR_TABLES][NR_PAGES_PER_BLOCK];
	int idx_pages[NR_BLOCKS_FOR_TABLES];
} blocks;
static unsigned int addBlockNoDup(unsigned long long block_paddr, blocks *pBlocksInfo, unsigned long long page_vaddr);
static void printBlockInfo(blocks *pBlocks, char *strHead, int bUseMyprintk);
extern unsigned int addBlockNoDupNormal_LIVE(unsigned long long block_paddr, unsigned long long page_vaddr);
static blocks blocksForPTP;
static blocks blocksForNormalPage;
int ginseng_copyPageMode = 0;
int ginseng_clearPageMode = 0;
int ginseng_bReadonlyTables = 0;
EXPORT_SYMBOL(ginseng_bReadonlyTables);
unsigned long long ymh_sysentry_addr = 0;
unsigned long long ymh_el10_irq = 0;
unsigned long long ymh_el10_irq_spsr = 0;
unsigned long long ymh_daif_sync_from_el0 = 0;
unsigned long long ymh_nzcv_sync_from_el0 = 0;
ktime_t ymh_ktime_start;
int bGinsengMeasureTracePF = 0;
int bGinsengMeasureTraceIRQ = 0;
int bGinsengMeasureTraceIRQ_cpuid = 100;
unsigned long pmConuters[8];
char pmConutersRead[8];
static unsigned long long unknown = 0x7788;

#define IS_POINTING_BLOCK(entry) \
	((entry & 0b11) == 1)

#define IS_POINTING_TABLE(entry) \
	((entry & 0b11) == 0b11)
#define IS_POINTING_PAGE	IS_POINTING_TABLE

#define IS_READY_ONLY(entry) \
	(entry & (0b10 << BLOCK_AP_SHIFT))

static char pmInit[8];

void pmReset(void *unused) {
	asm volatile (	
		"mov x15, 0b1101\n" // ER|CR|EN
		"msr PMUSERENR_EL0, x15\n"

		"mov x15, 0x80000000\n"
		"msr PMCNTENSET_EL0, x15\n"

		"mov x15, 0b1000101\n" // LongCycle | RESET | CntEnable
		"mrs x14, pmcr_el0\n"
		"orr x14, x14, x15\n"
		"msr pmcr_el0, x14\n"

		"mov x14, #1\n"
		"msr PMOVSCLR_EL0, x14\n" 	// cleare the overflow bit
	: //[ymh_pm_cnt] "=r" (ymh_pm_cnt)
	:: "memory", "x15", "x14");
	pmInit[smp_processor_id()] = 1;
}

SYSCALL_DEFINE2(hong, int, k, unsigned long long, arg1) {
	extern const void *sys_call_table[];
	unsigned long long stable = (unsigned long long) sys_call_table;//0xFFFF00000;
	unsigned long long out = 0xFFAA;
	unsigned long long out2 = 0;
	unsigned long long out3 = 0;
	unsigned int flags;
	char *pMem;
	extern int bTraceFault;

	switch (k) {
	case GINSENG_TEST_THREAD_TTBR0_EL1:
		asm volatile(
		"mrs %[out], ttbr0_el1\n"
		: [out] "=r" (out)
		: 
		: "memory"
		);
		asm volatile(
		"mrs %[out2], tpidr_el0\n"
		: [out2] "=r" (out2)
		: 
		: "memory"
		);
		asm volatile(
		"mrs %[out3], tpidrro_el0\n"
		: [out3] "=r" (out3)
		: 
		: "memory"
		);
		myprintk("PID(%d) tid(%d) ttbr0_el1(0x%llX) tpid(0x%llX) tpidro(0x%llX)\n", current->tgid, current->pid, out, out2, out3);
		return 0;

	case GINSENG_MEASURE_TRACE_IRQ:
		bGinsengMeasureTraceIRQ = 1;
		bGinsengMeasureTraceIRQ_cpuid = smp_processor_id();
		return 0;
	case GINSENG_MEASURE_TRACE_PF:
		bGinsengMeasureTracePF = 1;
		return 0;
	case GINSENG_MEASURE_DONTTRACE_PF:
		bGinsengMeasureTracePF = 0;
		return 0;
	case GINSENG_MEASURE_PMRESET:
		{
			int i;
			for(i = 0; i < 8; i++) {
				pmInit[i] = 0;
				pmConuters[i] = 0;
				pmConutersRead[i] = 0;
			}
			on_each_cpu(pmReset, 0, 1);
			while(1) {
				int check = 8;
				for(i = 0; i < 8; i++) {
					if (pmInit[i]) check--;
				}
				if (!check) break;
			}
		}
		return 0;

	case GINSENG_TEST_SMC_CMD_SET_64BIT:
		ginseng_smc(GINSENG_SMC_CMD_SET_64BIT, (unsigned long long) &unknown, 0x1234567887654321, 0, 0, 0);
		myprintk("unknown = 0x%llX\n", unknown);
		ginseng_smc(GINSENG_SMC_CMD_SET_64BIT, (unsigned long long) &out, 0xAABBCCDD, 0, 0, 0);
		myprintk("out = 0x%llX\n", out);

		unknown = 0x7788;
		break;

	case GINSENG_TEST_SMC_CMD_SET_64BIT_DCI:
		ginseng_smc(GINSENG_SMC_CMD_SET_64BIT_DCI, (unsigned long long) &unknown, 0x1234567887654321, 0, 0, 0);
		myprintk("unknown = 0x%llX\n", unknown);
		ginseng_smc(GINSENG_SMC_CMD_SET_64BIT_DCI, (unsigned long long) &out, 0xAABBCCDD, 0, 0, 0);
		myprintk("out = 0x%llX\n", out);

		unknown = 0x7788;
		break;

	case GINSENG_TEST_PAGETABLE_FIND_ALL_BLOCKS:
		tableWalk_kernel_allBlocks();
		break;
	case GINSENG_TEST_PAGETABLE_FIND_NORMAL_BLOCKS:
		break;

	case GINSENG_TEST_PAGETABLE_PRINT_PTPBLOCKS:
	{
		extern void print_ptpBlocks_live(void);
		print_ptpBlocks_live();
		break;
	}
	case GINSENG_TEST_EL3_PT_WALK:
		ginseng_smc(GINSENG_SMC_CMD_TEST_PT_WALK, 1, 2, 3, 4, 0);
		break;
	case GINSENG_TEST_SENTRY_VIA_SMC:	// this is for Qemu
		ginseng_smc(GINSENG_SMC_CMD_TEST_SSECTION_ENTRY, 1, 2, 3, 4, 0);
		break;

	case GINSENG_TEST_USER_VADDR_TO_PADDR:
		asm volatile (
			"mov x1, %[vaddr]\n"
			"at s1e0r, x1\n"
			"mrs x0, par_el1\n"
			"ubfx x0, x0, #12, #36\n" // extrace PA
			//"mov %[out2], x0\n"

			"lsl x0, x0, #12\n" // extrace PA
			"ubfx x1, x1, #0, #12\n" // extrace PA
			"orr x0, x0, x1\n"
			"mov %[out], x0\n"
			: [out] "=r" (out) //, [out2] "=r" (out2)
			: [vaddr] "r" (arg1)
			: "memory", "x0", "x1"
			);
		myprintk("Kernel AT (0x%llX)\n", out);
		ginseng_smc(GINSENG_SMC_CMD_USER_VADDR_TO_PADDR, arg1, 2, 3, 4, (unsigned long) &out2);
		myprintk("EL3 AT (0x%llX)\n", out2);
		break;
	case GINSENG_RS_INIT:
		ginseng_smc(GINSENG_SMC_CMD_RS_INIT, 1, 2, 3, 4, (unsigned long) &out);
		myprintk("rsInit returned: 0x%016llX\n", out);
		break;

	case GINSENG_TEST_RS_PING:
		myprintk("Calling GINSENG_TEST_RS_PING\n");
		ginseng_smc(GINSENG_SMC_CMD_RS_PING, 1004, 2, 3, 4, (unsigned long) &out);
		myprintk("1004 + 1 = %lld\n", out);
		break;

	case GINSENG_TEST_SMC_PING: {
		unsigned long cnt;
		myprintk("Requesting TTBR1 trapping ID(%d)\n", smp_processor_id());
		ginseng_smc(GINSENG_SMC_CMD_PING, 1, 2, 3, 4, 0);

		asm volatile (	
			"mov x15, 0b1101\n" // ER|CR|EN
			"msr PMUSERENR_EL0, x15\n"

			"mov x15, 0x80000000\n"
			"msr PMCNTENSET_EL0, x15\n"

			// "mov x15,    0b0101\n"
			"mov x15, 0b1000101\n" // LongCycle | RESET | CntEnable
			// "mov x15, 0b1001101\n" // LongCycle | 64-clock | RESET | CntEnable
			"mrs x14, pmcr_el0\n"
			"orr x14, x14, x15\n"
			"msr pmcr_el0, x14\n"
			"isb\n"

			"mrs x15, ttbr1_el1\n"
			"msr ttbr1_el1, x15\n"

			"mrs %[cnt], pmccntr_el0\n"
			: [cnt] "=r" (cnt)
			:: "memory", "x15", "x14"
			);

		myprintk("TTBR1 cnt %lu cycles\n", cnt);
		return 0;
		}

	case GINSENG_TEST_NULL:
		ginseng_smc(GINSENG_SMC_CMD_NULL, 1, 2, 3, 4, 0);
		break;
	case GINSENG_TEST_RS_NULL:
		ginseng_smc(GINSENG_SMC_CMD_RS_NULL, 1, 2, 3, 4, 0);
		break;
		
	case GINSENG_TEST_TOGGLE_TRACE_FAULT:
		bTraceFault = !bTraceFault;
		break;

	case GINSENG_TEST_CLEAR_PAGE_TRACE:
	case GINSENG_TEST_CLEAR_PAGE_CLR_IN_EL1_CHECK_IN_EL3:
	case GINSENG_TEST_CLEAR_PAGE_CLR_IN_EL3_CHECK_IN_EL1:
		ginseng_clearPageMode = k;
		break;

	case GINSENG_TEST_COPY_PAGE_CP_IN_EL1_CMP_IN_EL3:
	case GINSENG_TEST_COPY_PAGE_CP_IN_EL3_CMP_IN_EL1:
		ginseng_copyPageMode = k;
		break;

	case GINSENG_TEST_PAGE_OPERATION_EL3:
		ginseng_clearPageMode = GINSENG_TEST_CLEAR_PAGE_CLR_IN_EL3_CHECK_IN_EL1;
		ginseng_copyPageMode = GINSENG_TEST_COPY_PAGE_CP_IN_EL3_CMP_IN_EL1;
		break;

	case GINSENG_TEST_VMALLOC:
		pMem = vmalloc(4*1024*1024);
		memset(pMem, 0, 4*1024*1024);
		myprintk("Allocated 4MB @ 0x%016llX\n", (unsigned long long) pMem);
		break;

	case GINSENG_TEST_MAKE_KERNEL_PFAULT:
		pMem = (char *) 0xFFFF000009401000;
		break;

	case GINSENG_TEST_PAGETABLE_WALK:
		tableWalk_kernel();
		break;

	case GINSENG_TEST_KERNEL_PTABLE_RO:
		ginseng_bReadonlyTables = 1;
		ginseng_clearPageMode = GINSENG_TEST_CLEAR_PAGE_CLR_IN_EL3_CHECK_IN_EL1;
		ginseng_copyPageMode = GINSENG_TEST_COPY_PAGE_CP_IN_EL3_CMP_IN_EL1;
		findPagetables(true /*make RO*/, false /*verbose*/, 0 /*bTraceTablesInBlock*/, 1 /*bUseMyprintk*/, 0 /*bAddToLive*/);
		myprintk("READ-ONLY DONE\n");
		break;

	case GINSENG_TEST_PAGETABLE_FIND_TABLES:
		findPagetables(false /*make RO*/, true /*verbose*/, 1 /*bTraceTablesInBlock*/, 1 /*bUseMyprintk*/, 0 /*bAddToLive*/);
		printBlockInfo(&blocksForPTP, "BLOCKS for PTP", 1 /*bUseMyprintk*/);

	case GINSENG_TEST_PAGETABLE_FIND_TABLES_QUIET:
		findPagetables(false /*make RO*/, false /*verbose*/, 1 /*bTraceTablesInBlock*/, 1 /*bUseMyprintk*/, 0 /*bAddToLive*/);
		printBlockInfo(&blocksForPTP, "BLOCKS for PTP", 1 /*bUseMyprintk*/);
		break;

	case GINSENG_TEST_PAGETABLE_LIVE_TABLES:
		#ifdef YMH_USE_SEPARATE_BLOCKS
		printBlocksInfo_LIVE(BLOCKINFO_LOG_MASK_ALL /*logMask*/);
		#else
		myprintk("YMH_USE_SEPARATE_BLOCKS is off\n");
		#endif /* #ifdef YMH_USE_SEPARATE_BLOCKS */
		break;

	case GINSENG_TEST_PAGETABLE_LIVE_TABLES_QUIET:
		#ifdef YMH_USE_SEPARATE_BLOCKS
		printBlocksInfo_LIVE(BLOCKINFO_LOG_MASK_BLOCKS | BLOCKINFO_LOG_MASK_PTP_PAGES /*logMask*/);
		#else
		myprintk("YMH_USE_SEPARATE_BLOCKS is off\n");
		#endif /* #ifdef YMH_USE_SEPARATE_BLOCKS */
		break;		

	case GINSENG_TEST_PAGETABLE_FIND_PGDIR:
		myprintk("Find with swapper_pg_dir(0x%llX)\n", (unsigned long long) swapper_pg_dir);
		findme((unsigned long long) swapper_pg_dir);

		myprintk("Find with __va(__pa(swapper_pg_dir))(0x%llX)\n", (unsigned long long) __va(__pa(swapper_pg_dir)));
		findme((unsigned long long) __va(__pa(swapper_pg_dir)));
		break;

	case GINSENG_TEST_PAGETABLE_FIND_PGD_ENTRIES:
		findPGDEntries();
		break;

	case GINSENG_TEST_READ_USER_FROM_K:
		myprintk("ARG1 (0x%016llX) has 0x%llX\n", arg1, *((unsigned long long *) arg1) );
		break;

	case GINSENG_TEST_HVC:
		asm volatile(
			"hvc 0\n"
			:::"memory"
			);
		break;
	}

	myprintk("--------------- CASE END -------------\n");
	myprintk("sys_getpid ymh_sysentry_addr(0x%016llX)\n", ymh_sysentry_addr);
	myprintk("ymh_el10_irq(0x%016llX) ymh_el10_irq_spsr(0x%016llx)\n", ymh_el10_irq, ymh_el10_irq_spsr);
	myprintk("ymh_daif_sync_from_el0(0x%016llX) ymh_nzcv_sync_from_el0(0x%016llX)\n", 
		ymh_daif_sync_from_el0, ymh_nzcv_sync_from_el0);
	if(0) getCacheInfo();
	myprintk("MAX_NUMNODES(%d) MAX_ZONELISTS(%d) MAX_NR_ZONES(%d) VMEMMAP_START(0x%016llX) VMEMMAP_SIZE(0x%016llX) pageblock_order(%d)\n", MAX_NUMNODES, MAX_ZONELISTS, MAX_NR_ZONES, VMEMMAP_START, VMEMMAP_SIZE, pageblock_order	);
	myprintk("phy(0xF7113000) is vir(0x%llX)\n", (unsigned long long) __va(0xF7113000));
	myprintk("sys_hong bTraceFault(%d) copyPageMode(0x%X) clearPageMode(0x%X) bReadonlyTables(%d)\n", bTraceFault, ginseng_copyPageMode, ginseng_clearPageMode, ginseng_bReadonlyTables);
	myprintk("sys_hong VM START(0x%016llX) END(0x%016llX)\n", VMALLOC_START, VMALLOC_END);
	myprintk("sys_hong VA_BITS(0x%llX) PAGE_OFFSET(0x%llX) PAGE_SIZE(0x%llX) PHYS_OFFSET(0x%llX) kimage_voffset(0x%llX)\n", 
		VA_BITS, PAGE_OFFSET, PAGE_SIZE, PHYS_OFFSET, kimage_voffset);
	myprintk("sys_hong PHYS_MASK(0x%llX) PAGE_SHIFT(0x%llX)\n", PHYS_MASK, PAGE_SHIFT);

	asm volatile(
		"ldr x0, =0xffff00000809bab8\n"
		"mov %[out2], #(0xff << 56)\n"
		"bic %[out], x0, %[out2]\n"
		: [out] "=r" (out), [out2] "=r" (out2)
		: 
		: "memory", "x0"
		);
	myprintk("sys_hong shift(0x%016llX)\n", out);	
	myprintk("sys_hong out2(0x%016llX)\n", out2);	

	asm volatile(
		"mrs %[out], ttbr1_el1\n"
		: [out] "=r" (out)
		: 
		: "memory"
		);
	myprintk("sys_hong ttbr1_el1(0x%llX)\n", out);

	asm volatile(
		"mrs %[out], ttbr0_el1\n"
		: [out] "=r" (out)
		: 
		: "memory"
		);
	myprintk("sys_hong ttbr0_el1(0x%llX)\n", out);
	myprintk("sys_hong current->mm->pgd(0x%llX)\n", current->mm->pgd);

	asm volatile(
		"mrs %[out], ID_AA64MMFR0_EL1\n"
		: [out] "=r" (out)
		: 
		: "memory"
		);
	myprintk("sys_hong ID_AA64MMFR0_EL1(0x%llX)\n", out);

	asm volatile(
		"mrs %[out], tcr_el1\n"
		: [out] "=r" (out)
		: 
		: "memory"
		);
	myprintk("sys_hong tcr_el1(0x%llX)\n", out);

	myprintk("sys_hong swapper_pg_dir(0x%llX) _pa(0x%llX)\n", (unsigned long long) swapper_pg_dir, (unsigned long long) __pa(swapper_pg_dir));
	myprintk("sys_hong swapper_pg_dir[0](0x%lX)\n", *((unsigned long *) swapper_pg_dir));

	asm volatile(
		"ldr %[out], [%[stbl]]"
		: [out] "=r" (out)
		: [stbl] "r" (stable) //, [scno] "r" (syscallno)
		: "memory"
		);
	myprintk("sys_hong addr(0x%llX) sys_call_table(0x%llX) stable(0x%llX)\n", 
		(unsigned long long) sys_hong, (unsigned long long) sys_call_table, stable);
	myprintk("sys_hong arg(0x%x)\n", k);

	asm volatile(
		"mrs %0, elr_el1"
		: "=r" (flags)
		:
		: "memory");
	myprintk("sys_hong elr_el1(0x%X)\n", flags);

	asm volatile(
		"mrs %0, SPSR_EL1"
		: "=r" (flags)
		:
		: "memory");
	myprintk("sys_hong SPSR_EL1(0x%X)\n", flags);

	asm volatile(
		"mrs %0, currentel"
		: "=r" (flags)
		:
		: "memory");
	myprintk("sys_hong currentel(0x%X)\n", flags);

	asm volatile(
		"mrs %0, spsel"
		: "=r" (flags)
		:
		: "memory");
	myprintk("sys_hong SPSel(0x%X)\n", flags);

	asm volatile(
		"mrs %0, daif"
		: "=r" (flags)
		:
		: "memory");
	myprintk("sys_hong daif(0x%X)\n", flags);

	asm volatile(
		"mrs %0, vbar_el1"
		: "=r" (out2)
		:
		: "memory");
	myprintk("sys_hong vbar_el1(0x%llX)\n", out2);

	asm volatile(
		// "mov %0, 0b1101\n" // ER|CR|EN
		// "msr PMUSERENR_EL0, %0"
		"mrs %0, PMUSERENR_EL0"
		: "=r" (out2)
		:
		: "memory"
	);
	myprintk("sys_hong PMUSERENR_EL0(0x%llX)\n", out2);

	return 0x1234567887654321; // SYS_HONG magic
}

#define NST_MASK 	0x8000000000000000
#define NST_SHIFT	63

#define APT_MASK	0x6000000000000000
#define APT_SHIFT	61

#define UXNT_MASK	0x1000000000000000
#define UXNT_SHIFT 	60

#define PXNT_MASK	0x800000000000000
#define PXNT_SHIFT 	59

#define RES0_MASK	0x7000000000000
#define RES0_SHIFT	48

#define PUD_ADDR_MASK 			0xFFFFFFFFF000
#define PMD_ADDR_MASK 			PUD_ADDR_MASK
#define PT_ADDR_MASK 			PUD_ADDR_MASK
#define OA_ADDR_MASK 			PUD_ADDR_MASK
#define PMD_BLOLCK_ADDR_MASK	0xFFFFFFE00000

// for BLOCK
#define BLOCK_UXN_SHIFT			54
#define BLOCK_UXN_MASK			(1ULL << BLOCK_UXN_SHIFT)

#define BLOCK_PXN_SHIFT			53
#define BLOCK_PXN_MASK			(1ULL << BLOCK_PXN_SHIFT)

#define BLOCK_CONT_SHIFT		53
#define BLOCK_CONT_MASK			(1ULL << BLOCK_CONT_SHIFT)

#define BLOCK_NG_SHIFT			11
#define BLOCK_NG_MASK			(1ULL << BLOCK_NG_SHIFT)

#define BLOCK_AF_SHIFT			10
#define BLOCK_AF_MASK			(1ULL << BLOCK_AF_SHIFT)

#define BLOCK_SH_SHIFT			8
#define BLOCK_SH_MASK			(0b11ULL << BLOCK_SH_SHIFT)

#define BLOCK_AP_SHIFT			6
#define BLOCK_AP_MASK			(0b11ULL << BLOCK_AP_SHIFT)

#define BLOCK_NS_SHIFT			5
#define BLOCK_NS_MASK			(1ULL << BLOCK_NS_SHIFT)

#define BLOCK_ATTR_IDX_SHIFT	2
#define BLOCK_ATTR_IDX_MASK		(0b111ULL << BLOCK_ATTR_IDX_SHIFT)

#define PTE_UXN_SHIFT 			BLOCK_UXN_SHIFT
#define PTE_UXN_MASK 			BLOCK_UXN_MASK
#define PTE_PXN_SHIFT 			BLOCK_PXN_SHIFT
#define PTE_PXN_MASK 			BLOCK_PXN_MASK
#define PTE_CONT_SHIFT 			BLOCK_CONT_SHIFT
#define PTE_CONT_MASK 			BLOCK_CONT_MASK
#define PTE_NG_SHIFT 			BLOCK_NG_SHIFT
#define PTE_NG_MASK 			BLOCK_NG_MASK
#define PTE_AF_SHIFT 			BLOCK_AF_SHIFT
#define PTE_AF_MASK 			BLOCK_AF_MASK
#define PTE_SH_SHIFT 			BLOCK_SH_SHIFT
#define PTE_SH_MASK 			BLOCK_SH_MASK
#define PTE_AP_SHIFT 			BLOCK_AP_SHIFT
#define PTE_AP_MASK 			BLOCK_AP_MASK
#define PTE_NS_SHIFT 			BLOCK_NS_SHIFT
#define PTE_NS_MASK 			BLOCK_NS_MASK
#define PTE_ATTR_IDX_SHIFT 		BLOCK_ATTR_IDX_SHIFT
#define PTE_ATTR_IDX_MASK 		BLOCK_ATTR_IDX_MASK

#define GET_FIELD(e, name)\
	(e & name##_MASK) >> name##_SHIFT

#define GET_BLOCK_FIELD(e, name)\
	(e & BLOCK_##name##_MASK) >> BLOCK_##name##_SHIFT

#define GET_PTE_FIELD(e, name)\
	(e & PTE_##name##_MASK) >> PTE_##name##_SHIFT

static unsigned long nr_ptes = 0;
static unsigned long long min_OA = 0xffffffffffffffff;
static unsigned long long max_OA = 0x0;

typedef int (*log_fun)(const char *, ...);

/* 
 * In the following macro, _log and bVerbose must be declared
 */
#define _LOG(fmt, ...) 						\
	do {									\
		if (bVerbose && _log) _log(fmt, ##__VA_ARGS__);	\
	} while(0)

static int tableWalk_pt(pte_t *pt, unsigned long long findingPageAddr, int bPrintInfo, int idx_pgd, int idx_pud, int idx_pmd, log_fun _log, int bVerbose) {
	int i;
	unsigned long long pte;

	for (i = 0; i < PTRS_PER_PTE; i++) {
		pte = pte_val(pt[i]);
		if (pte) {
			if ( (pte & 0b11) == 0b11) {
				if (bPrintInfo
					) _LOG("            %03d: [%03d,%03d,%03d,%03d] UXN(%d) PXN(%d) CONT(%d) NG(%d) AF(%d) SH(%d) AP(%d) NS(%d) ATTR(%d) OA(0x%llX)	<-- 0x%llX\n", i, idx_pgd, idx_pud, idx_pmd, i,
									GET_PTE_FIELD(pte, UXN),
									GET_PTE_FIELD(pte, PXN),
									GET_PTE_FIELD(pte, CONT),
									GET_PTE_FIELD(pte, NG),
									GET_PTE_FIELD(pte, AF),
									GET_PTE_FIELD(pte, SH),
									GET_PTE_FIELD(pte, AP),
									GET_PTE_FIELD(pte, NS),
									GET_PTE_FIELD(pte, ATTR_IDX),
									pte & OA_ADDR_MASK,
									pte
									);
				if ( findingPageAddr &&
					(unsigned long long) (pte & OA_ADDR_MASK) == __pa(findingPageAddr)) {
						_LOG("FOUND! i(%d) - findingPageAddr(0x%llX) found(0x%llX -> 0x%llX) \n", i, findingPageAddr, (pte & OA_ADDR_MASK), (unsigned long long) __va(pte & OA_ADDR_MASK));
						_LOG("pg1[0](0x%llX) @ 0x%llX\n", *((unsigned long long *) findingPageAddr), (unsigned long long) findingPageAddr);
						_LOG("pg2[0](0x%llX) @ 0x%llX\n", *((unsigned long long *)__va(pte & OA_ADDR_MASK)), (unsigned long long) __va(pte & OA_ADDR_MASK));
						return 1;
				}

				nr_ptes++;
				if (min_OA > (pte & OA_ADDR_MASK) ) min_OA = (pte & OA_ADDR_MASK);
				if (max_OA < (pte & OA_ADDR_MASK) ) max_OA = (pte & OA_ADDR_MASK);
			}
		}

	}
	return 0;
}

/*
 * We assume 	1) blocksForNormalPage is initialied.
 * 				2) blocksForPTP is populated
 * @bTraceBlock: as mentioned in _tableWal(), if it is true, we will NOT walk PT.
 */
static noinline int tableWalk_pmd(pmd_t *pmd, unsigned long long findingPageAddr, int bTraceBlock,int bAddToLive,
						int idx_pgd, int idx_pud, log_fun _log, int bVerbose) {
	int i;
	unsigned long long pmd_e;
	int rtn = -1;
	unsigned long long block_paddr;

	for (i = 0; i < PTRS_PER_PUD; i++) {
		pmd_e = pmd_val(pmd[i]);
		if (pmd_e) {
			if ( IS_POINTING_BLOCK(pmd_e) /*(pmd_e & 0b11) == 0b1*/ ) {
				block_paddr = pmd_e & PMD_BLOLCK_ADDR_MASK;
				_LOG("        %03d: [%03d,%03d,%03d] [BLOCK] UXN(%d) PXN(%d) CONT(%d) NG(%d) AF(%d) SH(%d) AP(%d) NS(%d) ATTR(%d) BLOCK_PADDR(0x%llX) BLOCK_VADDR(0x%llX)	<-- 0x%llX\n", i, idx_pgd, idx_pud, i,
						GET_BLOCK_FIELD(pmd_e, UXN),
						GET_BLOCK_FIELD(pmd_e, PXN),
						GET_BLOCK_FIELD(pmd_e, CONT),
						GET_BLOCK_FIELD(pmd_e, NG),
						GET_BLOCK_FIELD(pmd_e, AF),
						GET_BLOCK_FIELD(pmd_e, SH),
						GET_BLOCK_FIELD(pmd_e, AP),
						GET_BLOCK_FIELD(pmd_e, NS),
						GET_BLOCK_FIELD(pmd_e, ATTR_IDX),
						block_paddr,
						__va(block_paddr),
						pmd_e
						);
					if (bTraceBlock && findBlockInPTPBlocks((unsigned long long) __va(block_paddr)) == -1) {
						if (bUpdateBlockList) rtn = addBlockNoDup(block_paddr, &blocksForNormalPage, 0ULL);	// we're passing '0' because we're not interested in keeping normal pages

						if (!bVerbose) {	// even not verbose -> print result
							_log("[%d] %03d: [%03d,%03d,%03d] [BLOCK] UXN(%d) PXN(%d) CONT(%d) NG(%d) AF(%d) SH(%d) AP(%d) NS(%d) ATTR(%d) BLOCK_PADDR(0x%llX) BLOCK_VADDR(0x%llX)	<-- 0x%llX\n", 
								rtn,
								i, idx_pgd, idx_pud, i,
								GET_BLOCK_FIELD(pmd_e, UXN),
								GET_BLOCK_FIELD(pmd_e, PXN),
								GET_BLOCK_FIELD(pmd_e, CONT),
								GET_BLOCK_FIELD(pmd_e, NG),
								GET_BLOCK_FIELD(pmd_e, AF),
								GET_BLOCK_FIELD(pmd_e, SH),
								GET_BLOCK_FIELD(pmd_e, AP),
								GET_BLOCK_FIELD(pmd_e, NS),
								GET_BLOCK_FIELD(pmd_e, ATTR_IDX),
								block_paddr,
								__va(block_paddr),
								pmd_e
								);
						}
					
						if (bAddToLive && rtn /*&& addLimit*/) {
							rtn = addBlockNoDupNormal_LIVE(block_paddr, 0ULL);
						}
					}
			} else {
				_LOG("        %03d: [%03d,%03d,%03d] NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PT_ADDR(0x%llX) <-- 0x%llX\n", i, idx_pgd, idx_pud, i,
					GET_FIELD(pmd_e, NST),
					GET_FIELD(pmd_e, APT),
					GET_FIELD(pmd_e, UXNT),
					GET_FIELD(pmd_e, PXNT),
					GET_FIELD(pmd_e, RES0),
					pmd_e & PT_ADDR_MASK,
					pmd_e
					);
				if (GET_FIELD(pmd_e, APT)) _LOG("Hierarchical data access permission - PMD\n");

				if (bTraceBlock) continue;

				rtn = tableWalk_pt( (pte_t *) __va((pmd_e & PT_ADDR_MASK)), findingPageAddr, 1 /*bPrintInfo*/, idx_pgd, idx_pud, i, _log, bVerbose);
				if (findingPageAddr && rtn) return 1;
			}
		}
	}

	return 0;
}

static noinline int tableWalk_pud(pud_t *pud, unsigned long long findingPageAddr, int bTraceBlock, int bAddToLive,
						int idx_pgd, log_fun _log, int bVerbose) {
	int i;
	unsigned long long pud_e;
	int rtn;

	_LOG("    Walking pud(0x%llX)\n", (unsigned long long) pud);
	for (i = 0; i < PTRS_PER_PUD; i++) {
		pud_e = pud_val(pud[i]);
		if (pud_e) {
			if ( IS_POINTING_BLOCK(pud_e) /*(pud_e & 0b11) == 0b1*/ ) panic("    %3d: 0x%llX <--------- BLOCK! (1GB)\n", i, pud_e);
			else {
				if ( !IS_POINTING_TABLE(pud_e) /*(pud_e & 0b11) != 0b11*/ ) panic("    %3d: 0x%llX <--------- somthing wrong!\n", i, pud_e);
				_LOG("    %03d: [%03d,%03d] NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PMD_ADDR(0x%llX) <-- 0x%llX\n", i, idx_pgd, i,
					GET_FIELD(pud_e, NST),
					GET_FIELD(pud_e, APT),
					GET_FIELD(pud_e, UXNT),
					GET_FIELD(pud_e, PXNT),
					GET_FIELD(pud_e, RES0),
					pud_e & PMD_ADDR_MASK,
					pud_e
					);
				if (GET_FIELD(pud_e, APT)) _LOG("Hierarchical data access permission - PUD\n");
				rtn = tableWalk_pmd( (pmd_t *) __va((pud_e & PMD_ADDR_MASK)), findingPageAddr, bTraceBlock, bAddToLive, idx_pgd, i, _log, bVerbose);
				if (rtn && findingPageAddr) return 1;
			}
		}
	}
	return 0;
}


static int isMapped(unsigned long long vaddr) {
	unsigned long long rtn;

	asm volatile(
		"at s1e1r, %[vaddr]\n"
		"mrs %[rtn], par_el1\n"
		: [rtn] "=r" (rtn)
		: [vaddr] "r" (vaddr)
		: "memory", "x4");

	return !(rtn & 1ULL);
} // moved to pgtable.h

/* @findingPageAddr: 	specifying a page address to be found. if found, return immediately.
 *						To avoid immedate return, set it zero or impossible address.
 * @bTraceBlock: if it is true, we will not visit PT.
 */
static void _tableWalk(int bVerbose, unsigned long long pgd_addr, 
						unsigned long long findingPageAddr, int bTraceBlock, 
						int bAddToLive, int bUseMyprintk) {

	int i;
	unsigned long long pgd_e;
	unsigned long long pud_vaddr;

	log_fun _log = bUseMyprintk ? myprintk : printk; //NULL;

	nr_ptes = 0;
	min_OA = 0xffffffffffffffff;
	max_OA = 0x0;

	if (pgd_addr == 0ULL) pgd_addr = (unsigned long long) current->mm->pgd;			// 0: app
	else if (pgd_addr == 1ULL) pgd_addr = (unsigned long long) swapper_pg_dir;		// 1: kernel

	
	_LOG("sys_hong PTRS_PER_PGD(0x%x)\n", PTRS_PER_PGD);
	_LOG("sys_hong pgd_addr(0x%llX) phy(0x%X):\n", (unsigned long long) pgd_addr, __pa(pgd_addr));

	for (i = 0; i < PTRS_PER_PGD; i++){
		pgd_e = pgd_val(((pgd_t *)pgd_addr)[i]);
		if (pgd_e) {
			if ( !IS_POINTING_TABLE(pgd_e) /*(pgd_e & 0b11) != 0b11*/ ) panic("%3d: 0x%llX <- PGD_E MUST point to a table\n", i, pgd_e);
			else {
				 
				_LOG("%03d: [%03d] NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PUD_ADDR(0x%llX) <-- 0x%llX\n", i, i,
					GET_FIELD(pgd_e, NST),
					GET_FIELD(pgd_e, APT),
					GET_FIELD(pgd_e, UXNT),
					GET_FIELD(pgd_e, PXNT),
					GET_FIELD(pgd_e, RES0),
					pgd_e & PUD_ADDR_MASK,
					pgd_e
					);
				if (GET_FIELD(pgd_e, APT)) _LOG("Hierarchical data access permission - PGD\n");

				pud_vaddr = (unsigned long long) __va((pgd_e & PUD_ADDR_MASK));
				if (isMapped(pud_vaddr))
					tableWalk_pud( (pud_t *) pud_vaddr, findingPageAddr, bTraceBlock, bAddToLive, i, _log, bVerbose);
			}
		}
	}
	_LOG("PT_WALK statistics: nr_ptes(%lld) min_OA(0x%llX) max_OA(0x%llX)\n", nr_ptes, min_OA, max_OA);
}

static void findme(unsigned long long findingPageAddr) {
	int i;
	unsigned long long pgd_e;
	unsigned long long pgd_addr;
	int rtn;

	pgd_t *pPgd;
	pud_t *pPud;
	pmd_t *pPmd;
	pte_t *pPte;
	unsigned long long pte;

	pgd_addr = (unsigned long long) swapper_pg_dir;

	// USING KERNEL PROVIDED APIS
	pPgd = pgd_offset_k(findingPageAddr);
	pPud = pud_offset(pPgd, findingPageAddr);
	pPmd = pmd_offset(pPud, findingPageAddr);
	pPte = pte_offset_kernel(pPmd, findingPageAddr);
	pte = pte_val((*pPte));

	myprintk("pg_dir(0x%llX) phy(0x%llX) with %d entries\n", (unsigned long long) swapper_pg_dir, (unsigned long long) __pa(swapper_pg_dir), PTRS_PER_PGD);
	myprintk("pg_entrty(0x%llX) phy(0x%llX)\n", (unsigned long long) pPgd, __pa(pPgd));
	myprintk("PGD[%d], PUD[%d], pmd[%d] pt[%d]\n", pPgd - swapper_pg_dir,
									pPud - ((pud_t *) __va(pgd_val(*pPgd) & PUD_ADDR_MASK)),
									pPmd - ((pmd_t *) __va(pud_val(*pPud) & PMD_ADDR_MASK)),
									pPte - ((pte_t *) __va(pmd_val(*pPmd) & PT_ADDR_MASK))
									);
	myprintk("PGD[%d] = 0x%llX OA(0x%llX)\n", pPgd - swapper_pg_dir, pgd_val(*pPgd), pgd_val(*pPgd) & PUD_ADDR_MASK);
	myprintk("PUD[%d] = 0x%llX OA(0x%llX)\n", pPud - ((pud_t *) __va(pgd_val(*pPgd) & PUD_ADDR_MASK)), pud_val(*pPud), pud_val(*pPud) & PMD_ADDR_MASK);
	myprintk("PMD[%d] = 0x%llX OA(0x%llX)\n", pPmd - ((pmd_t *) __va(pud_val(*pPud) & PMD_ADDR_MASK)), pmd_val(*pPmd), pmd_val(*pPmd) & PT_ADDR_MASK);
	myprintk("PT[%d] = 0x%llX OA(0x%llX)\n", pPte - ((pte_t *) __va(pmd_val(*pPmd) & PT_ADDR_MASK)), pte_val(*pPte), pte_val(*pPte) & OA_ADDR_MASK);


	// WALKING
	myprintk("sys_findme pgd_addr(0x%llX) phy(0x%X):\n", (unsigned long long) pgd_addr, __pa(pgd_addr));
	for (i = 0; i < PTRS_PER_PGD; i++){
		pgd_e = pgd_val(((pgd_t *)pgd_addr)[i]);
		if (pgd_e) {
			if ( (pgd_e & 0b11) != 0b11 ) myprintk("%3d: 0x%llX <--------- something wrong\n", i, pgd_e);
			else {
				myprintk("%03d: NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PUD_ADDR(0x%llX) <-- 0x%llX\n", i,
					GET_FIELD(pgd_e, NST),
					GET_FIELD(pgd_e, APT),
					GET_FIELD(pgd_e, UXNT),
					GET_FIELD(pgd_e, PXNT),
					GET_FIELD(pgd_e, RES0),
					pgd_e & PUD_ADDR_MASK,
					pgd_e
					);
				if (GET_FIELD(pgd_e, APT)) myprintk("Hierarchical data access permission - PGD\n");

				rtn = tableWalk_pud( (pud_t *) __va((pgd_e & PUD_ADDR_MASK)), findingPageAddr, 0 /*bTraceBlock*/, 0 /*bAddToLive*/, i, myprintk, 1 /*bVerbose*/);
				if (rtn) break;
			}
		}

		break;		// <---- once! too lazy....#:)
	}
}


static void findPGDEntries(void) {
	int i;
	pgd_t* pgd = swapper_pg_dir;
	unsigned long long pgd_e;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		pgd_e = pgd_val(pgd[i]);
		if (pgd_e) {
			if ( (pgd_e & 0b11) != 0b11 ) myprintk("%3d: 0x%llX <--------- something wrong\n", i, pgd_e);
			else {
				myprintk("PUD_ADDR(0x%llX) va(0x%llX)\n", (pgd_e & PUD_ADDR_MASK), __va(pgd_e & PUD_ADDR_MASK));
				myprintk("VA1(0x%llX)\n", *((unsigned long long *) __va(pgd_e & PUD_ADDR_MASK)));
			}
		}
	}
}

#define YMH_PTERO_LOGLEVEL_DEBUG		3
#define YMH_PTERO_LOGLEVEL_RESULT_ALL	2
#define YMH_PTERO_LOGLEVEL_RESULT_PTE 	1

#define print_pgdInfo(pgd, addr) \
	myprintk("PGD_E: [%03d]             NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PUD_ADDR(0x%llX) pgd_idx(%d)<-- 0x%llX\n",	\
			pgd_index(addr), 		\
			GET_FIELD(pgd, NST),	\
			GET_FIELD(pgd, APT),	\
			GET_FIELD(pgd, UXNT),	\
			GET_FIELD(pgd, PXNT),	\
			GET_FIELD(pgd, RES0),	\
			pgd & PUD_ADDR_MASK,	\
			pgd_index(addr),	\
			pgd	\
			)

#define print_pudInfo(pud, addr) \
	myprintk("PUD_E: [%03d,%03d]         NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PMD_ADDR(0x%llX) pud_idx(%d)<-- 0x%llX\n",	\
			pgd_index(addr), 		\
			pud_index(addr),		\
			GET_FIELD(pud, NST),	\
			GET_FIELD(pud, APT),	\
			GET_FIELD(pud, UXNT),	\
			GET_FIELD(pud, PXNT),	\
			GET_FIELD(pud, RES0),	\
			pud & PMD_ADDR_MASK,	\
			pud_index(addr),	\
			pud	\
			)
#define print_pmdInfo_simple(pmd, addr) \
	myprintk("PMD_E: [%03d,%03d,%03d]     NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PT_ADDR(0x%llX) pmd_idx(%d)<-- 0x%llX\n",	\
			pgd_index(addr), 		\
			pud_index(addr),		\
			pmd_index(addr),		\
			GET_FIELD(pmd, NST),	\
			GET_FIELD(pmd, APT),	\
			GET_FIELD(pmd, UXNT),	\
			GET_FIELD(pmd, PXNT),	\
			GET_FIELD(pmd, RES0),	\
			pmd & PMD_ADDR_MASK,	\
			pmd_index(addr),	\
			pmd	\
			)

#define print_pmdBlockInfo(pmd, addr, postfix) myprintk("PMD_E: [%03d,%03d,%03d] [BLOCK] UXN(%d) PXN(%d) CONT(%d) NG(%d) AF(%d) SH(%d) AP(%d) NS(%d) ATTR(%d) BLOCK_PADDR(0x%llX) B_VA(0x%llX) pmd_idx(%d)<-- 0x%llX [" postfix "]\n",	\
									pgd_index(addr), 		\
									pud_index(addr),		\
									pmd_index(addr),		\
									GET_BLOCK_FIELD(pmd, UXN),	\
									GET_BLOCK_FIELD(pmd, PXN),	\
									GET_BLOCK_FIELD(pmd, CONT),	\
									GET_BLOCK_FIELD(pmd, NG),	\
									GET_BLOCK_FIELD(pmd, AF),	\
									GET_BLOCK_FIELD(pmd, SH),	\
									GET_BLOCK_FIELD(pmd, AP),	\
									GET_BLOCK_FIELD(pmd, NS),	\
									GET_BLOCK_FIELD(pmd, ATTR_IDX),	\
									pmd & PMD_BLOLCK_ADDR_MASK,	\
									__va(pmd & PMD_BLOLCK_ADDR_MASK),	\
									pmd_index(addr),	\
									pmd	\
									)
#if 0 // for print_pmdBlockInfoAfter()
#define print_pmdBlockInfoAfter(pmd, addr) myprintk("PMD: [BLOCK] UXN(%d) PXN(%d) CONT(%d) NG(%d) AF(%d) SH(%d) AP(%d) NS(%d) ATTR(%d) BLOCK_PADDR(0x%llX) B_VA(0x%llX) pmd_idx(%d)<-- 0x%llX [AFTER]\n",	\
										GET_BLOCK_FIELD(pmd, UXN),	\
										GET_BLOCK_FIELD(pmd, PXN),	\
										GET_BLOCK_FIELD(pmd, CONT),	\
										GET_BLOCK_FIELD(pmd, NG),	\
										GET_BLOCK_FIELD(pmd, AF),	\
										GET_BLOCK_FIELD(pmd, SH),	\
										GET_BLOCK_FIELD(pmd, AP),	\
										GET_BLOCK_FIELD(pmd, NS),	\
										GET_BLOCK_FIELD(pmd, ATTR_IDX),	\
										pmd & PMD_BLOLCK_ADDR_MASK,	\
										__va(pmd & PMD_BLOLCK_ADDR_MASK),	\
										pmd_index(addr),	\
										pmd	\
										)
#else

void print_pmdBlockInfoAfter(unsigned long long pmd, unsigned long long addr) {
	panic("AT LEAST HERE!");

	myprintk("PMD: [BLOCK]\n");	
	myprintk("UXN(%d)\n", GET_BLOCK_FIELD(pmd, UXN));
	myprintk("PXN(%d)\n", GET_BLOCK_FIELD(pmd, PXN));
	myprintk("CONT(%d)\n", GET_BLOCK_FIELD(pmd, CONT));
	myprintk("NG(%d)\n", GET_BLOCK_FIELD(pmd, NG));
	myprintk("AF(%d)\n", GET_BLOCK_FIELD(pmd, AF));
	myprintk("SH(%d)\n", GET_BLOCK_FIELD(pmd, SH));
	myprintk("AP(%d)\n", GET_BLOCK_FIELD(pmd, AP));
	myprintk("NS(%d)\n", GET_BLOCK_FIELD(pmd, NS));
	myprintk("ATTR(%d)\n", GET_BLOCK_FIELD(pmd, ATTR_IDX));
	myprintk("BLOCK_PADDR(0x%llX)\n", pmd & PMD_BLOLCK_ADDR_MASK);
	myprintk("B_VA(0x%llX)\n", __va(pmd & PMD_BLOLCK_ADDR_MASK));
	myprintk("pmd_idx(%d) \n", pmd_index(addr));
	myprintk("0x%llX[AFTER]\n", pmd);
}
#endif

#define print_pmdBlockInfoDesired(pmd, addr) myprintk("PMD: [BLOCK] UXN(%d) PXN(%d) CONT(%d) NG(%d) AF(%d) SH(%d) AP(%d) NS(%d) ATTR(%d) BLOCK_PADDR(0x%llX) B_VA(0x%llX) pmd_idx(%d)<-- 0x%llX [Desired]\n",	\
										GET_BLOCK_FIELD(pmd, UXN),	\
										GET_BLOCK_FIELD(pmd, PXN),	\
										GET_BLOCK_FIELD(pmd, CONT),	\
										GET_BLOCK_FIELD(pmd, NG),	\
										GET_BLOCK_FIELD(pmd, AF),	\
										GET_BLOCK_FIELD(pmd, SH),	\
										GET_BLOCK_FIELD(pmd, AP),	\
										GET_BLOCK_FIELD(pmd, NS),	\
										GET_BLOCK_FIELD(pmd, ATTR_IDX),	\
										pmd & PMD_BLOLCK_ADDR_MASK,	\
										__va(pmd & PMD_BLOLCK_ADDR_MASK),	\
										pmd_index(addr),	\
										pmd	\
										)

#define print_pmdInfo(pmd, addr) myprintk("PMD: NST(%d) APT(%d) UXNT(%d) PXNT(%d) RES0(%d) PT_ADDR(0x%llX) pmd_idx(%d)<-- 0x%llX\n",	\
									GET_FIELD(pmd, NST),	\
									GET_FIELD(pmd, APT),	\
									GET_FIELD(pmd, UXNT),	\
									GET_FIELD(pmd, PXNT),	\
									GET_FIELD(pmd, RES0),	\
									pmd & PMD_ADDR_MASK,	\
									pmd_index(addr),	\
									pmd	\
									)

#define print_pteInfo(pte, addr, postfix) myprintk("PT__E: [%03d,%03d,%03d,%03d] UXN(%d) PXN(%d) CONT(%d) NG(%d) AF(%d) SH(%d) AP(%d) NS(%d) ATTR(%d) OA(0x%llX) pte_idx(%d)<-- 0x%llX [" postfix "]\n",	\
									pgd_index(addr), 		\
									pud_index(addr),		\
									pmd_index(addr),		\
									pte_index(addr),		\
									GET_PTE_FIELD(pte, UXN),	\
									GET_PTE_FIELD(pte, PXN),	\
									GET_PTE_FIELD(pte, CONT),	\
									GET_PTE_FIELD(pte, NG),	\
									GET_PTE_FIELD(pte, AF),	\
									GET_PTE_FIELD(pte, SH),	\
									GET_PTE_FIELD(pte, AP),	\
									GET_PTE_FIELD(pte, NS),	\
									GET_PTE_FIELD(pte, ATTR_IDX),	\
									pte & OA_ADDR_MASK,	\
									pte_index(addr),	\
									pte	\
									)
#define TLB_INVALIDATE_ALL(	)			\
	asm volatile(  						\
					"dsb ishst\n"		\
					"tlbi vmalle1is\n" 	\
				   	"dsb ish\n"			\
					"isb"				\
					::: "memory" ) 

inline void TLB_INVALIDATE_ALL_TOP(unsigned long long entry) {
	asm volatile(	"dc cvac, %[entry]\n"
					"dsb ishst\n"
					:: [entry] "r" (entry) : "memory" );
}
#define TLB_INVALIDATE_ALL_BOTTOM()		\
	asm volatile(  						\
					"tlbi vmalle1is\n"	\
				   	"dsb ish\n"			\
					"isb"				\
					::: "memory" )

static void makeEntryRO(unsigned long long addr, int logLevel) {
	//find PTE for addr
	pgd_t *pPgd_e;
	pud_t *pPud_e;
	pmd_t *pPmd_e;
	pte_t *pPte;
	unsigned long long pgd_e;
	unsigned long long pud_e;
	unsigned long long pmd_e;
	unsigned long long pte;
	unsigned int ap;
	int bIsBlock;

	pPgd_e = pgd_offset_k(addr);
	pgd_e = pgd_val((*pPgd_e));
	if (logLevel >= YMH_PTERO_LOGLEVEL_DEBUG) print_pgdInfo(pgd_e, addr);

	pPud_e = pud_offset(pPgd_e, addr);
	pud_e = pud_val((*pPud_e));
	if ( IS_POINTING_BLOCK(pud_e)/*(pud & 0b11) == 0b1*/ ) myprintk("PUD: 0x%llX <--------- BLOCK! (1GB) something wrong\n", pud_e);
	else {
		if ( !IS_POINTING_TABLE(pud_e) /*(pud & 0b11) != 0b11*/ ) myprintk("PUD: 0x%llX <--------- somthing wrong!\n", pud_e);
		if (logLevel >= YMH_PTERO_LOGLEVEL_DEBUG) print_pudInfo(pud_e, addr);
	}

	pPmd_e = pmd_offset(pPud_e, addr);
	pmd_e = pmd_val((*pPmd_e));
	if ( IS_POINTING_BLOCK(pmd_e) /*(pmd & 0b11) == 0b1*/ ) {
		if (logLevel >= YMH_PTERO_LOGLEVEL_RESULT_ALL) print_pmdBlockInfo(pmd_e, addr, "BEFORE");

		// FOR NOW, don't make BLOCKs RO. <- if the following line is commented out
		if (  IS_READY_ONLY(pmd_e) /*pmd_val((*pPmd)) & (0b10 << BLOCK_AP_SHIFT)*/ ) {
		} else {
			// I am going to change PMD_E's AP bits.
			// That means I am going to modify the page/block containing PMD_E.
			// So, before I modify it, I have to check whether the page/block is writable
			// To do so, I have to check the AP bits of the entry pointing to the page/block, not the PMD_E itself.
			ap = findOA((unsigned long long) pPmd_e, 1 /*bKaddr*/, "[CHECK_AP] ", "PMD_E", 1 /*bCheckAP*/, &bIsBlock /*pIsBlock*/, 0 /*bSilent*/, 1 /*bUseMyprintk*/);

			if (bIsBlock) {
				extern int isInPTPBlockRange(unsigned long long addr);
				myprintk("isInPTPBlockRange: %d\n", isInPTPBlockRange((unsigned long long) pPmd_e));
			}

			// 
			// If the PUD entry is RO, we have to ask the secure world to change it or turn off MMU temporarily to change the PMD entry with physical address.
			// I will ask to the secure world.

			if (ap & 0b10) panic("AP AP AP-1");

			flush_tlb_all();
			pmd_val(*pPmd_e) = pmd_e | (0b10 << BLOCK_AP_SHIFT);

			// test
			print_pmdBlockInfo(pmd_val(*pPmd_e), addr, "DESIRED");

			flush_tlb_all();
			panic("After TLBIs");
		}

		pPgd_e = pgd_offset_k(addr);
		pPud_e = pud_offset(pPgd_e, addr);
		pPmd_e = pmd_offset(pPud_e, addr);
		pmd_e = pmd_val(*pPmd_e);
		panic("You've reached...");
		if (logLevel >= YMH_PTERO_LOGLEVEL_RESULT_ALL) print_pmdBlockInfo(pmd_e, addr, "AFTER"); //print_pmdBlockInfoAfter(pmd, addr);
		return;
	} else {
		if ( !IS_POINTING_PAGE(pmd_e) /*(pmd & 0b11) != 0b11*/ ) myprintk("PMD: 0x%llX <--------- somthing wrong!\n", pmd_e);
		if (logLevel >= YMH_PTERO_LOGLEVEL_DEBUG) print_pmdInfo_simple(pmd_e, addr);
	}

	pPte = pte_offset_kernel(pPmd_e, addr);
	pte = pte_val(*pPte);
	if ( !IS_POINTING_PAGE(pte) /*(pte & 0b11) != 0b11*/ ) {
		myprintk("PTE: 0x%llX <--------- WRONG!\n", pte);
		return;
	} //else if (logLevel >= YMH_PTERO_LOGLEVEL_RESULT_PTE) print_pteInfo(pte, addr, "BEFORE");

	if ( IS_READY_ONLY(pte) /*pte_val((*pPte)) & (0b10 << PTE_AP_SHIFT)*/ ) {
		if (logLevel >= YMH_PTERO_LOGLEVEL_RESULT_ALL) myprintk("Don't make PT_E read-only multiple times\n");
	} else {
		// I am going to make PT_E read-only.
		// That means I am going to modify the page/block containing PT_E.
		// So, before I modify it, I have to check whether the page/block is writable
		// To do so, I have to check the AP bits of the entry pointing to the page/block
		ap = findOA((unsigned long long) pPte, 1 /*bKaddr*/, "[CHECK_AP] ", "PT__E", 1 /*bCheckAP*/, &bIsBlock /*pIsBlock*/, 1 /*0*/ /*bSilent*/, 1 /*bUseMyprintk*/);

		if (bIsBlock) {
			extern int isInPTPBlockRange(unsigned long long addr);
			myprintk("isInPTPBlockRange: %d\n", isInPTPBlockRange((unsigned long long) pPmd_e));
		}

		if (ap & 0b10) {
			ginseng_smc(GINSENG_SMC_CMD_SET_64BIT, (unsigned long long) pPte, pte | (0b10 << PTE_AP_SHIFT), 0, 0, 0);
		} else pte_val(*pPte) = pte | (0b10 << PTE_AP_SHIFT);

		// invalidate TLB
		flush_tlb_all();
	}

		pPgd_e = pgd_offset_k(addr);
		pPud_e = pud_offset(pPgd_e, addr);
		pPmd_e = pmd_offset(pPud_e, addr);
		pPte = pte_offset_kernel(pPmd_e, addr);
		pte = pte_val(*pPte);
}

int checkAP(unsigned long long addr) {
	pgd_t *pPgd;
	pud_t *pPud;
	pmd_t *pPmd;
	pte_t *pPte;
	unsigned long long pud;
	unsigned long long pmd;
	unsigned long long pte;
	unsigned long long oa;

	pPgd = pgd_offset_k(addr);
	pPud = pud_offset(pPgd, addr);
	if (pud_none(*pPud)) return -1;
	pud = pud_val((*pPud));
	if ( (pud & 0b11) == 0b1 ) {
		oa = pud & PMD_ADDR_MASK;
		myprintk("1G block found - somthing wrong...oa(0x%llX)\n", oa);
		return -1;
	}

	pPmd = pmd_offset(pPud, addr);
	if (pmd_none(*pPmd)) return -1;
	pmd = pmd_val((*pPmd));
	if ( (pmd & 0b11) == 0b1 ) {
		oa = pmd & PT_ADDR_MASK;
		return GET_BLOCK_FIELD(pmd, AP);
	}
	if ( (pmd & 0b11) != 0b11 ) {
		myprintk("PMD: 0x%llX <--------- WRONG!\n", pmd);
		return -1;
	}

	pPte = pte_offset_kernel(pPmd, addr);
	pte = pte_val((*pPte));
	if ( (pte & 0b11) != 0b11 ) {
		myprintk("PTE: 0x%llX <--------- WRONG!\n", pte);
		myprintk("pgd_idx(%d) pud_idx(%d) pmd_idx(%d) pte_idx(%d)\n", pgd_index(addr), pud_index(addr), pmd_index(addr), pte_index(addr));
		return -1;
	} else {
		oa = pte & OA_ADDR_MASK;
		return GET_PTE_FIELD(pte, AP);
	}

	return -1;
}

// return OA when bCheckAP=0
// return AP when bCheckAP=1
// return -1..-4 when *_none
unsigned long long findOA(unsigned long long addr, int bKaddr, const char* blanks, const char* who, int bCheckAP, int *pIsBlock, int bSilent, int bUseMyprintk) {
	pgd_t *pPgd;
	pud_t *pPud;
	pmd_t *pPmd;
	pte_t *pPte;
	unsigned long long pud;
	unsigned long long pmd;
	unsigned long long pte;
	unsigned long long oa;

	if (pIsBlock) *pIsBlock = 0;

	if (addr >= 0xFFFF000000000000ULL) {
		if (!bKaddr) panic("You said it's user addr, but it's a kernel addr");
	} else {
		if (bKaddr) panic("You said it's a kernel addr, but it's a user addr");
	}

	if (likely(bKaddr)) pPgd = pgd_offset_k(addr);
	else pPgd = pgd_offset(current->mm, addr);

	if (pgd_none(*pPgd)) {
		panic("PGD_NONE (0x%llx) @ (0x%llx)", (unsigned long long) pgd_val(*pPgd), (unsigned long long) pPgd);
		return -1;
	}
	pPud = pud_offset(pPgd, addr);
	if(pud_none(*pPud)) {
		panic("PUD_NONE");
		return -2;
	}
	pud = pud_val((*pPud));
	if ( (pud & 0b11) == 0b1 ) {
		oa = pud & PMD_ADDR_MASK;
		if (!bSilent) {
			if (bUseMyprintk) myprintk("%s1G block found - somthing wrong...oa(0x%llX)\n", blanks, oa);
			else pr_emerg("###YMH### %s1G block found - somthing wrong...oa(0x%llX)\n", blanks, oa);
		}
		return oa;
	}

	pPmd = pmd_offset(pPud, addr);
	if(pmd_none(*pPmd)) {
		panic("PMD_NONE");
		return -3;
	}
	pmd = pmd_val((*pPmd));
	if ( (pmd & 0b11) == 0b1 ) {
		oa = pmd & PT_ADDR_MASK;
		if (pIsBlock) *pIsBlock = 1;
		if (bCheckAP) {
			if (!bSilent) {
				if (bUseMyprintk) myprintk("%s%s @0x%llX is in a 2MB block [%03d,%03d,%03d] PMD_E(0x%016llX) AP(%d) @ 0x%llX phy(0x%llX)\n", blanks, who, addr,
									pgd_index(addr), pud_index(addr), pmd_index(addr),
									pmd, GET_BLOCK_FIELD(pmd, AP),
									(unsigned long long) __va(oa), oa);
				else pr_emerg("###YMH### %s%s is in a 2MB block [%03d,%03d,%03d] PMD_E(0x%016llX) AP(%d) @ 0x%llX phy(0x%llX)\n", blanks, who, 
									(int) pgd_index(addr), (int) pud_index(addr), (int) pmd_index(addr),
									pmd, (int) GET_BLOCK_FIELD(pmd, AP),
									(unsigned long long) __va(oa), oa);
			}
			return GET_BLOCK_FIELD(pmd, AP);
		} else {
			if (!bSilent) {
				if (bUseMyprintk) myprintk("%s%s @ 0x%llX is in a 2MB block [%03d,%03d,%03d] @ 0x%llX phy(0x%llX)\n", blanks, who, addr,
									pgd_index(addr), pud_index(addr), pmd_index(addr),
									(unsigned long long) __va(oa), oa);
				else pr_emerg("###YMH### %s%s is in a 2MB block [%03d,%03d,%03d] @ 0x%llX phy(0x%llX)\n", blanks, who, 
									(int) (int) pgd_index(addr), (int) pud_index(addr), (int) pmd_index(addr),
									(unsigned long long) __va(oa), oa);
			}
		}
		return oa;
	}
	if ( (pmd & 0b11) != 0b11 && !bSilent) {
		if (bUseMyprintk) myprintk("PMD: 0x%llX <--------- WRONG!\n", pmd);
		else pr_emerg("###YMH### PMD: 0x%llX <--------- WRONG!\n", pmd);
	}

	pPte = pte_offset_kernel(pPmd, addr);
	if (pte_none(*pPte)) {
		panic("PTE_NONE");
		return -4;
	}
	pte = pte_val((*pPte));
	if ( (pte & 0b11) != 0b11 && !bSilent) {
		if (bUseMyprintk) {
			myprintk("%sPTE: 0x%llX <--------- WRONG!\n", blanks, pte);
			myprintk("pgd_idx(%d) pud_idx(%d) pmd_idx(%d) pte_idx(%d)\n", pgd_index(addr), pud_index(addr), pmd_index(addr), pte_index(addr));
		} else {
			pr_emerg("###YMH### %sPTE: 0x%llX <--------- WRONG!\n", blanks, pte);
			pr_emerg("###YMH### pgd_idx(%d) pud_idx(%d) pmd_idx(%d) pte_idx(%d)\n", (int) pgd_index(addr), (int) pud_index(addr), (int) pmd_index(addr), (int) pte_index(addr));
		}
	}
	else {
		oa = pte & OA_ADDR_MASK;
		if (bCheckAP) {
			if (!bSilent) {
				if (bUseMyprintk) myprintk("%s%s is in a 4K page [%03d,%03d,%03d,%03d] PT_E(0x%016llX) AP(%d) @ 0x%llX, phy(0x%llX)\n", blanks, who, 
									pgd_index(addr), pud_index(addr), pmd_index(addr), pte_index(addr), 
									pte, GET_PTE_FIELD(pte, AP),
									(unsigned long long) __va(oa), oa);
				else pr_emerg("###YMH### %s%s is in a 4K page [%03d,%03d,%03d,%03d] PT_E(0x%016llX) AP(%d) @ 0x%llX, phy(0x%llX)\n", blanks, who, 
									(int) pgd_index(addr), (int) pud_index(addr), (int) pmd_index(addr), (int) pte_index(addr), 
									pte, (int) GET_PTE_FIELD(pte, AP),
									(unsigned long long) __va(oa), oa);
			}
			return GET_PTE_FIELD(pte, AP);
		} else {
			if (!bSilent) {
				if (bUseMyprintk) myprintk("%s%s is in a 4K page [%03d,%03d,%03d,%03d] @ 0x%llX, phy(0x%llX)\n", blanks, who, 
									pgd_index(addr), pud_index(addr), pmd_index(addr), pte_index(addr), 
									(unsigned long long) __va(oa), oa);
				else pr_emerg("###YMH### %s%s is in a 4K page [%03d,%03d,%03d,%03d] @ 0x%llX, phy(0x%llX)\n", blanks, who, 
									(int) pgd_index(addr), (int) pud_index(addr), (int) pmd_index(addr), (int) pte_index(addr), 
									(unsigned long long) __va(oa), oa);
			}
		}
		return oa;
	}

	return 0;
}
EXPORT_SYMBOL(findOA);

// find a page or block that contains the entry (pEntry)
unsigned long long findContainingPageBlock(unsigned long long pEntry, char *strType) {
	pgd_t *pPgd_e;
	pud_t *pPud_e;
	pmd_t *pPmd_e;
	pte_t *pPt_e;
	unsigned long long pud_e;
	unsigned long long pmd_e;
	unsigned long long pt_e;
	unsigned long long oa;

	pPgd_e = pgd_offset_k(pEntry);

	pPud_e = pud_offset(pPgd_e, pEntry);
	pud_e = pud_val((*pPud_e));
	if ( (pud_e & 0b11) == 0b1 ) {
		oa = pud_e & PMD_ADDR_MASK;
		myprintk("%s 1G block found - somthing wrong...oa(0x%llX)\n", strType, oa);
		return pud_e;
	}

	pPmd_e = pmd_offset(pPud_e, pEntry);
	pmd_e = pmd_val((*pPmd_e));
	if ( (pmd_e & 0b11) == 0b1 ) {
		oa = pmd_e & PT_ADDR_MASK;
		myprintk("%s Entry(@0x%llX) belongs to a 2MB block PMD_E[0x%016llX] [%03d,%03d,%03d]\n", strType, pEntry, pmd_e, 
			pgd_index(pEntry), pud_index(pEntry), pmd_index(pEntry) );
		return pmd_e;
	}
	if ( (pmd_e & 0b11) != 0b11 ) myprintk("%s PMD_E: 0x%llX <--------- WRONG!\n", strType, pmd_e);

	pPt_e = pte_offset_kernel(pPmd_e, pEntry);
	pt_e = pte_val((*pPt_e));
	if ( (pt_e & 0b11) != 0b11 ) {
		myprintk("%s PT_E: 0x%llX <--------- WRONG!\n", strType, pt_e);
		// myprintk("pgd_idx(%d) pud_idx(%d) pmd_idx(%d) pte_idx(%d)\n", pgd_index(pEntry), pud_index(pEntry), pmd_index(pEntry), pte_index(pEntry));
	}
	else {
		oa = pt_e & OA_ADDR_MASK;
		// myprintk("4K page found: oa(0x%llX)\n", oa);

		myprintk("%s Entry(@0x%llX) belongs to a PAGE PT_E[0x%016llX] [%03d,%03d,%03d,%03d]\n", strType, pEntry, pt_e,
			pgd_index(pEntry), pud_index(pEntry), pmd_index(pEntry), pte_index(pEntry) );
		return pt_e;
	}

	return 0;	
}

static void initBlocksForTablesAndNormal(void) {
	memset(&blocksForPTP, 0, sizeof(blocksForPTP));
	memset(&blocksForNormalPage, 0, sizeof(blocksForNormalPage));
}

#if 0
static int isInBlock(unsigned long long block_vaddr) {
	int i;

	// I can use idx_blocksForTables as the limit to remove a condition. 
	// But for now, leave it.
	for (i = 0; i < NR_BLOCKS_FOR_TABLES; i++) {
		if (blocksForTables[i] && blocksForTables[i] == block_vaddr) return 1;
		if (!blocksForTables[i]) break;
	}

	return 0;
}

// if vaddr is in a block, return the block starting address
static unsigned long long isInBlockRange(unsigned long long vaddr) {
	int i;
	unsigned long long blockStartingAddr;

	// I can use idx_blocksForTables as the limit to remove a condition. 
	// But for now, leave it.
	for (i = 0; i < NR_BLOCKS_FOR_TABLES; i++) {
		blockStartingAddr = (unsigned long long) blocksForTables[i];
		if (!blockStartingAddr) break;
		if (blockStartingAddr <= vaddr && 
			vaddr < (blockStartingAddr + 0x200000) ) return blockStartingAddr;
	}

	return 0;
}
static void addBlockNoDup(unsigned long long paddr) {
	unsigned long long vaddr = __va(paddr);

	if (idx_blocksForTables >= NR_BLOCKS_FOR_TABLES) {
		myprintk("Cannnot add more blocks to blocksForTables\n");
		return;
	}

	// return when there is a duplicate entry
	if (isInBlock(vaddr)) return;

	blocksForTables[idx_blocksForTables++] = vaddr;
}

static void printBlocksForTables(void) {
	int i;

	for (i = 0; i < NR_BLOCKS_FOR_TABLES; i++) {
		if ( !blocksForTables[i] ) break;
		myprintk("0x%llX has table(s)\n", blocksForTables[i]);
	}
	myprintk("%d blocks have tables\n", i);
}
#else
// returns found block list index
static int findBlockInBlocks(unsigned long long block_vaddr, void **blockList, int idx) {
	int i;

	for (i = 0; i < idx; i++) {
		if (blockList[i] && blockList[i] == (void *) block_vaddr) return i;
	}

	return -1;
}

static int findBlockInPTPBlocks(unsigned long long block_vaddr) {
	return findBlockInBlocks(block_vaddr, blocksForPTP.blocks, blocksForPTP.idx_blocks);
}

static int isPageInBlock(unsigned long long page_vaddr, void **pageList, int idx) {
	int i;

	for (i = 0; i < idx; i++)
		if (pageList[i] == (void *) page_vaddr) return i;

	return 0;
}

#define ADD_BLOCK_RTN_NONE 			0x00000000
#define ADD_BLOCK_RTN_ADDED_BLOCK	0x00000001
#define ADD_BLOCK_RTN_ADDED_PAGE	0x00000002
static unsigned int addBlockNoDup(unsigned long long block_paddr, blocks *pBlocksInfo, unsigned long long page_vaddr) {
	unsigned long long block_vaddr = (unsigned long long) __va(block_paddr);
	int block_idx = 0;
	int *pIdx_page;
	int *pIdx_block;
	void **pageList;
	void **blockList = pBlocksInfo->blocks;
	unsigned int rtn = ADD_BLOCK_RTN_NONE;

	if (pBlocksInfo == &blocksForPTP) pIdx_block = &blocksForPTP.idx_blocks;
	else pIdx_block = &blocksForNormalPage.idx_blocks;

	if (*pIdx_block >= NR_BLOCKS_FOR_TABLES) {
		myprintk("Cannnot add more blocks\n");
		return rtn;
	}


	// new block? -> add it
	block_idx = findBlockInBlocks(block_vaddr, blockList, *pIdx_block);
	if ( block_idx == -1 ) {
		blockList[(*pIdx_block)++] = (void *) block_vaddr;
		block_idx = (*pIdx_block);
		rtn |= ADD_BLOCK_RTN_ADDED_BLOCK;
	}

	if (pBlocksInfo == &blocksForPTP) {
		pIdx_page = &blocksForPTP.idx_pages[block_idx];
		pageList = blocksForPTP.pages[block_idx];
	} else {
		pIdx_page = &blocksForNormalPage.idx_pages[block_idx];
		pageList = blocksForNormalPage.pages[block_idx];
	}

	// add page without duplicate
	if ( page_vaddr && !isPageInBlock(page_vaddr, pageList, *pIdx_page) ) {
		pageList[(*pIdx_page)++] = (void *) page_vaddr;
		rtn |= ADD_BLOCK_RTN_ADDED_PAGE;
	} 
	return rtn;
}

void printBlockInfo_PTP(void) {
	printBlockInfo(&blocksForPTP, "BLOCKS for PTP", 0 /*bUseMyprintk*/);
}

void printBlockInfo_normal(void) {
	printBlockInfo(&blocksForNormalPage, "BLOCKS for NORMAL", 0 /*bUseMyprintk*/);
}

static void printBlockInfo(blocks *pBlocks, char *strHead, int bUseMyprintk) {
	int i, j;
	int nr_blocks = pBlocks->idx_blocks;
	int nr_pages;
	void **blockList = pBlocks->blocks;
	void **pageList;
	int *pIdx_page = pBlocks->idx_pages;

	int total_paegs = 0;

	if (bUseMyprintk) myprintk("%s\n", strHead);
	else pr_emerg("###YMH### %s\n", strHead);

	for (i = 0; i < nr_blocks; i++) {
		if (bUseMyprintk) myprintk("Block @ 0x%llX has: \n", (unsigned long long) blockList[i]);
		else pr_emerg("###YMH### Block @ 0x%llX has: \n", (unsigned long long) blockList[i]);
		nr_pages = pIdx_page[i];
		pageList = pBlocks->pages[i];// //pPageList[i];
		for (j = 0; j < nr_pages; j++)
			if (bUseMyprintk) myprintk("  0x%llX\n", (unsigned long long) pageList[j]);
		else pr_emerg("###YMH###   0x%llX\n", (unsigned long long) pageList[j]);

		total_paegs += j;
	}
	if (bUseMyprintk) myprintk("STAT: %d blocks %d pages\n", i, total_paegs);
	else pr_emerg("###YMH### STAT: %d blocks %d pages\n", i, total_paegs);
}
#endif

extern unsigned int addBlockNoDupPTP_LIVE(unsigned long long block_paddr, unsigned long long page_vaddr);
void findPagetables(int bMakeReadOnly, int bVerbose, int bTraceTablesInBlock, int bUseMyprintk, int bAddToLive) {
	char who[16];
	unsigned long long addr = (unsigned long long) swapper_pg_dir;
	unsigned long long oa;
	int i, j, k; //, l;
	pgd_t pgd_e;
	pud_t pud_e;
	pmd_t pmd_e;
	// pte_t pt_e;

	pud_t *pPud;
	pmd_t *pPmd;
	pte_t *pPt;
	int isBlock;

	int nr_pud = 0;
	int nr_pmd = 0;
	int nr_pt = 0;

	unsigned int rtn;

	if (bTraceTablesInBlock) initBlocksForTablesAndNormal();

	if (bVerbose) {
		if (bUseMyprintk) myprintk("Find level-0 table\n");
		else pr_emerg("###YMH### Find level-0 table\n");
	}
	if (bMakeReadOnly) {
		if (bUseMyprintk) myprintk("--Making level-0 table read-only\n");
		else pr_emerg("###YMH### --Making level-0 table read-only\n");
		// makeEntryRO(addr, YMH_PTERO_LOGLEVEL_RESULT_ALL);
		makeEntryRO(addr, YMH_PTERO_LOGLEVEL_DEBUG);
	} else {
		sprintf(who, "PGD");
		oa = findOA(addr, 1 /*bKaddr*/, "", who, 0 /*bCheckAP*/, &isBlock, !bVerbose /*bSilent*/, bUseMyprintk);
		if (bTraceTablesInBlock && isBlock) {
			rtn = addBlockNoDup(oa, &blocksForPTP, addr);
			if (bAddToLive && rtn) addBlockNoDupPTP_LIVE(oa, addr);	// this is for the initial pagetables
		}
			

		if (!oa) {
			if (bUseMyprintk) myprintk("OA is ZERO: somthing wrong....\n");
			else pr_emerg("###YMH### OA is ZERO: somthing wrong....\n");
			return;
		}
	}

	if (bVerbose) {
		if (bUseMyprintk) myprintk("Find level-1/2/3 tables\n");
		else pr_emerg("###YMH### Find level-1/2/3 tables\n");
	}
	if (bMakeReadOnly) {
		if (bUseMyprintk) myprintk("--Making level-1/2/3 tables read-only\n");
		else pr_emerg("###YMH### --Making level-1/2/3 tables read-only\n");
	}
	for (i = 0; i < PTRS_PER_PGD; i++) { 	// iterate PGD entries - level 0
		pgd_e = swapper_pg_dir[i];

		switch (pgd_val(pgd_e) & 0b11) {
		case 0b10:
		case 0b00:
			// invalid pud
			break;
		case 0b01:
			if (bUseMyprintk) myprintk("ERROR: BLOCK found in level 0");
			else pr_emerg("###YMH### ERROR: BLOCK found in level 0");
			break;
		case 0b11:
			pPud = (pud_t *)__va(pgd_page_paddr(pgd_e));
			if (bVerbose) {
				if (bUseMyprintk) myprintk("PGD[%03d](=0x%lX) -> PUD @ 0x%llX\n", i, pgd_val(pgd_e), (unsigned long long) pPud);
				else pr_emerg("###YMH### PGD[%03d](=0x%llX) -> PUD @ 0x%llX\n", i, pgd_val(pgd_e), (unsigned long long) pPud);
			}
			if (bMakeReadOnly) {
				if (bUseMyprintk) myprintk("[PUD -> RO] @ 0x%16llX\n", pPud);
				else pr_emerg("###YMH### [PUD -> RO] @ 0x%16llX\n", (unsigned long long) pPud);
				makeEntryRO((unsigned long long)pPud, YMH_PTERO_LOGLEVEL_RESULT_ALL);
				nr_pud++;
			} else {
				sprintf(who, "PUD");
				oa = findOA( (unsigned long long) pPud, 1 /*bKaddr*/, "  ", who, 0 /*bCheckAP*/, &isBlock, !bVerbose /*bSilent*/, bUseMyprintk);
				if (bTraceTablesInBlock && isBlock) {
					rtn = addBlockNoDup(oa, &blocksForPTP, (unsigned long long)pPud);
					if (bAddToLive && rtn) addBlockNoDupPTP_LIVE(oa, addr);	// this is for the initial pagetables
				}
					
				if (!oa) {
					if (bUseMyprintk) myprintk("OA is ZERO: somthing wrong....0\n");
					else pr_emerg("###YMH### OA is ZERO: somthing wrong....0\n");
				}
			}

			for(j = 0; j < PTRS_PER_PUD; j++) {	// iterate PUD entries - level 1
				pud_e = pPud[j];
				if (pud_val(pud_e)) {
					if ( (pud_val(pud_e) & 0b11) == 0b1 ) {
						if (bUseMyprintk) myprintk("ERROR: 0x%llX <--------- BLOCK! (1GB)\n", pud_val(pud_e));
						else pr_emerg("###YMH### ERROR: 0x%llX <--------- BLOCK! (1GB)\n", pud_val(pud_e));
					}
					else {
						if ( (pud_val(pud_e) & 0b11) != 0b11 ) {
							if (bUseMyprintk) myprintk("ERROR: 0x%llX <--------- somthing wrong!\n", pud_val(pud_e));
							else pr_emerg("###YMH### ERROR: 0x%llX <--------- somthing wrong!\n", pud_val(pud_e));
						}
						pPmd = (pmd_t *) __va(pud_page_paddr(pud_e));
						if (bVerbose) {
							if (bUseMyprintk) myprintk("  PUD[%03d,%03d](=0x%lX) -> PMD @ 0x%llX\n", i,j, pud_val(pud_e), (unsigned long long) pPmd);
							else pr_emerg("###YMH###   PUD[%03d,%03d](=0x%llX) -> PMD @ 0x%llX\n", i,j, pud_val(pud_e), (unsigned long long) pPmd);
						}
						if (bMakeReadOnly) {
							if (bUseMyprintk) myprintk("  [PMD -> RO] @ 0x%16llX\n", pPmd);
							else pr_emerg("###YMH###   [PMD -> RO] @ 0x%16llX\n", (unsigned long long) pPmd);
							makeEntryRO((unsigned long long)pPmd, YMH_PTERO_LOGLEVEL_RESULT_ALL);
							nr_pmd++;
						} else {
							sprintf(who, "PMD");
							oa = findOA( (unsigned long long) pPmd, 1 /*bKaddr*/, "    ", who, 0 /*bCheckAP*/, &isBlock, !bVerbose /*bSilent*/, bUseMyprintk);
							if (bTraceTablesInBlock && isBlock) {
								rtn = addBlockNoDup(oa, &blocksForPTP, (unsigned long long)pPmd);
								if (bAddToLive && rtn) addBlockNoDupPTP_LIVE(oa, addr);	// this is for the initial pagetables
							}
								
							if (!oa) {
								if (bVerbose) {
									if (bUseMyprintk) myprintk("OA is ZERO: somthing wrong....1\n");
									else pr_emerg("###YMH### OA is ZERO: somthing wrong....1\n");
								}
							}
						}

						for(k = 0; k < PTRS_PER_PMD; k++) { // iterate PMD entries - level 2
							pmd_e = pPmd[k];
							if (pmd_val(pmd_e)) {
								pPt = (pte_t *) __va(pmd_page_paddr(pmd_e));
								if ( (pmd_val(pmd_e) & 0b11) == 0b1)  { //<------ points at BLOCK : I decided to check to know whether the BLOCK contains any PT/PMD/PUD
									if (bVerbose) {
										if (bUseMyprintk) myprintk("    PMD[%03d,%03d,%03d](=0x%lX) -> BLOCK @ 0x%llX\n", i,j,k, pmd_val(pmd_e), (unsigned long long) pPt);
										else pr_emerg("###YMH###     PMD[%03d,%03d,%03d](=0x%llX) -> BLOCK @ 0x%llX\n", i,j,k, pmd_val(pmd_e), (unsigned long long) pPt);
									}
								} else if ( (pmd_val(pmd_e) & 0b11) == 0b11) { // PT table: visit!
									if (bVerbose) {
										if (bUseMyprintk) myprintk("    PMD[%03d,%03d,%03d](=0x%lX) -> PT @ 0x%llX\n", i,j,k, pmd_val(pmd_e), (unsigned long long) pPt);
										else pr_emerg("###YMH###     PMD[%03d,%03d,%03d](=0x%llX) -> PT @ 0x%llX\n", i,j,k, pmd_val(pmd_e), (unsigned long long) pPt);
									}
									if (bMakeReadOnly) {
										if (bUseMyprintk) myprintk("    [PT[%03d,%03d,%03d] -> RO] @ 0x%16llX\n", i, j, k, pPt);
										else pr_emerg("###YMH###     [PT[%03d,%03d,%03d] -> RO] @ 0x%16llX\n", i, j, k, (unsigned long long) pPt);
										makeEntryRO((unsigned long long)pPt, YMH_PTERO_LOGLEVEL_RESULT_ALL);
										nr_pt++;
									} else {
										sprintf(who, "PT");
										oa = findOA( (unsigned long long) pPt, 1 /*bKaddr*/, "      ", who, 0 /*bCheckAP*/, &isBlock, !bVerbose /*bSilent*/, bUseMyprintk);
										if (bTraceTablesInBlock && isBlock) {
											rtn = addBlockNoDup(oa, &blocksForPTP, (unsigned long long)pPt);
											if (bAddToLive && rtn) addBlockNoDupPTP_LIVE(oa, addr);	// this is for the initial pagetables
										}
											
										if (!oa) {
											if (bVerbose) {
												if (bUseMyprintk) myprintk("OA is ZERO: somthing wrong....2\n");
												else pr_emerg("###YMH### OA is ZERO: somthing wrong....2\n");
											}
										}
									}
								} else {
									if (bUseMyprintk) myprintk("THEN, WHO ARE YOU? k(%d)\n", k);
									else pr_emerg("###YMH### THEN, WHO ARE YOU? k(%d)\n", k);
								}
							}
						}
					}
				}
			}

			break;
		}
	}

	if (bMakeReadOnly) {
		if (bUseMyprintk) myprintk("READ-ONLY STAT: pud(%d) pmd(%d) pt(%d)\n", nr_pud, nr_pmd, nr_pt);
		else pr_emerg("###YMH### READ-ONLY STAT: pud(%d) pmd(%d) pt(%d)\n", nr_pud, nr_pmd, nr_pt);
	}
}

void printARGS_0_3(unsigned long long arg0, unsigned long long arg1, unsigned long long arg2, unsigned long long arg3) {
	extern int bTraceFault;
	if (bTraceFault) myprintk("arg0(0x%llX) arg1(0x%llX) arg2(0x%llX) arg3(0x%llX)\n", arg0, arg1, arg2, arg3);
}

static void getCacheInfo(void) {
	unsigned int data_l2, data_l1;
	unsigned long cacheLevels;
	asm volatile(
		"mrs %[cacheLevels], clidr_el1\n"

		"mov x0, #0\n"	// L1 D-cache
		"msr csselr_el1, x0\n"
		"mrs %[data_l1], ccsidr_el1\n"

		"mov x0, #0b10\n"	// L2 D-cache
		"msr csselr_el1, x0\n"
		"mrs %[data_l2], ccsidr_el1\n"
		: [cacheLevels] "=r" (cacheLevels), [data_l1] "=r" (data_l1), [data_l2] "=r" (data_l2)
		: 
		: "memory", "x0"
	);

	myprintk("C-LEVEL(0x%016lX) data_l1(0x%08X) data_l2(0x%08X)\n", cacheLevels, data_l1, data_l2);
}

SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)
{
	struct task_struct *g, *p;
	struct user_struct *user;
	const struct cred *cred = current_cred();
	int error = -EINVAL;
	struct pid *pgrp;
	kuid_t uid;

	if (which > PRIO_USER || which < PRIO_PROCESS)
		goto out;

	/* normalize: avoid signed division (rounding problems) */
	error = -ESRCH;
	if (niceval < MIN_NICE)
		niceval = MIN_NICE;
	if (niceval > MAX_NICE)
		niceval = MAX_NICE;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	switch (which) {
	case PRIO_PROCESS:
		if (who)
			p = find_task_by_vpid(who);
		else
			p = current;
		if (p)
			error = set_one_prio(p, niceval, error);
		break;
	case PRIO_PGRP:
		if (who)
			pgrp = find_vpid(who);
		else
			pgrp = task_pgrp(current);
		do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
			error = set_one_prio(p, niceval, error);
		} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
		break;
	case PRIO_USER:
		uid = make_kuid(cred->user_ns, who);
		user = cred->user;
		if (!who)
			uid = cred->uid;
		else if (!uid_eq(uid, cred->uid)) {
			user = find_user(uid);
			if (!user)
				goto out_unlock;	/* No processes for this user */
		}
		do_each_thread(g, p) {
			if (uid_eq(task_uid(p), uid) && task_pid_vnr(p))
				error = set_one_prio(p, niceval, error);
		} while_each_thread(g, p);
		if (!uid_eq(uid, cred->uid))
			free_uid(user);		/* For find_user() */
		break;
	}
out_unlock:
	read_unlock(&tasklist_lock);
	rcu_read_unlock();
out:
	return error;
}

/*
 * Ugh. To avoid negative return values, "getpriority()" will
 * not return the normal nice-value, but a negated value that
 * has been offset by 20 (ie it returns 40..1 instead of -20..19)
 * to stay compatible.
 */
SYSCALL_DEFINE2(getpriority, int, which, int, who)
{
	struct task_struct *g, *p;
	struct user_struct *user;
	const struct cred *cred = current_cred();
	long niceval, retval = -ESRCH;
	struct pid *pgrp;
	kuid_t uid;

	if (which > PRIO_USER || which < PRIO_PROCESS)
		return -EINVAL;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	switch (which) {
	case PRIO_PROCESS:
		if (who)
			p = find_task_by_vpid(who);
		else
			p = current;
		if (p) {
			niceval = nice_to_rlimit(task_nice(p));
			if (niceval > retval)
				retval = niceval;
		}
		break;
	case PRIO_PGRP:
		if (who)
			pgrp = find_vpid(who);
		else
			pgrp = task_pgrp(current);
		do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
			niceval = nice_to_rlimit(task_nice(p));
			if (niceval > retval)
				retval = niceval;
		} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
		break;
	case PRIO_USER:
		uid = make_kuid(cred->user_ns, who);
		user = cred->user;
		if (!who)
			uid = cred->uid;
		else if (!uid_eq(uid, cred->uid)) {
			user = find_user(uid);
			if (!user)
				goto out_unlock;	/* No processes for this user */
		}
		do_each_thread(g, p) {
			if (uid_eq(task_uid(p), uid) && task_pid_vnr(p)) {
				niceval = nice_to_rlimit(task_nice(p));
				if (niceval > retval)
					retval = niceval;
			}
		} while_each_thread(g, p);
		if (!uid_eq(uid, cred->uid))
			free_uid(user);		/* for find_user() */
		break;
	}
out_unlock:
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	return retval;
}

/*
 * Unprivileged users may change the real gid to the effective gid
 * or vice versa.  (BSD-style)
 *
 * If you set the real gid at all, or set the effective gid to a value not
 * equal to the real gid, then the saved gid is set to the new effective gid.
 *
 * This makes it possible for a setgid program to completely drop its
 * privileges, which is often a useful assertion to make when you are doing
 * a security audit over a program.
 *
 * The general idea is that a program which uses just setregid() will be
 * 100% compatible with BSD.  A program which uses just setgid() will be
 * 100% compatible with POSIX with saved IDs.
 *
 * SMP: There are not races, the GIDs are checked only by filesystem
 *      operations (as far as semantic preservation is concerned).
 */
#ifdef CONFIG_MULTIUSER
SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t krgid, kegid;

	krgid = make_kgid(ns, rgid);
	kegid = make_kgid(ns, egid);

	if ((rgid != (gid_t) -1) && !gid_valid(krgid))
		return -EINVAL;
	if ((egid != (gid_t) -1) && !gid_valid(kegid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (rgid != (gid_t) -1) {
		if (gid_eq(old->gid, krgid) ||
		    gid_eq(old->egid, krgid) ||
		    ns_capable(old->user_ns, CAP_SETGID))
			new->gid = krgid;
		else
			goto error;
	}
	if (egid != (gid_t) -1) {
		if (gid_eq(old->gid, kegid) ||
		    gid_eq(old->egid, kegid) ||
		    gid_eq(old->sgid, kegid) ||
		    ns_capable(old->user_ns, CAP_SETGID))
			new->egid = kegid;
		else
			goto error;
	}

	if (rgid != (gid_t) -1 ||
	    (egid != (gid_t) -1 && !gid_eq(kegid, old->gid)))
		new->sgid = new->egid;
	new->fsgid = new->egid;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

/*
 * setgid() is implemented like SysV w/ SAVED_IDS
 *
 * SMP: Same implicit races as above.
 */
SYSCALL_DEFINE1(setgid, gid_t, gid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t kgid;

	kgid = make_kgid(ns, gid);
	if (!gid_valid(kgid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ns_capable(old->user_ns, CAP_SETGID))
		new->gid = new->egid = new->sgid = new->fsgid = kgid;
	else if (gid_eq(kgid, old->gid) || gid_eq(kgid, old->sgid))
		new->egid = new->fsgid = kgid;
	else
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

/*
 * change the user struct in a credentials set to match the new UID
 */
static int set_user(struct cred *new)
{
	struct user_struct *new_user;

	new_user = alloc_uid(new->uid);
	if (!new_user)
		return -EAGAIN;

	/*
	 * We don't fail in case of NPROC limit excess here because too many
	 * poorly written programs don't check set*uid() return code, assuming
	 * it never fails if called by root.  We may still enforce NPROC limit
	 * for programs doing set*uid()+execve() by harmlessly deferring the
	 * failure to the execve() stage.
	 */
	if (atomic_read(&new_user->processes) >= rlimit(RLIMIT_NPROC) &&
			new_user != INIT_USER)
		current->flags |= PF_NPROC_EXCEEDED;
	else
		current->flags &= ~PF_NPROC_EXCEEDED;

	free_uid(new->user);
	new->user = new_user;
	return 0;
}

/*
 * Unprivileged users may change the real uid to the effective uid
 * or vice versa.  (BSD-style)
 *
 * If you set the real uid at all, or set the effective uid to a value not
 * equal to the real uid, then the saved uid is set to the new effective uid.
 *
 * This makes it possible for a setuid program to completely drop its
 * privileges, which is often a useful assertion to make when you are doing
 * a security audit over a program.
 *
 * The general idea is that a program which uses just setreuid() will be
 * 100% compatible with BSD.  A program which uses just setuid() will be
 * 100% compatible with POSIX with saved IDs.
 */
SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kruid, keuid;

	kruid = make_kuid(ns, ruid);
	keuid = make_kuid(ns, euid);

	if ((ruid != (uid_t) -1) && !uid_valid(kruid))
		return -EINVAL;
	if ((euid != (uid_t) -1) && !uid_valid(keuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ruid != (uid_t) -1) {
		new->uid = kruid;
		if (!uid_eq(old->uid, kruid) &&
		    !uid_eq(old->euid, kruid) &&
		    !ns_capable(old->user_ns, CAP_SETUID))
			goto error;
	}

	if (euid != (uid_t) -1) {
		new->euid = keuid;
		if (!uid_eq(old->uid, keuid) &&
		    !uid_eq(old->euid, keuid) &&
		    !uid_eq(old->suid, keuid) &&
		    !ns_capable(old->user_ns, CAP_SETUID))
			goto error;
	}

	if (!uid_eq(new->uid, old->uid)) {
		retval = set_user(new);
		if (retval < 0)
			goto error;
	}
	if (ruid != (uid_t) -1 ||
	    (euid != (uid_t) -1 && !uid_eq(keuid, old->uid)))
		new->suid = new->euid;
	new->fsuid = new->euid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_RE);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

/*
 * setuid() is implemented like SysV with SAVED_IDS
 *
 * Note that SAVED_ID's is deficient in that a setuid root program
 * like sendmail, for example, cannot set its uid to be a normal
 * user and then switch back, because if you're root, setuid() sets
 * the saved uid too.  If you don't like this, blame the bright people
 * in the POSIX committee and/or USG.  Note that the BSD-style setreuid()
 * will allow a root program to temporarily drop privileges and be able to
 * regain them by swapping the real and effective uid.
 */
SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kuid;

	kuid = make_kuid(ns, uid);
	if (!uid_valid(kuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (ns_capable(old->user_ns, CAP_SETUID)) {
		new->suid = new->uid = kuid;
		if (!uid_eq(kuid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	} else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
		goto error;
	}

	new->fsuid = new->euid = kuid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}


/*
 * This function implements a generic ability to update ruid, euid,
 * and suid.  This allows you to implement the 4.4 compatible seteuid().
 */
SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kruid, keuid, ksuid;

	kruid = make_kuid(ns, ruid);
	keuid = make_kuid(ns, euid);
	ksuid = make_kuid(ns, suid);

	if ((ruid != (uid_t) -1) && !uid_valid(kruid))
		return -EINVAL;

	if ((euid != (uid_t) -1) && !uid_valid(keuid))
		return -EINVAL;

	if ((suid != (uid_t) -1) && !uid_valid(ksuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	old = current_cred();

	retval = -EPERM;
	if (!ns_capable(old->user_ns, CAP_SETUID)) {
		if (ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&
		    !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid))
			goto error;
		if (euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&
		    !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid))
			goto error;
		if (suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&
		    !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid))
			goto error;
	}

	if (ruid != (uid_t) -1) {
		new->uid = kruid;
		if (!uid_eq(kruid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	}
	if (euid != (uid_t) -1)
		new->euid = keuid;
	if (suid != (uid_t) -1)
		new->suid = ksuid;
	new->fsuid = new->euid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE3(getresuid, uid_t __user *, ruidp, uid_t __user *, euidp, uid_t __user *, suidp)
{
	const struct cred *cred = current_cred();
	int retval;
	uid_t ruid, euid, suid;

	ruid = from_kuid_munged(cred->user_ns, cred->uid);
	euid = from_kuid_munged(cred->user_ns, cred->euid);
	suid = from_kuid_munged(cred->user_ns, cred->suid);

	retval = put_user(ruid, ruidp);
	if (!retval) {
		retval = put_user(euid, euidp);
		if (!retval)
			return put_user(suid, suidp);
	}
	return retval;
}

/*
 * Same as above, but for rgid, egid, sgid.
 */
SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kgid_t krgid, kegid, ksgid;

	krgid = make_kgid(ns, rgid);
	kegid = make_kgid(ns, egid);
	ksgid = make_kgid(ns, sgid);

	if ((rgid != (gid_t) -1) && !gid_valid(krgid))
		return -EINVAL;
	if ((egid != (gid_t) -1) && !gid_valid(kegid))
		return -EINVAL;
	if ((sgid != (gid_t) -1) && !gid_valid(ksgid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (!ns_capable(old->user_ns, CAP_SETGID)) {
		if (rgid != (gid_t) -1        && !gid_eq(krgid, old->gid) &&
		    !gid_eq(krgid, old->egid) && !gid_eq(krgid, old->sgid))
			goto error;
		if (egid != (gid_t) -1        && !gid_eq(kegid, old->gid) &&
		    !gid_eq(kegid, old->egid) && !gid_eq(kegid, old->sgid))
			goto error;
		if (sgid != (gid_t) -1        && !gid_eq(ksgid, old->gid) &&
		    !gid_eq(ksgid, old->egid) && !gid_eq(ksgid, old->sgid))
			goto error;
	}

	if (rgid != (gid_t) -1)
		new->gid = krgid;
	if (egid != (gid_t) -1)
		new->egid = kegid;
	if (sgid != (gid_t) -1)
		new->sgid = ksgid;
	new->fsgid = new->egid;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE3(getresgid, gid_t __user *, rgidp, gid_t __user *, egidp, gid_t __user *, sgidp)
{
	const struct cred *cred = current_cred();
	int retval;
	gid_t rgid, egid, sgid;

	rgid = from_kgid_munged(cred->user_ns, cred->gid);
	egid = from_kgid_munged(cred->user_ns, cred->egid);
	sgid = from_kgid_munged(cred->user_ns, cred->sgid);

	retval = put_user(rgid, rgidp);
	if (!retval) {
		retval = put_user(egid, egidp);
		if (!retval)
			retval = put_user(sgid, sgidp);
	}

	return retval;
}


/*
 * "setfsuid()" sets the fsuid - the uid used for filesystem checks. This
 * is used for "access()" and for the NFS daemon (letting nfsd stay at
 * whatever uid it wants to). It normally shadows "euid", except when
 * explicitly set by setfsuid() or for access..
 */
SYSCALL_DEFINE1(setfsuid, uid_t, uid)
{
	const struct cred *old;
	struct cred *new;
	uid_t old_fsuid;
	kuid_t kuid;

	old = current_cred();
	old_fsuid = from_kuid_munged(old->user_ns, old->fsuid);

	kuid = make_kuid(old->user_ns, uid);
	if (!uid_valid(kuid))
		return old_fsuid;

	new = prepare_creds();
	if (!new)
		return old_fsuid;

	if (uid_eq(kuid, old->uid)  || uid_eq(kuid, old->euid)  ||
	    uid_eq(kuid, old->suid) || uid_eq(kuid, old->fsuid) ||
	    ns_capable(old->user_ns, CAP_SETUID)) {
		if (!uid_eq(kuid, old->fsuid)) {
			new->fsuid = kuid;
			if (security_task_fix_setuid(new, old, LSM_SETID_FS) == 0)
				goto change_okay;
		}
	}

	abort_creds(new);
	return old_fsuid;

change_okay:
	commit_creds(new);
	return old_fsuid;
}

/*
 * Samma på svenska..
 */
SYSCALL_DEFINE1(setfsgid, gid_t, gid)
{
	const struct cred *old;
	struct cred *new;
	gid_t old_fsgid;
	kgid_t kgid;

	old = current_cred();
	old_fsgid = from_kgid_munged(old->user_ns, old->fsgid);

	kgid = make_kgid(old->user_ns, gid);
	if (!gid_valid(kgid))
		return old_fsgid;

	new = prepare_creds();
	if (!new)
		return old_fsgid;

	if (gid_eq(kgid, old->gid)  || gid_eq(kgid, old->egid)  ||
	    gid_eq(kgid, old->sgid) || gid_eq(kgid, old->fsgid) ||
	    ns_capable(old->user_ns, CAP_SETGID)) {
		if (!gid_eq(kgid, old->fsgid)) {
			new->fsgid = kgid;
			goto change_okay;
		}
	}

	abort_creds(new);
	return old_fsgid;

change_okay:
	commit_creds(new);
	return old_fsgid;
}
#endif /* CONFIG_MULTIUSER */

/**
 * sys_getpid - return the thread group id of the current process
 *
 * Note, despite the name, this returns the tgid not the pid.  The tgid and
 * the pid are identical unless CLONE_THREAD was specified on clone() in
 * which case the tgid is the same in all threads of the same group.
 *
 * This is SMP safe as current->tgid does not change.
 */
unsigned long long ymh_sysentry_afterKernelEntry_addr = 0;
unsigned int ymh_magic = 0x11223344;
SYSCALL_DEFINE0(getpid)
{
	return task_tgid_vnr(current);
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
	return task_pid_vnr(current);
}

/*
 * Accessing ->real_parent is not SMP-safe, it could
 * change from under us. However, we can use a stale
 * value of ->real_parent under rcu_read_lock(), see
 * release_task()->call_rcu(delayed_put_task_struct).
 */
SYSCALL_DEFINE0(getppid)
{
	int pid;

	rcu_read_lock();
	pid = task_tgid_vnr(rcu_dereference(current->real_parent));
	rcu_read_unlock();

	return pid;
}

SYSCALL_DEFINE0(getuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_uid());
}

SYSCALL_DEFINE0(geteuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_euid());
}

SYSCALL_DEFINE0(getgid)
{
	/* Only we change this so SMP safe */
	return from_kgid_munged(current_user_ns(), current_gid());
}

SYSCALL_DEFINE0(getegid)
{
	/* Only we change this so SMP safe */
	return from_kgid_munged(current_user_ns(), current_egid());
}

void do_sys_times(struct tms *tms)
{
	cputime_t tgutime, tgstime, cutime, cstime;

	thread_group_cputime_adjusted(current, &tgutime, &tgstime);
	cutime = current->signal->cutime;
	cstime = current->signal->cstime;
	tms->tms_utime = cputime_to_clock_t(tgutime);
	tms->tms_stime = cputime_to_clock_t(tgstime);
	tms->tms_cutime = cputime_to_clock_t(cutime);
	tms->tms_cstime = cputime_to_clock_t(cstime);
}

SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
{
	if (tbuf) {
		struct tms tmp;

		do_sys_times(&tmp);
		if (copy_to_user(tbuf, &tmp, sizeof(struct tms)))
			return -EFAULT;
	}
	force_successful_syscall_return();
	return (long) jiffies_64_to_clock_t(get_jiffies_64());
}

/*
 * This needs some heavy checking ...
 * I just haven't the stomach for it. I also don't fully
 * understand sessions/pgrp etc. Let somebody who does explain it.
 *
 * OK, I think I have the protection semantics right.... this is really
 * only important on a multi-user system anyway, to make sure one user
 * can't send a signal to a process owned by another.  -TYT, 12/12/91
 *
 * !PF_FORKNOEXEC check to conform completely to POSIX.
 */
SYSCALL_DEFINE2(setpgid, pid_t, pid, pid_t, pgid)
{
	struct task_struct *p;
	struct task_struct *group_leader = current->group_leader;
	struct pid *pgrp;
	int err;

	if (!pid)
		pid = task_pid_vnr(group_leader);
	if (!pgid)
		pgid = pid;
	if (pgid < 0)
		return -EINVAL;
	rcu_read_lock();

	/* From this point forward we keep holding onto the tasklist lock
	 * so that our parent does not change from under us. -DaveM
	 */
	write_lock_irq(&tasklist_lock);

	err = -ESRCH;
	p = find_task_by_vpid(pid);
	if (!p)
		goto out;

	err = -EINVAL;
	if (!thread_group_leader(p))
		goto out;

	if (same_thread_group(p->real_parent, group_leader)) {
		err = -EPERM;
		if (task_session(p) != task_session(group_leader))
			goto out;
		err = -EACCES;
		if (!(p->flags & PF_FORKNOEXEC))
			goto out;
	} else {
		err = -ESRCH;
		if (p != group_leader)
			goto out;
	}

	err = -EPERM;
	if (p->signal->leader)
		goto out;

	pgrp = task_pid(p);
	if (pgid != pid) {
		struct task_struct *g;

		pgrp = find_vpid(pgid);
		g = pid_task(pgrp, PIDTYPE_PGID);
		if (!g || task_session(g) != task_session(group_leader))
			goto out;
	}

	err = security_task_setpgid(p, pgid);
	if (err)
		goto out;

	if (task_pgrp(p) != pgrp)
		change_pid(p, PIDTYPE_PGID, pgrp);

	err = 0;
out:
	/* All paths lead to here, thus we are safe. -DaveM */
	write_unlock_irq(&tasklist_lock);
	rcu_read_unlock();
	return err;
}

SYSCALL_DEFINE1(getpgid, pid_t, pid)
{
	struct task_struct *p;
	struct pid *grp;
	int retval;

	rcu_read_lock();
	if (!pid)
		grp = task_pgrp(current);
	else {
		retval = -ESRCH;
		p = find_task_by_vpid(pid);
		if (!p)
			goto out;
		grp = task_pgrp(p);
		if (!grp)
			goto out;

		retval = security_task_getpgid(p);
		if (retval)
			goto out;
	}
	retval = pid_vnr(grp);
out:
	rcu_read_unlock();
	return retval;
}

#ifdef __ARCH_WANT_SYS_GETPGRP

SYSCALL_DEFINE0(getpgrp)
{
	return sys_getpgid(0);
}

#endif

SYSCALL_DEFINE1(getsid, pid_t, pid)
{
	struct task_struct *p;
	struct pid *sid;
	int retval;

	rcu_read_lock();
	if (!pid)
		sid = task_session(current);
	else {
		retval = -ESRCH;
		p = find_task_by_vpid(pid);
		if (!p)
			goto out;
		sid = task_session(p);
		if (!sid)
			goto out;

		retval = security_task_getsid(p);
		if (retval)
			goto out;
	}
	retval = pid_vnr(sid);
out:
	rcu_read_unlock();
	return retval;
}

static void set_special_pids(struct pid *pid)
{
	struct task_struct *curr = current->group_leader;

	if (task_session(curr) != pid)
		change_pid(curr, PIDTYPE_SID, pid);

	if (task_pgrp(curr) != pid)
		change_pid(curr, PIDTYPE_PGID, pid);
}

SYSCALL_DEFINE0(setsid)
{
	struct task_struct *group_leader = current->group_leader;
	struct pid *sid = task_pid(group_leader);
	pid_t session = pid_vnr(sid);
	int err = -EPERM;

	write_lock_irq(&tasklist_lock);
	/* Fail if I am already a session leader */
	if (group_leader->signal->leader)
		goto out;

	/* Fail if a process group id already exists that equals the
	 * proposed session id.
	 */
	if (pid_task(sid, PIDTYPE_PGID))
		goto out;

	group_leader->signal->leader = 1;
	set_special_pids(sid);

	proc_clear_tty(group_leader);

	err = session;
out:
	write_unlock_irq(&tasklist_lock);
	if (err > 0) {
		proc_sid_connector(group_leader);
		sched_autogroup_create_attach(group_leader);
	}
	return err;
}

DECLARE_RWSEM(uts_sem);

#ifdef COMPAT_UTS_MACHINE
#define override_architecture(name) \
	(personality(current->personality) == PER_LINUX32 && \
	 copy_to_user(name->machine, COMPAT_UTS_MACHINE, \
		      sizeof(COMPAT_UTS_MACHINE)))
#else
#define override_architecture(name)	0
#endif

/*
 * Work around broken programs that cannot handle "Linux 3.0".
 * Instead we map 3.x to 2.6.40+x, so e.g. 3.0 would be 2.6.40
 * And we map 4.x to 2.6.60+x, so 4.0 would be 2.6.60.
 */
static int override_release(char __user *release, size_t len)
{
	int ret = 0;

	if (current->personality & UNAME26) {
		const char *rest = UTS_RELEASE;
		char buf[65] = { 0 };
		int ndots = 0;
		unsigned v;
		size_t copy;

		while (*rest) {
			if (*rest == '.' && ++ndots >= 3)
				break;
			if (!isdigit(*rest) && *rest != '.')
				break;
			rest++;
		}
		v = ((LINUX_VERSION_CODE >> 8) & 0xff) + 60;
		copy = clamp_t(size_t, len, 1, sizeof(buf));
		copy = scnprintf(buf, copy, "2.6.%u%s", v, rest);
		ret = copy_to_user(release, buf, copy + 1);
	}
	return ret;
}

SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
{
	int errno = 0;

	down_read(&uts_sem);
	if (copy_to_user(name, utsname(), sizeof *name))
		errno = -EFAULT;
	up_read(&uts_sem);

	if (!errno && override_release(name->release, sizeof(name->release)))
		errno = -EFAULT;
	if (!errno && override_architecture(name))
		errno = -EFAULT;
	return errno;
}

#ifdef __ARCH_WANT_SYS_OLD_UNAME
/*
 * Old cruft
 */
SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
{
	int error = 0;

	if (!name)
		return -EFAULT;

	down_read(&uts_sem);
	if (copy_to_user(name, utsname(), sizeof(*name)))
		error = -EFAULT;
	up_read(&uts_sem);

	if (!error && override_release(name->release, sizeof(name->release)))
		error = -EFAULT;
	if (!error && override_architecture(name))
		error = -EFAULT;
	return error;
}

SYSCALL_DEFINE1(olduname, struct oldold_utsname __user *, name)
{
	int error;

	if (!name)
		return -EFAULT;
	if (!access_ok(VERIFY_WRITE, name, sizeof(struct oldold_utsname)))
		return -EFAULT;

	down_read(&uts_sem);
	error = __copy_to_user(&name->sysname, &utsname()->sysname,
			       __OLD_UTS_LEN);
	error |= __put_user(0, name->sysname + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->nodename, &utsname()->nodename,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->nodename + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->release, &utsname()->release,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->release + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->version, &utsname()->version,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->version + __OLD_UTS_LEN);
	error |= __copy_to_user(&name->machine, &utsname()->machine,
				__OLD_UTS_LEN);
	error |= __put_user(0, name->machine + __OLD_UTS_LEN);
	up_read(&uts_sem);

	if (!error && override_architecture(name))
		error = -EFAULT;
	if (!error && override_release(name->release, sizeof(name->release)))
		error = -EFAULT;
	return error ? -EFAULT : 0;
}
#endif

SYSCALL_DEFINE2(sethostname, char __user *, name, int, len)
{
	int errno;
	char tmp[__NEW_UTS_LEN];

	if (!ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (len < 0 || len > __NEW_UTS_LEN)
		return -EINVAL;
	down_write(&uts_sem);
	errno = -EFAULT;
	if (!copy_from_user(tmp, name, len)) {
		struct new_utsname *u = utsname();

		memcpy(u->nodename, tmp, len);
		memset(u->nodename + len, 0, sizeof(u->nodename) - len);
		errno = 0;
		uts_proc_notify(UTS_PROC_HOSTNAME);
	}
	up_write(&uts_sem);
	return errno;
}

#ifdef __ARCH_WANT_SYS_GETHOSTNAME

SYSCALL_DEFINE2(gethostname, char __user *, name, int, len)
{
	int i, errno;
	struct new_utsname *u;

	if (len < 0)
		return -EINVAL;
	down_read(&uts_sem);
	u = utsname();
	i = 1 + strlen(u->nodename);
	if (i > len)
		i = len;
	errno = 0;
	if (copy_to_user(name, u->nodename, i))
		errno = -EFAULT;
	up_read(&uts_sem);
	return errno;
}

#endif

/*
 * Only setdomainname; getdomainname can be implemented by calling
 * uname()
 */
SYSCALL_DEFINE2(setdomainname, char __user *, name, int, len)
{
	int errno;
	char tmp[__NEW_UTS_LEN];

	if (!ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (len < 0 || len > __NEW_UTS_LEN)
		return -EINVAL;

	down_write(&uts_sem);
	errno = -EFAULT;
	if (!copy_from_user(tmp, name, len)) {
		struct new_utsname *u = utsname();

		memcpy(u->domainname, tmp, len);
		memset(u->domainname + len, 0, sizeof(u->domainname) - len);
		errno = 0;
		uts_proc_notify(UTS_PROC_DOMAINNAME);
	}
	up_write(&uts_sem);
	return errno;
}

SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit value;
	int ret;

	ret = do_prlimit(current, resource, NULL, &value);
	if (!ret)
		ret = copy_to_user(rlim, &value, sizeof(*rlim)) ? -EFAULT : 0;

	return ret;
}

#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT

/*
 *	Back compatibility for getrlimit. Needed for some apps.
 */
SYSCALL_DEFINE2(old_getrlimit, unsigned int, resource,
		struct rlimit __user *, rlim)
{
	struct rlimit x;
	if (resource >= RLIM_NLIMITS)
		return -EINVAL;

	task_lock(current->group_leader);
	x = current->signal->rlim[resource];
	task_unlock(current->group_leader);
	if (x.rlim_cur > 0x7FFFFFFF)
		x.rlim_cur = 0x7FFFFFFF;
	if (x.rlim_max > 0x7FFFFFFF)
		x.rlim_max = 0x7FFFFFFF;
	return copy_to_user(rlim, &x, sizeof(x)) ? -EFAULT : 0;
}

#endif

static inline bool rlim64_is_infinity(__u64 rlim64)
{
#if BITS_PER_LONG < 64
	return rlim64 >= ULONG_MAX;
#else
	return rlim64 == RLIM64_INFINITY;
#endif
}

static void rlim_to_rlim64(const struct rlimit *rlim, struct rlimit64 *rlim64)
{
	if (rlim->rlim_cur == RLIM_INFINITY)
		rlim64->rlim_cur = RLIM64_INFINITY;
	else
		rlim64->rlim_cur = rlim->rlim_cur;
	if (rlim->rlim_max == RLIM_INFINITY)
		rlim64->rlim_max = RLIM64_INFINITY;
	else
		rlim64->rlim_max = rlim->rlim_max;
}

static void rlim64_to_rlim(const struct rlimit64 *rlim64, struct rlimit *rlim)
{
	if (rlim64_is_infinity(rlim64->rlim_cur))
		rlim->rlim_cur = RLIM_INFINITY;
	else
		rlim->rlim_cur = (unsigned long)rlim64->rlim_cur;
	if (rlim64_is_infinity(rlim64->rlim_max))
		rlim->rlim_max = RLIM_INFINITY;
	else
		rlim->rlim_max = (unsigned long)rlim64->rlim_max;
}

/* make sure you are allowed to change @tsk limits before calling this */
int do_prlimit(struct task_struct *tsk, unsigned int resource,
		struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	struct rlimit *rlim;
	int retval = 0;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
	if (new_rlim) {
		if (new_rlim->rlim_cur > new_rlim->rlim_max)
			return -EINVAL;
		if (resource == RLIMIT_NOFILE &&
				new_rlim->rlim_max > sysctl_nr_open)
			return -EPERM;
	}

	/* protect tsk->signal and tsk->sighand from disappearing */
	read_lock(&tasklist_lock);
	if (!tsk->sighand) {
		retval = -ESRCH;
		goto out;
	}

	rlim = tsk->signal->rlim + resource;
	task_lock(tsk->group_leader);
	if (new_rlim) {
		/* Keep the capable check against init_user_ns until
		   cgroups can contain all limits */
		if (new_rlim->rlim_max > rlim->rlim_max &&
				!capable(CAP_SYS_RESOURCE))
			retval = -EPERM;
		if (!retval)
			retval = security_task_setrlimit(tsk->group_leader,
					resource, new_rlim);
		if (resource == RLIMIT_CPU && new_rlim->rlim_cur == 0) {
			/*
			 * The caller is asking for an immediate RLIMIT_CPU
			 * expiry.  But we use the zero value to mean "it was
			 * never set".  So let's cheat and make it one second
			 * instead
			 */
			new_rlim->rlim_cur = 1;
		}
	}
	if (!retval) {
		if (old_rlim)
			*old_rlim = *rlim;
		if (new_rlim)
			*rlim = *new_rlim;
	}
	task_unlock(tsk->group_leader);

	/*
	 * RLIMIT_CPU handling.   Note that the kernel fails to return an error
	 * code if it rejected the user's attempt to set RLIMIT_CPU.  This is a
	 * very long-standing error, and fixing it now risks breakage of
	 * applications, so we live with it
	 */
	 if (!retval && new_rlim && resource == RLIMIT_CPU &&
			 new_rlim->rlim_cur != RLIM_INFINITY)
		update_rlimit_cpu(tsk, new_rlim->rlim_cur);
out:
	read_unlock(&tasklist_lock);
	return retval;
}

/* rcu lock must be held */
static int check_prlimit_permission(struct task_struct *task)
{
	const struct cred *cred = current_cred(), *tcred;

	if (current == task)
		return 0;

	tcred = __task_cred(task);
	if (uid_eq(cred->uid, tcred->euid) &&
	    uid_eq(cred->uid, tcred->suid) &&
	    uid_eq(cred->uid, tcred->uid)  &&
	    gid_eq(cred->gid, tcred->egid) &&
	    gid_eq(cred->gid, tcred->sgid) &&
	    gid_eq(cred->gid, tcred->gid))
		return 0;
	if (ns_capable(tcred->user_ns, CAP_SYS_RESOURCE))
		return 0;

	return -EPERM;
}

SYSCALL_DEFINE4(prlimit64, pid_t, pid, unsigned int, resource,
		const struct rlimit64 __user *, new_rlim,
		struct rlimit64 __user *, old_rlim)
{
	struct rlimit64 old64, new64;
	struct rlimit old, new;
	struct task_struct *tsk;
	int ret;

	if (new_rlim) {
		if (copy_from_user(&new64, new_rlim, sizeof(new64)))
			return -EFAULT;
		rlim64_to_rlim(&new64, &new);
	}

	rcu_read_lock();
	tsk = pid ? find_task_by_vpid(pid) : current;
	if (!tsk) {
		rcu_read_unlock();
		return -ESRCH;
	}
	ret = check_prlimit_permission(tsk);
	if (ret) {
		rcu_read_unlock();
		return ret;
	}
	get_task_struct(tsk);
	rcu_read_unlock();

	ret = do_prlimit(tsk, resource, new_rlim ? &new : NULL,
			old_rlim ? &old : NULL);

	if (!ret && old_rlim) {
		rlim_to_rlim64(&old, &old64);
		if (copy_to_user(old_rlim, &old64, sizeof(old64)))
			ret = -EFAULT;
	}

	put_task_struct(tsk);
	return ret;
}

SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit new_rlim;

	if (copy_from_user(&new_rlim, rlim, sizeof(*rlim)))
		return -EFAULT;
	return do_prlimit(current, resource, &new_rlim, NULL);
}

/*
 * It would make sense to put struct rusage in the task_struct,
 * except that would make the task_struct be *really big*.  After
 * task_struct gets moved into malloc'ed memory, it would
 * make sense to do this.  It will make moving the rest of the information
 * a lot simpler!  (Which we're not doing right now because we're not
 * measuring them yet).
 *
 * When sampling multiple threads for RUSAGE_SELF, under SMP we might have
 * races with threads incrementing their own counters.  But since word
 * reads are atomic, we either get new values or old values and we don't
 * care which for the sums.  We always take the siglock to protect reading
 * the c* fields from p->signal from races with exit.c updating those
 * fields when reaping, so a sample either gets all the additions of a
 * given child after it's reaped, or none so this sample is before reaping.
 *
 * Locking:
 * We need to take the siglock for CHILDEREN, SELF and BOTH
 * for  the cases current multithreaded, non-current single threaded
 * non-current multithreaded.  Thread traversal is now safe with
 * the siglock held.
 * Strictly speaking, we donot need to take the siglock if we are current and
 * single threaded,  as no one else can take our signal_struct away, no one
 * else can  reap the  children to update signal->c* counters, and no one else
 * can race with the signal-> fields. If we do not take any lock, the
 * signal-> fields could be read out of order while another thread was just
 * exiting. So we should  place a read memory barrier when we avoid the lock.
 * On the writer side,  write memory barrier is implied in  __exit_signal
 * as __exit_signal releases  the siglock spinlock after updating the signal->
 * fields. But we don't do this yet to keep things simple.
 *
 */

static void accumulate_thread_rusage(struct task_struct *t, struct rusage *r)
{
	r->ru_nvcsw += t->nvcsw;
	r->ru_nivcsw += t->nivcsw;
	r->ru_minflt += t->min_flt;
	r->ru_majflt += t->maj_flt;
	r->ru_inblock += task_io_get_inblock(t);
	r->ru_oublock += task_io_get_oublock(t);
}

static void k_getrusage(struct task_struct *p, int who, struct rusage *r)
{
	struct task_struct *t;
	unsigned long flags;
	cputime_t tgutime, tgstime, utime, stime;
	unsigned long maxrss = 0;

	memset((char *)r, 0, sizeof (*r));
	utime = stime = 0;

	if (who == RUSAGE_THREAD) {
		task_cputime_adjusted(current, &utime, &stime);
		accumulate_thread_rusage(p, r);
		maxrss = p->signal->maxrss;
		goto out;
	}

	if (!lock_task_sighand(p, &flags))
		return;

	switch (who) {
	case RUSAGE_BOTH:
	case RUSAGE_CHILDREN:
		utime = p->signal->cutime;
		stime = p->signal->cstime;
		r->ru_nvcsw = p->signal->cnvcsw;
		r->ru_nivcsw = p->signal->cnivcsw;
		r->ru_minflt = p->signal->cmin_flt;
		r->ru_majflt = p->signal->cmaj_flt;
		r->ru_inblock = p->signal->cinblock;
		r->ru_oublock = p->signal->coublock;
		maxrss = p->signal->cmaxrss;

		if (who == RUSAGE_CHILDREN)
			break;

	case RUSAGE_SELF:
		thread_group_cputime_adjusted(p, &tgutime, &tgstime);
		utime += tgutime;
		stime += tgstime;
		r->ru_nvcsw += p->signal->nvcsw;
		r->ru_nivcsw += p->signal->nivcsw;
		r->ru_minflt += p->signal->min_flt;
		r->ru_majflt += p->signal->maj_flt;
		r->ru_inblock += p->signal->inblock;
		r->ru_oublock += p->signal->oublock;
		if (maxrss < p->signal->maxrss)
			maxrss = p->signal->maxrss;
		t = p;
		do {
			accumulate_thread_rusage(t, r);
		} while_each_thread(p, t);
		break;

	default:
		BUG();
	}
	unlock_task_sighand(p, &flags);

out:
	cputime_to_timeval(utime, &r->ru_utime);
	cputime_to_timeval(stime, &r->ru_stime);

	if (who != RUSAGE_CHILDREN) {
		struct mm_struct *mm = get_task_mm(p);

		if (mm) {
			setmax_mm_hiwater_rss(&maxrss, mm);
			mmput(mm);
		}
	}
	r->ru_maxrss = maxrss * (PAGE_SIZE / 1024); /* convert pages to KBs */
}

int getrusage(struct task_struct *p, int who, struct rusage __user *ru)
{
	struct rusage r;

	k_getrusage(p, who, &r);
	return copy_to_user(ru, &r, sizeof(r)) ? -EFAULT : 0;
}

SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru)
{
	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN &&
	    who != RUSAGE_THREAD)
		return -EINVAL;
	return getrusage(current, who, ru);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(getrusage, int, who, struct compat_rusage __user *, ru)
{
	struct rusage r;

	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN &&
	    who != RUSAGE_THREAD)
		return -EINVAL;

	k_getrusage(current, who, &r);
	return put_compat_rusage(&r, ru);
}
#endif

SYSCALL_DEFINE1(umask, int, mask)
{
	mask = xchg(&current->fs->umask, mask & S_IRWXUGO);
	return mask;
}

static int prctl_set_mm_exe_file(struct mm_struct *mm, unsigned int fd)
{
	struct fd exe;
	struct file *old_exe, *exe_file;
	struct inode *inode;
	int err;

	exe = fdget(fd);
	if (!exe.file)
		return -EBADF;

	inode = file_inode(exe.file);

	/*
	 * Because the original mm->exe_file points to executable file, make
	 * sure that this one is executable as well, to avoid breaking an
	 * overall picture.
	 */
	err = -EACCES;
	if (!S_ISREG(inode->i_mode) || path_noexec(&exe.file->f_path))
		goto exit;

	err = inode_permission(inode, MAY_EXEC);
	if (err)
		goto exit;

	/*
	 * Forbid mm->exe_file change if old file still mapped.
	 */
	exe_file = get_mm_exe_file(mm);
	err = -EBUSY;
	if (exe_file) {
		struct vm_area_struct *vma;

		down_read(&mm->mmap_sem);
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (!vma->vm_file)
				continue;
			if (path_equal(&vma->vm_file->f_path,
				       &exe_file->f_path))
				goto exit_err;
		}

		up_read(&mm->mmap_sem);
		fput(exe_file);
	}

	/*
	 * The symlink can be changed only once, just to disallow arbitrary
	 * transitions malicious software might bring in. This means one
	 * could make a snapshot over all processes running and monitor
	 * /proc/pid/exe changes to notice unusual activity if needed.
	 */
	err = -EPERM;
	if (test_and_set_bit(MMF_EXE_FILE_CHANGED, &mm->flags))
		goto exit;

	err = 0;
	/* set the new file, lockless */
	get_file(exe.file);
	old_exe = xchg(&mm->exe_file, exe.file);
	if (old_exe)
		fput(old_exe);
exit:
	fdput(exe);
	return err;
exit_err:
	up_read(&mm->mmap_sem);
	fput(exe_file);
	goto exit;
}

/*
 * WARNING: we don't require any capability here so be very careful
 * in what is allowed for modification from userspace.
 */
static int validate_prctl_map(struct prctl_mm_map *prctl_map)
{
	unsigned long mmap_max_addr = TASK_SIZE;
	struct mm_struct *mm = current->mm;
	int error = -EINVAL, i;

	static const unsigned char offsets[] = {
		offsetof(struct prctl_mm_map, start_code),
		offsetof(struct prctl_mm_map, end_code),
		offsetof(struct prctl_mm_map, start_data),
		offsetof(struct prctl_mm_map, end_data),
		offsetof(struct prctl_mm_map, start_brk),
		offsetof(struct prctl_mm_map, brk),
		offsetof(struct prctl_mm_map, start_stack),
		offsetof(struct prctl_mm_map, arg_start),
		offsetof(struct prctl_mm_map, arg_end),
		offsetof(struct prctl_mm_map, env_start),
		offsetof(struct prctl_mm_map, env_end),
	};

	/*
	 * Make sure the members are not somewhere outside
	 * of allowed address space.
	 */
	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		u64 val = *(u64 *)((char *)prctl_map + offsets[i]);

		if ((unsigned long)val >= mmap_max_addr ||
		    (unsigned long)val < mmap_min_addr)
			goto out;
	}

	/*
	 * Make sure the pairs are ordered.
	 */
#define __prctl_check_order(__m1, __op, __m2)				\
	((unsigned long)prctl_map->__m1 __op				\
	 (unsigned long)prctl_map->__m2) ? 0 : -EINVAL
	error  = __prctl_check_order(start_code, <, end_code);
	error |= __prctl_check_order(start_data, <, end_data);
	error |= __prctl_check_order(start_brk, <=, brk);
	error |= __prctl_check_order(arg_start, <=, arg_end);
	error |= __prctl_check_order(env_start, <=, env_end);
	if (error)
		goto out;
#undef __prctl_check_order

	error = -EINVAL;

	/*
	 * @brk should be after @end_data in traditional maps.
	 */
	if (prctl_map->start_brk <= prctl_map->end_data ||
	    prctl_map->brk <= prctl_map->end_data)
		goto out;

	/*
	 * Neither we should allow to override limits if they set.
	 */
	if (check_data_rlimit(rlimit(RLIMIT_DATA), prctl_map->brk,
			      prctl_map->start_brk, prctl_map->end_data,
			      prctl_map->start_data))
			goto out;

	/*
	 * Someone is trying to cheat the auxv vector.
	 */
	if (prctl_map->auxv_size) {
		if (!prctl_map->auxv || prctl_map->auxv_size > sizeof(mm->saved_auxv))
			goto out;
	}

	/*
	 * Finally, make sure the caller has the rights to
	 * change /proc/pid/exe link: only local root should
	 * be allowed to.
	 */
	if (prctl_map->exe_fd != (u32)-1) {
		struct user_namespace *ns = current_user_ns();
		const struct cred *cred = current_cred();

		if (!uid_eq(cred->uid, make_kuid(ns, 0)) ||
		    !gid_eq(cred->gid, make_kgid(ns, 0)))
			goto out;
	}

	error = 0;
out:
	return error;
}

#ifdef CONFIG_CHECKPOINT_RESTORE
static int prctl_set_mm_map(int opt, const void __user *addr, unsigned long data_size)
{
	struct prctl_mm_map prctl_map = { .exe_fd = (u32)-1, };
	unsigned long user_auxv[AT_VECTOR_SIZE];
	struct mm_struct *mm = current->mm;
	int error;

	BUILD_BUG_ON(sizeof(user_auxv) != sizeof(mm->saved_auxv));
	BUILD_BUG_ON(sizeof(struct prctl_mm_map) > 256);

	if (opt == PR_SET_MM_MAP_SIZE)
		return put_user((unsigned int)sizeof(prctl_map),
				(unsigned int __user *)addr);

	if (data_size != sizeof(prctl_map))
		return -EINVAL;

	if (copy_from_user(&prctl_map, addr, sizeof(prctl_map)))
		return -EFAULT;

	error = validate_prctl_map(&prctl_map);
	if (error)
		return error;

	if (prctl_map.auxv_size) {
		memset(user_auxv, 0, sizeof(user_auxv));
		if (copy_from_user(user_auxv,
				   (const void __user *)prctl_map.auxv,
				   prctl_map.auxv_size))
			return -EFAULT;

		/* Last entry must be AT_NULL as specification requires */
		user_auxv[AT_VECTOR_SIZE - 2] = AT_NULL;
		user_auxv[AT_VECTOR_SIZE - 1] = AT_NULL;
	}

	if (prctl_map.exe_fd != (u32)-1) {
		error = prctl_set_mm_exe_file(mm, prctl_map.exe_fd);
		if (error)
			return error;
	}

	down_write(&mm->mmap_sem);

	/*
	 * We don't validate if these members are pointing to
	 * real present VMAs because application may have correspond
	 * VMAs already unmapped and kernel uses these members for statistics
	 * output in procfs mostly, except
	 *
	 *  - @start_brk/@brk which are used in do_brk but kernel lookups
	 *    for VMAs when updating these memvers so anything wrong written
	 *    here cause kernel to swear at userspace program but won't lead
	 *    to any problem in kernel itself
	 */

	mm->start_code	= prctl_map.start_code;
	mm->end_code	= prctl_map.end_code;
	mm->start_data	= prctl_map.start_data;
	mm->end_data	= prctl_map.end_data;
	mm->start_brk	= prctl_map.start_brk;
	mm->brk		= prctl_map.brk;
	mm->start_stack	= prctl_map.start_stack;
	mm->arg_start	= prctl_map.arg_start;
	mm->arg_end	= prctl_map.arg_end;
	mm->env_start	= prctl_map.env_start;
	mm->env_end	= prctl_map.env_end;

	/*
	 * Note this update of @saved_auxv is lockless thus
	 * if someone reads this member in procfs while we're
	 * updating -- it may get partly updated results. It's
	 * known and acceptable trade off: we leave it as is to
	 * not introduce additional locks here making the kernel
	 * more complex.
	 */
	if (prctl_map.auxv_size)
		memcpy(mm->saved_auxv, user_auxv, sizeof(user_auxv));

	up_write(&mm->mmap_sem);
	return 0;
}
#endif /* CONFIG_CHECKPOINT_RESTORE */

static int prctl_set_auxv(struct mm_struct *mm, unsigned long addr,
			  unsigned long len)
{
	/*
	 * This doesn't move the auxiliary vector itself since it's pinned to
	 * mm_struct, but it permits filling the vector with new values.  It's
	 * up to the caller to provide sane values here, otherwise userspace
	 * tools which use this vector might be unhappy.
	 */
	unsigned long user_auxv[AT_VECTOR_SIZE];

	if (len > sizeof(user_auxv))
		return -EINVAL;

	if (copy_from_user(user_auxv, (const void __user *)addr, len))
		return -EFAULT;

	/* Make sure the last entry is always AT_NULL */
	user_auxv[AT_VECTOR_SIZE - 2] = 0;
	user_auxv[AT_VECTOR_SIZE - 1] = 0;

	BUILD_BUG_ON(sizeof(user_auxv) != sizeof(mm->saved_auxv));

	task_lock(current);
	memcpy(mm->saved_auxv, user_auxv, len);
	task_unlock(current);

	return 0;
}

static int prctl_set_mm(int opt, unsigned long addr,
			unsigned long arg4, unsigned long arg5)
{
	struct mm_struct *mm = current->mm;
	struct prctl_mm_map prctl_map;
	struct vm_area_struct *vma;
	int error;

	if (arg5 || (arg4 && (opt != PR_SET_MM_AUXV &&
			      opt != PR_SET_MM_MAP &&
			      opt != PR_SET_MM_MAP_SIZE)))
		return -EINVAL;

#ifdef CONFIG_CHECKPOINT_RESTORE
	if (opt == PR_SET_MM_MAP || opt == PR_SET_MM_MAP_SIZE)
		return prctl_set_mm_map(opt, (const void __user *)addr, arg4);
#endif

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;

	if (opt == PR_SET_MM_EXE_FILE)
		return prctl_set_mm_exe_file(mm, (unsigned int)addr);

	if (opt == PR_SET_MM_AUXV)
		return prctl_set_auxv(mm, addr, arg4);

	if (addr >= TASK_SIZE || addr < mmap_min_addr)
		return -EINVAL;

	error = -EINVAL;

	down_write(&mm->mmap_sem);
	vma = find_vma(mm, addr);

	prctl_map.start_code	= mm->start_code;
	prctl_map.end_code	= mm->end_code;
	prctl_map.start_data	= mm->start_data;
	prctl_map.end_data	= mm->end_data;
	prctl_map.start_brk	= mm->start_brk;
	prctl_map.brk		= mm->brk;
	prctl_map.start_stack	= mm->start_stack;
	prctl_map.arg_start	= mm->arg_start;
	prctl_map.arg_end	= mm->arg_end;
	prctl_map.env_start	= mm->env_start;
	prctl_map.env_end	= mm->env_end;
	prctl_map.auxv		= NULL;
	prctl_map.auxv_size	= 0;
	prctl_map.exe_fd	= -1;

	switch (opt) {
	case PR_SET_MM_START_CODE:
		prctl_map.start_code = addr;
		break;
	case PR_SET_MM_END_CODE:
		prctl_map.end_code = addr;
		break;
	case PR_SET_MM_START_DATA:
		prctl_map.start_data = addr;
		break;
	case PR_SET_MM_END_DATA:
		prctl_map.end_data = addr;
		break;
	case PR_SET_MM_START_STACK:
		prctl_map.start_stack = addr;
		break;
	case PR_SET_MM_START_BRK:
		prctl_map.start_brk = addr;
		break;
	case PR_SET_MM_BRK:
		prctl_map.brk = addr;
		break;
	case PR_SET_MM_ARG_START:
		prctl_map.arg_start = addr;
		break;
	case PR_SET_MM_ARG_END:
		prctl_map.arg_end = addr;
		break;
	case PR_SET_MM_ENV_START:
		prctl_map.env_start = addr;
		break;
	case PR_SET_MM_ENV_END:
		prctl_map.env_end = addr;
		break;
	default:
		goto out;
	}

	error = validate_prctl_map(&prctl_map);
	if (error)
		goto out;

	switch (opt) {
	/*
	 * If command line arguments and environment
	 * are placed somewhere else on stack, we can
	 * set them up here, ARG_START/END to setup
	 * command line argumets and ENV_START/END
	 * for environment.
	 */
	case PR_SET_MM_START_STACK:
	case PR_SET_MM_ARG_START:
	case PR_SET_MM_ARG_END:
	case PR_SET_MM_ENV_START:
	case PR_SET_MM_ENV_END:
		if (!vma) {
			error = -EFAULT;
			goto out;
		}
	}

	mm->start_code	= prctl_map.start_code;
	mm->end_code	= prctl_map.end_code;
	mm->start_data	= prctl_map.start_data;
	mm->end_data	= prctl_map.end_data;
	mm->start_brk	= prctl_map.start_brk;
	mm->brk		= prctl_map.brk;
	mm->start_stack	= prctl_map.start_stack;
	mm->arg_start	= prctl_map.arg_start;
	mm->arg_end	= prctl_map.arg_end;
	mm->env_start	= prctl_map.env_start;
	mm->env_end	= prctl_map.env_end;

	error = 0;
out:
	up_write(&mm->mmap_sem);
	return error;
}

#ifdef CONFIG_CHECKPOINT_RESTORE
static int prctl_get_tid_address(struct task_struct *me, int __user **tid_addr)
{
	return put_user(me->clear_child_tid, tid_addr);
}
#else
static int prctl_get_tid_address(struct task_struct *me, int __user **tid_addr)
{
	return -EINVAL;
}
#endif

SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)
{
	struct task_struct *me = current;
	unsigned char comm[sizeof(me->comm)];
	long error;

	error = security_task_prctl(option, arg2, arg3, arg4, arg5);
	if (error != -ENOSYS)
		return error;

	error = 0;
	switch (option) {
	case PR_SET_PDEATHSIG:
		if (!valid_signal(arg2)) {
			error = -EINVAL;
			break;
		}
		me->pdeath_signal = arg2;
		break;
	case PR_GET_PDEATHSIG:
		error = put_user(me->pdeath_signal, (int __user *)arg2);
		break;
	case PR_GET_DUMPABLE:
		error = get_dumpable(me->mm);
		break;
	case PR_SET_DUMPABLE:
		if (arg2 != SUID_DUMP_DISABLE && arg2 != SUID_DUMP_USER) {
			error = -EINVAL;
			break;
		}
		set_dumpable(me->mm, arg2);
		break;

	case PR_SET_UNALIGN:
		error = SET_UNALIGN_CTL(me, arg2);
		break;
	case PR_GET_UNALIGN:
		error = GET_UNALIGN_CTL(me, arg2);
		break;
	case PR_SET_FPEMU:
		error = SET_FPEMU_CTL(me, arg2);
		break;
	case PR_GET_FPEMU:
		error = GET_FPEMU_CTL(me, arg2);
		break;
	case PR_SET_FPEXC:
		error = SET_FPEXC_CTL(me, arg2);
		break;
	case PR_GET_FPEXC:
		error = GET_FPEXC_CTL(me, arg2);
		break;
	case PR_GET_TIMING:
		error = PR_TIMING_STATISTICAL;
		break;
	case PR_SET_TIMING:
		if (arg2 != PR_TIMING_STATISTICAL)
			error = -EINVAL;
		break;
	case PR_SET_NAME:
		comm[sizeof(me->comm) - 1] = 0;
		if (strncpy_from_user(comm, (char __user *)arg2,
				      sizeof(me->comm) - 1) < 0)
			return -EFAULT;
		set_task_comm(me, comm);
		proc_comm_connector(me);
		break;
	case PR_GET_NAME:
		get_task_comm(comm, me);
		if (copy_to_user((char __user *)arg2, comm, sizeof(comm)))
			return -EFAULT;
		break;
	case PR_GET_ENDIAN:
		error = GET_ENDIAN(me, arg2);
		break;
	case PR_SET_ENDIAN:
		error = SET_ENDIAN(me, arg2);
		break;
	case PR_GET_SECCOMP:
		error = prctl_get_seccomp();
		break;
	case PR_SET_SECCOMP:
		error = prctl_set_seccomp(arg2, (char __user *)arg3);
		break;
	case PR_GET_TSC:
		error = GET_TSC_CTL(arg2);
		break;
	case PR_SET_TSC:
		error = SET_TSC_CTL(arg2);
		break;
	case PR_TASK_PERF_EVENTS_DISABLE:
		error = perf_event_task_disable();
		break;
	case PR_TASK_PERF_EVENTS_ENABLE:
		error = perf_event_task_enable();
		break;
	case PR_GET_TIMERSLACK:
		if (current->timer_slack_ns > ULONG_MAX)
			error = ULONG_MAX;
		else
			error = current->timer_slack_ns;
		break;
	case PR_SET_TIMERSLACK:
		if (arg2 <= 0)
			current->timer_slack_ns =
					current->default_timer_slack_ns;
		else
			current->timer_slack_ns = arg2;
		break;
	case PR_MCE_KILL:
		if (arg4 | arg5)
			return -EINVAL;
		switch (arg2) {
		case PR_MCE_KILL_CLEAR:
			if (arg3 != 0)
				return -EINVAL;
			current->flags &= ~PF_MCE_PROCESS;
			break;
		case PR_MCE_KILL_SET:
			current->flags |= PF_MCE_PROCESS;
			if (arg3 == PR_MCE_KILL_EARLY)
				current->flags |= PF_MCE_EARLY;
			else if (arg3 == PR_MCE_KILL_LATE)
				current->flags &= ~PF_MCE_EARLY;
			else if (arg3 == PR_MCE_KILL_DEFAULT)
				current->flags &=
						~(PF_MCE_EARLY|PF_MCE_PROCESS);
			else
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
		break;
	case PR_MCE_KILL_GET:
		if (arg2 | arg3 | arg4 | arg5)
			return -EINVAL;
		if (current->flags & PF_MCE_PROCESS)
			error = (current->flags & PF_MCE_EARLY) ?
				PR_MCE_KILL_EARLY : PR_MCE_KILL_LATE;
		else
			error = PR_MCE_KILL_DEFAULT;
		break;
	case PR_SET_MM:
		error = prctl_set_mm(arg2, arg3, arg4, arg5);
		break;
	case PR_GET_TID_ADDRESS:
		error = prctl_get_tid_address(me, (int __user **)arg2);
		break;
	case PR_SET_CHILD_SUBREAPER:
		me->signal->is_child_subreaper = !!arg2;
		break;
	case PR_GET_CHILD_SUBREAPER:
		error = put_user(me->signal->is_child_subreaper,
				 (int __user *)arg2);
		break;
	case PR_SET_NO_NEW_PRIVS:
		if (arg2 != 1 || arg3 || arg4 || arg5)
			return -EINVAL;

		task_set_no_new_privs(current);
		break;
	case PR_GET_NO_NEW_PRIVS:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		return task_no_new_privs(current) ? 1 : 0;
	case PR_GET_THP_DISABLE:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		error = !!(me->mm->def_flags & VM_NOHUGEPAGE);
		break;
	case PR_SET_THP_DISABLE:
		if (arg3 || arg4 || arg5)
			return -EINVAL;
		if (down_write_killable(&me->mm->mmap_sem))
			return -EINTR;
		if (arg2)
			me->mm->def_flags |= VM_NOHUGEPAGE;
		else
			me->mm->def_flags &= ~VM_NOHUGEPAGE;
		up_write(&me->mm->mmap_sem);
		break;
	case PR_MPX_ENABLE_MANAGEMENT:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		error = MPX_ENABLE_MANAGEMENT();
		break;
	case PR_MPX_DISABLE_MANAGEMENT:
		if (arg2 || arg3 || arg4 || arg5)
			return -EINVAL;
		error = MPX_DISABLE_MANAGEMENT();
		break;
	case PR_SET_FP_MODE:
		error = SET_FP_MODE(me, arg2);
		break;
	case PR_GET_FP_MODE:
		error = GET_FP_MODE(me);
		break;
	default:
		error = -EINVAL;
		break;
	}
	return error;
}

SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
		struct getcpu_cache __user *, unused)
{
	int err = 0;
	int cpu = raw_smp_processor_id();

	if (cpup)
		err |= put_user(cpu, cpup);
	if (nodep)
		err |= put_user(cpu_to_node(cpu), nodep);
	return err ? -EFAULT : 0;
}

/**
 * do_sysinfo - fill in sysinfo struct
 * @info: pointer to buffer to fill
 */
static int do_sysinfo(struct sysinfo *info)
{
	unsigned long mem_total, sav_total;
	unsigned int mem_unit, bitcount;
	struct timespec tp;

	memset(info, 0, sizeof(struct sysinfo));

	get_monotonic_boottime(&tp);
	info->uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

	get_avenrun(info->loads, 0, SI_LOAD_SHIFT - FSHIFT);

	info->procs = nr_threads;

	si_meminfo(info);
	si_swapinfo(info);

	/*
	 * If the sum of all the available memory (i.e. ram + swap)
	 * is less than can be stored in a 32 bit unsigned long then
	 * we can be binary compatible with 2.2.x kernels.  If not,
	 * well, in that case 2.2.x was broken anyways...
	 *
	 *  -Erik Andersen <andersee@debian.org>
	 */

	mem_total = info->totalram + info->totalswap;
	if (mem_total < info->totalram || mem_total < info->totalswap)
		goto out;
	bitcount = 0;
	mem_unit = info->mem_unit;
	while (mem_unit > 1) {
		bitcount++;
		mem_unit >>= 1;
		sav_total = mem_total;
		mem_total <<= 1;
		if (mem_total < sav_total)
			goto out;
	}

	/*
	 * If mem_total did not overflow, multiply all memory values by
	 * info->mem_unit and set it to 1.  This leaves things compatible
	 * with 2.2.x, and also retains compatibility with earlier 2.4.x
	 * kernels...
	 */

	info->mem_unit = 1;
	info->totalram <<= bitcount;
	info->freeram <<= bitcount;
	info->sharedram <<= bitcount;
	info->bufferram <<= bitcount;
	info->totalswap <<= bitcount;
	info->freeswap <<= bitcount;
	info->totalhigh <<= bitcount;
	info->freehigh <<= bitcount;

out:
	return 0;
}

SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
{
	struct sysinfo val;

	do_sysinfo(&val);

	if (copy_to_user(info, &val, sizeof(struct sysinfo)))
		return -EFAULT;

	return 0;
}

#ifdef CONFIG_COMPAT
struct compat_sysinfo {
	s32 uptime;
	u32 loads[3];
	u32 totalram;
	u32 freeram;
	u32 sharedram;
	u32 bufferram;
	u32 totalswap;
	u32 freeswap;
	u16 procs;
	u16 pad;
	u32 totalhigh;
	u32 freehigh;
	u32 mem_unit;
	char _f[20-2*sizeof(u32)-sizeof(int)];
};

COMPAT_SYSCALL_DEFINE1(sysinfo, struct compat_sysinfo __user *, info)
{
	struct sysinfo s;

	do_sysinfo(&s);

	/* Check to see if any memory value is too large for 32-bit and scale
	 *  down if needed
	 */
	if (upper_32_bits(s.totalram) || upper_32_bits(s.totalswap)) {
		int bitcount = 0;

		while (s.mem_unit < PAGE_SIZE) {
			s.mem_unit <<= 1;
			bitcount++;
		}

		s.totalram >>= bitcount;
		s.freeram >>= bitcount;
		s.sharedram >>= bitcount;
		s.bufferram >>= bitcount;
		s.totalswap >>= bitcount;
		s.freeswap >>= bitcount;
		s.totalhigh >>= bitcount;
		s.freehigh >>= bitcount;
	}

	if (!access_ok(VERIFY_WRITE, info, sizeof(struct compat_sysinfo)) ||
	    __put_user(s.uptime, &info->uptime) ||
	    __put_user(s.loads[0], &info->loads[0]) ||
	    __put_user(s.loads[1], &info->loads[1]) ||
	    __put_user(s.loads[2], &info->loads[2]) ||
	    __put_user(s.totalram, &info->totalram) ||
	    __put_user(s.freeram, &info->freeram) ||
	    __put_user(s.sharedram, &info->sharedram) ||
	    __put_user(s.bufferram, &info->bufferram) ||
	    __put_user(s.totalswap, &info->totalswap) ||
	    __put_user(s.freeswap, &info->freeswap) ||
	    __put_user(s.procs, &info->procs) ||
	    __put_user(s.totalhigh, &info->totalhigh) ||
	    __put_user(s.freehigh, &info->freehigh) ||
	    __put_user(s.mem_unit, &info->mem_unit))
		return -EFAULT;

	return 0;
}

void exitingSyscall(unsigned long long id) {
	unsigned long long elr;
	unsigned int spsr;

	if (id != 172 && id != 291) return;

	asm volatile(
		"mrs %0, elr_el1"
		: "=r" (elr)
		:
		: "memory");
	asm volatile(
		"mrs %0, SPSR_EL1"
		: "=r" (spsr)
		:
		: "memory");
	myprintk("Exiting elr(0x%llX) SPSR_EL1(0x%X) id(%lld)\n", elr, spsr, id);
}

/*
 * Those *_findNonPTPblocks_*() functions must be called after findPagetables().
 * For precaution, I placed them at the bottom of the file.
 */
static void tableWalk_kernel_findNonPTPBlocks(int bAddToLive) {
	_tableWalk(0 /*bVerbose*/, (unsigned long long) swapper_pg_dir, 0 /*findingPageAddr*/, 1 /*bTraceBlock*/, bAddToLive, 0 /*bUseMyprintk*/);
}

static void tableWalk_kernel_findNonPTPBlocks_verbose(int bAddToLive) {	// a test function
	_tableWalk(1 /*bVerbose*/, (unsigned long long) swapper_pg_dir, 0 /*findingPageAddr*/, 1 /*bTraceBlock*/, bAddToLive, 0 /*bUseMyprintk*/);
}

/*
 * WARNING: This must be invoked after findPagetables() is called because 
 *			1) it compares pages/blocks with those in blocksForPTP,
 *			2) findPagetables() initializes normal list
 *
 * This must conduct two pass:
 *		1. It identifies all blocks not in the PTP block list and adds them to the Normal block list.
 *		   This doesn't mean the blocks are only for Normal data. That's why we need the second pass.
 *		2. It checks if there is any pagetable belonging to the Normal block list.
 */
void findNormalBlocks(int bVerbose, int bUseMyprintk, int bAddToLive) {
	// WARNING: Make sure that you've called findPagetables()
	tableWalk_kernel_findNonPTPBlocks(1);// <--- TODO: after debugging, change it to bAddToLive
}

#endif /* CONFIG_COMPAT */
