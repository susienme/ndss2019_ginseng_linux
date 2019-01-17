#include <linux/string.h>
#include <linux/arm-smccc.h>
#include <linux/ginseng_smc_cmd.h>
#include <linux/ginseng.h>
#include <linux/printk.h>
#include <asm/memory.h>

#define WAYS			16
#define WAYS_SHIFT		28
#define SETS 			256
#define SETS_SHIFT		6
#define LEVELS			2
#define LEVELS_SHIFT	1

extern int ginseng_copyPageMode;
extern int checkAP(unsigned long long addr);

#ifdef YMH_QEMU
#define QEMU_WAY			16
#define QEMU_WAY_SHIFT		28
#define QEMU_SET 			2048
#define QEMU_SET_SHIFT		6
#define QEMU_LEVEL_SHIFT	1
#endif	// YMH_QEMU

void copy_page(void *dest, void *src) {
	int ap_src, ap_dest;//, rtn;

	ap_src = checkAP((unsigned long long) src);
	ap_dest = checkAP((unsigned long long) dest);

	if (ap_dest >= 2) {
		myprintk("YES, we have to copy in EL3 ap_src(%d) ap_dest(%d)\n", ap_src, ap_dest);
		ginseng_copyPageMode = GINSENG_TEST_COPY_PAGE_CP_IN_EL3_CMP_IN_EL1;
	}
	
	switch(ginseng_copyPageMode) {
	case GINSENG_COPY_PAGE_IN_EL3:
	case GINSENG_TEST_COPY_PAGE_CP_IN_EL3_CMP_IN_EL1:
#ifdef YMH_QEMU_NEVER_RUN
		ci_all_qemu();
#else
		asm volatile (
			"mov x9, #64\n"			// x9 is the counter
			"mov x10, %[a1_va]\n"	// x10 is the dest addr
			"mov x11, %[a2_va]\n"	// x11 is the src addr
			
		"1:\n" // LOOP_START
			"dc ivac, x10\n" 	// dest
			"dc cvac, x11\n" 	// src
			"sub x9, x9, #1\n"
			"cbz x9, 99f\n"
			"add x10, x10, #64\n"
			"add x11, x11, #64\n"
			"b 1b\n"

		"99:\n" //exit
			"dmb sy\n"
			"isb sy"
			:
			: [a2_va] "r" (src) , [a1_va] "r" (dest)
			: "x9", "x10", "x11"
			);
#endif	// else of YMH_QEMU
		ginseng_smc(GINSENG_SMC_CMD_COPY_PAGE, (unsigned long long) dest, (unsigned long long) src, 4096, 0, 0);

		if (memcmp(dest, src, 4096)) {
				myprintk("MEMCMP FAILED!!!\n");
			memcpy(dest, src, 4096);
		} //else myprintk("SUCESS copying in EL3!!!\n");


		break;

	case GINSENG_TEST_COPY_PAGE_CP_IN_EL1_CMP_IN_EL3:	// memcpy in EL1 / cmp in EL3
		memcpy(dest, src, 4096);

		asm volatile (
			"mov x9, #64\n"			// x9 is the counter
			"mov x10, %[a1_va]\n"	// x10 is the dest addr
			"mov x11, %[a2_va]\n"	// x11 is the src addr
			
		"1:\n" // LOOP_START
			"dc cvac, x10\n"
			"dc cvac, x11\n"
			"sub x9, x9, #1\n"
			"cbz x9, 99f\n"
			"add x10, x10, #64\n"
			"add x11, x11, #64\n"
			"b 1b\n"

		"99:\n" //exit
			"isb sy"
			:
			: [a1_va] "r" (dest), [a2_va] "r" (src)
			: "x9", "x10", "x11"
			);

		ginseng_smc(GINSENG_SMC_CMD_COPY_PAGE_TEST, (unsigned long long) dest, (unsigned long long) src, 4096, 0, 0);
		break;

	default:
		memcpy(dest, src, 4096);
	}
}