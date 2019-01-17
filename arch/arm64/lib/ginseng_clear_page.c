#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ginseng.h>
#include <linux/arm-smccc.h>
#include <linux/ginseng_smc_cmd.h>

extern int ginseng_clearPageMode;
extern int checkAP(unsigned long long addr);


void clear_page(void *dest) {
	int i;
	int ap_dest;
	void *tmp_dest;

	ap_dest = checkAP((unsigned long long) dest);
	if (ap_dest >= 2) {
		ginseng_clearPageMode = GINSENG_TEST_CLEAR_PAGE_CLR_IN_EL3_CHECK_IN_EL1;
		myprintk("YES, we have to clear in EL3 ap_dest(%d)\n", ap_dest);
	}

	switch(ginseng_clearPageMode) {
	case GINSENG_TEST_CLEAR_PAGE_TRACE:
		ginseng_clearPageMode = 0;
		dump_stack();
		memset(dest, 0, 4096);
		break;

	case GINSENG_TEST_CLEAR_PAGE_CLR_IN_EL1_CHECK_IN_EL3:
		memset(dest, 0, 4096);

		asm volatile (
			"mov x9, #64\n"			// x9 is the counter
			"mov x10, %[dest]\n"	// x10 is the dest addr
			
		"1:\n" // LOOP_START
			"dc ivac, x10\n"
			"sub x9, x9, #1\n"
			"cbz x9, 99f\n"
			"add x10, x10, #64\n"
			"b 1b\n"

		"99:\n" //exit
			"dmb sy\n"
			"isb sy"
			:
			: [dest] "r" (dest)
			: "x9", "x10"
			);

		ginseng_smc(GINSENG_SMC_CMD_CLEAR_PAGE_TEST_CLEAR_IN_EL1_CHECK_IN_EL3, (unsigned long long) dest, 0, 0, 0, 0);
		break;

	case GINSENG_SMC_CMD_CLEAR_PAGE:
	case GINSENG_TEST_CLEAR_PAGE_CLR_IN_EL3_CHECK_IN_EL1:
		// dest -> invalidate
		asm volatile (
			"mov x9, #64\n"			// x9 is the counter
			"mov x10, %[dest]\n"	// x10 is the dest addr
			
		"1:\n" // LOOP_START
			"dc ivac, x10\n" 	// dest
			"sub x9, x9, #1\n"
			"cbz x9, 99f\n"
			"add x10, x10, #64\n"
			"b 1b\n"

		"99:\n" //exit
			"dmb sy\n"
			"isb sy"
			:
			: [dest] "r" (dest)
			: "x9", "x10"
			);

		ginseng_smc(GINSENG_SMC_CMD_CLEAR_PAGE, (unsigned long long) dest, 0, 0, 0, 0);

		tmp_dest = dest;
		for(i = 0; i < 64; i++) {
			if ( *((unsigned long long *) tmp_dest) ) {
				myprintk("CLEAR_PAGE WRONG i(%d) *tmp_dest(0x%llX)\n", i, *((unsigned long long *) tmp_dest));
				// break;
			}
			tmp_dest = (void *) (((unsigned long long *) tmp_dest) + 1);
		}
		if (i != 64) {
			panic("CLEAR_PAGE WRONG!!\n");
		} //else myprintk("CLEAR_PAGE SUCCESS\n");
		break;

	default:
		memset(dest, 0, 4096);
	}
}