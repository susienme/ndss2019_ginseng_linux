/*
 * This is a wrapper or hook function to add actions before or after the SMC call
 * TODO: I will remove the wrapper when debugging is done
 */
#include <linux/arm-smccc.h>
#include <asm/string.h>
#include <linux/ftrace.h>

#ifndef ERR_ADDR
#define ERR_ADDR	0x0000FFFFB7FCCC00ULL
#endif

void ginseng_smc(unsigned long smc_cmd, unsigned long a1,
			unsigned long a2, unsigned long a3, unsigned long a4,
			unsigned long a5) {
	__ginseng_smc(smc_cmd, a1, a2, a3, a4, a5);
}
EXPORT_SYMBOL(ginseng_smc);