/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm-generic/export.h>

	.macro SMCCC instr
	.cfi_startproc
	\instr	#0
	ldr	x4, [sp]
	stp	x0, x1, [x4, #ARM_SMCCC_RES_X0_OFFS]
	stp	x2, x3, [x4, #ARM_SMCCC_RES_X2_OFFS]
	ret
	.cfi_endproc
	.endm

/*
 * void arm_smccc_smc(unsigned long a0, unsigned long a1, unsigned long a2,
 *		  unsigned long a3, unsigned long a4, unsigned long a5,
 *		  unsigned long a6, unsigned long a7, struct arm_smccc_res *res)
 */
ENTRY(arm_smccc_smc)
	SMCCC	smc
ENDPROC(arm_smccc_smc)

	.macro YMH_SMCCC instr
	.cfi_startproc
	\instr	#18
	ldr	x4, [sp]
	stp	x0, x1, [x4, #ARM_SMCCC_RES_X0_OFFS]
	stp	x2, x3, [x4, #ARM_SMCCC_RES_X2_OFFS]
	ret
	.cfi_endproc
	.endm

ENTRY(ymh_arm_smccc_smc)
	YMH_SMCCC	smc
ENDPROC(ymh_arm_smccc_smc)

ENTRY(__ginseng_smc)
	// DC invalidate when x5 is not NULL
	// x5 will be used to hold the return value from SW.
	cbz x5, 1f
	dc ivac, x5
1:
	dmb sy
	isb sy
	smc #0x798
	ret
ENDPROC(__ginseng_smc)
EXPORT_SYMBOL(__ginseng_smc)


ENTRY(__ginseng_smc_forEL2)
	dmb sy
	isb sy
	smc #0x700
	ret
ENDPROC(__ginseng_smc_forEL2)
EXPORT_SYMBOL(__ginseng_smc_forEL2)

/*
 * void arm_smccc_hvc(unsigned long a0, unsigned long a1, unsigned long a2,
 *		  unsigned long a3, unsigned long a4, unsigned long a5,
 *		  unsigned long a6, unsigned long a7, struct arm_smccc_res *res)
 */
ENTRY(arm_smccc_hvc)
	SMCCC	hvc
ENDPROC(arm_smccc_hvc)
