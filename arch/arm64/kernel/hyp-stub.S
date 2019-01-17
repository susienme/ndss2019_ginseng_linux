/*
 * Hypervisor stub
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author:	Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/irqchip/arm-gic-v3.h>

#include <asm/assembler.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/ptrace.h>
#include <asm/virt.h>

#define INST_MSR_TTBR0_EL1_X0		0xD5182000
#define EL1_IRQ_HANDLER 			0xFFFF000008083480
#define HONG_SPSR 		0x60000145

.section .rodata.hyp, "aS"
str_hyp_newl:
	.asciz "\n"
str_hyp_invalid_el2_sync_invalid:
	.asciz " el2_sync_invalid\n"
str_hyp_invalid_el2_irq_invalid:
	.asciz " el2_irq_invalid\n"
str_hyp_invalid_el2_fiq_invalid:
	.asciz " el2_fiq_invalid\n"
str_hyp_invalid_el2_error_invalid_h:
	.asciz " el2_error_invalid_h\n"
str_hyp_invalid_el1_sync_invalid:
	.asciz " el1_sync_invalid\n"
str_hyp_invalid_el1_irq_invalid:
	.asciz " el1_irq_invalid\n"
str_hyp_invalid_el1_fiq_invalid:
	.asciz " el1_fiq_invalid\n"
str_hyp_invalid_el1_error_invalid:
	.asciz " el1_error_invalid\n"
str_hyp_invalid_el2_sync_invalid_t:
	.asciz " el2_sync_invalid_t\n"
str_hyp_invalid_el2_sync_invalid_h:
	.asciz " el2_sync_invalid_h\n"
str_hyp_invalid_el2_error_invalid_t:
	.asciz " el2_error_invalid_t\n"

.globl ymh_magic
	.text
	.align 11

my_el1_irq:
	adrp	x4, str_hyp_invalid_el1_irq_invalid
	add	x4, x4, #:lo12:str_hyp_invalid_el1_irq_invalid
	bl asm_print_str
2:
	b   2b

	smc #7
	eret

ENTRY(__hyp_stub_vectors)
	ventry	el2_sync_invalid_t		// Synchronous EL2t
	ventry	el2_irq_invalid			// IRQ EL2t
	ventry	el2_fiq_invalid			// FIQ EL2t
	ventry	el2_error_invalid_t		// Error EL2t

	ventry	el2_sync_invalid_h		// Synchronous EL2h
	ventry	el2_irq_invalid			// IRQ EL2h
	ventry	el2_fiq_invalid			// FIQ EL2h
	ventry	el2_error_invalid_h		// Error EL2h

	ventry	el1_sync			// Synchronous 64-bit EL1
	ventry  my_el1_irq // ventry	el1_irq_invalid			// IRQ 64-bit EL1
	ventry	el1_fiq_invalid			// FIQ 64-bit EL1
	ventry	el1_error_invalid		// Error 64-bit EL1

	ventry	el1_sync_invalid		// Synchronous 32-bit EL1
	ventry	el1_irq_invalid			// IRQ 32-bit EL1
	ventry	el1_fiq_invalid			// FIQ 32-bit EL1
	ventry	el1_error_invalid		// Error 32-bit EL1
ENDPROC(__hyp_stub_vectors)

	.align 11


el1_sync:
	smc #8
	eret

5:
	b 5b	

	mrs x4, elr_el2 		// ELR_EL2: 	0xffff00000809bab8
	ubfx x4, x4, #0, #24 	// VA -> PA
	ldr w4, [x4]

	ldr w5, =INST_MSR_TTBR0_EL1_X0
	cmp w4, w5
	//b.ne 5f
	b.ne 77f

	msr ttbr0_el1, x0
	// Don't need to trap read (MRS) instructions

	mrs x4, elr_el2
	add x4, x4, #4
	msr elr_el2, x4

	eret


77:
	bl asm_print_hex // unhandled inst

	mrs x4, esr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, spsr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

88:
	b 88b

	mrs	x30, esr_el2
	lsr	x30, x30, #ESR_ELx_EC_SHIFT

	cmp	x30, #ESR_ELx_EC_HVC64
	b.ne	9f				// Not an HVC trap

	cmp	x0, #HVC_GET_VECTORS
	b.ne	1f
	mrs	x0, vbar_el2
	b	9f

1:	cmp	x0, #HVC_SET_VECTORS
	b.ne	2f
	msr	vbar_el2, x1
	b	9f

2:	cmp	x0, #HVC_SOFT_RESTART
	b.ne	3f
	mov	x0, x2
	mov	x2, x4
	mov	x4, x1
	mov	x1, x3
	br	x4				// no return

	/* Someone called kvm_call_hyp() against the hyp-stub... */
3:	mov	x0, #ARM_EXCEPTION_HYP_GONE

9:	
	eret
ENDPROC(el1_sync)

.macro invalid_vector	label
\label:
	adrp	x4, str_hyp_invalid_\label
	add	x4, x4, #:lo12:str_hyp_invalid_\label
	bl asm_print_str

	mrs x4, elr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, spsr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, far_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, esr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	smc #7

	eret // <-- unreachable...
	b \label
ENDPROC(\label)
.endm

	invalid_vector	el2_irq_invalid
	invalid_vector	el2_fiq_invalid
	invalid_vector	el1_sync_invalid
	invalid_vector	el1_irq_invalid
	invalid_vector	el1_fiq_invalid
	invalid_vector	el1_error_invalid

el2_sync_invalid_t:
	adrp	x4, str_hyp_invalid_el2_sync_invalid_t
	add	x4, x4, #:lo12:str_hyp_invalid_el2_sync_invalid_t
	bl asm_print_str
	b el2_sync_invalid_t

el2_error_invalid_t:
	adrp	x4, str_hyp_invalid_el2_error_invalid_t
	add	x4, x4, #:lo12:str_hyp_invalid_el2_error_invalid_t
	bl asm_print_str

	mrs x4, esr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, spsr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, far_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

2:
	b 2b


el2_error_invalid_h:
	smc #11
	eret

	mrs x0, mpidr_el1
	and x1, x0, #0xFF
	and x0, x0, #0xFF00
	add x4, x1, x0, LSR #6		// CPU ID
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	adrp	x4, str_hyp_invalid_el2_error_invalid_h
	add	x4, x4, #:lo12:str_hyp_invalid_el2_error_invalid_h
	bl asm_print_str

	mrs x4, esr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, spsr_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

	mrs x4, far_el2
	bl asm_print_hex
	adrp	x4, str_hyp_newl
	add	x4, x4, #:lo12:str_hyp_newl
	bl asm_print_str

2:
	b 2b


el2_sync_invalid_h:
	adrp	x4, str_hyp_invalid_el2_sync_invalid_h
	add	x4, x4, #:lo12:str_hyp_invalid_el2_sync_invalid_h
	bl asm_print_str

	smc #9
	eret
	

	mrs x4, esr_el2
	bl asm_print_hex
79:
	b 79b	
	b el2_sync_invalid_h

/*
 * __hyp_set_vectors: Call this after boot to set the initial hypervisor
 * vectors as part of hypervisor installation.  On an SMP system, this should
 * be called on each CPU.
 *
 * x0 must be the physical address of the new vector table, and must be
 * 2KB aligned.
 *
 * Before calling this, you must check that the stub hypervisor is installed
 * everywhere, by waiting for any secondary CPUs to be brought up and then
 * checking that is_hyp_mode_available() is true.
 *
 * If not, there is a pre-existing hypervisor, some CPUs failed to boot, or
 * something else went wrong... in such cases, trying to install a new
 * hypervisor is unlikely to work as desired.
 *
 * When you call into your shiny new hypervisor, sp_el2 will contain junk,
 * so you will need to set that to something sensible at the new hypervisor's
 * initialisation entry point.
 */

ENTRY(__hyp_get_vectors)
	str	lr, [sp, #-16]!
	mov	x0, #HVC_GET_VECTORS
	hvc	#0
	ldr	lr, [sp], #16
	ret
ENDPROC(__hyp_get_vectors)

ENTRY(__hyp_set_vectors)
	str	lr, [sp, #-16]!
	mov	x1, x0
	mov	x0, #HVC_SET_VECTORS
	hvc	#0
	ldr	lr, [sp], #16
	ret
ENDPROC(__hyp_set_vectors)
