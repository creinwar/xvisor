/**
 * Copyright (c) 2012 Anup Patel.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * @file cpu_defines.h
 * @author Anup Patel (anup@brainfault.org)
 * @brief common macros & defines for shared by all C & Assembly code
 */
#ifndef __CPU_DEFINES_H__
#define __CPU_DEFINES_H__

/* Maximum allowed VTLB entries */
#define CPU_VCPU_VTLB_LINE_MASK				0x00000000
#define CPU_VCPU_VTLB_LINE_SHIFT			0
#define CPU_VCPU_VTLB_LINE_COUNT			1
#define CPU_VCPU_VTLB_LINE_ENTRY_COUNT			128
#define CPU_VCPU_VTLB_ENTRY_COUNT			128

/* Coprocessor related macros & defines */
#define CPU_COPROC_COUNT				16

/* GPR related macros & defines */
#define CPU_GPR_COUNT 					13
#define CPU_FIQ_GPR_COUNT 				5

/* Interrupt or Exception related macros & defines */
#define CPU_IRQ_NR					8
#define CPU_IRQ_LOWVEC_BASE				0x00000000
#define CPU_IRQ_HIGHVEC_BASE				0xFFFF0000
#define CPU_RESET_IRQ					0
#define CPU_UNDEF_INST_IRQ				1
#define CPU_SOFT_IRQ					2
#define CPU_PREFETCH_ABORT_IRQ				3
#define CPU_DATA_ABORT_IRQ				4
#define CPU_HYP_TRAP_IRQ				5
#define CPU_EXTERNAL_IRQ				6
#define CPU_EXTERNAL_FIQ				7

/* CPSR related macros & defines */
#define CPSR_MODE_MASK					0x0000001f
#define CPSR_MODE_USER					0x00000010
#define CPSR_MODE_FIQ					0x00000011
#define CPSR_MODE_IRQ					0x00000012
#define CPSR_MODE_SUPERVISOR				0x00000013
#define CPSR_MODE_MONITOR				0x00000016
#define CPSR_MODE_ABORT					0x00000017
#define CPSR_MODE_HYPERVISOR				0x0000001a
#define CPSR_MODE_UNDEFINED				0x0000001b
#define CPSR_MODE_SYSTEM				0x0000001f
#define CPSR_THUMB_ENABLED				(1 << 5)
#define CPSR_FIQ_DISABLED				(1 << 6)
#define CPSR_IRQ_DISABLED				(1 << 7)
#define CPSR_ASYNC_ABORT_DISABLED			(1 << 8)
#define CPSR_BE_ENABLED					(1 << 9)
#define CPSR_IT2_MASK					0x0000FC00
#define CPSR_IT2_SHIFT					10
#define CPSR_GE_MASK					0x000F0000
#define CPSR_GE_SHIFT					16
#define CPSR_JAZZLE_ENABLED				(1 << 24)
#define CPSR_IT1_MASK					0x06000000
#define CPSR_IT1_SHIFT					25
#define CPSR_CUMMULATE_MASK				(1 << 27)
#define CPSR_CUMMULATE_SHIFT				27
#define CPSR_OVERFLOW_MASK				(1 << 28)
#define CPSR_OVERFLOW_SHIFT				28
#define CPSR_CARRY_MASK					(1 << 29)
#define CPSR_CARRY_SHIFT				29
#define CPSR_ZERO_MASK					(1 << 30)
#define CPSR_ZERO_SHIFT					30
#define CPSR_NEGATIVE_MASK				(1 << 31)
#define CPSR_NEGATIVE_SHIFT				31

#define CPSR_NZCV_MASK					(CPSR_NEGATIVE_MASK |\
							CPSR_ZERO_MASK |\
							CPSR_CARRY_MASK |\
							CPSR_OVERFLOW_MASK)
#define CPSR_IT_MASK					(CPSR_IT2_MASK |\
							CPSR_IT1_MASK)
#define CPSR_USERBITS_MASK				(CPSR_NZCV_MASK |\
							CPSR_CUMMULATE_MASK |\
							CPSR_GE_MASK |\
							CPSR_IT_MASK |\
							CPSR_THUMB_ENABLED)
#define CPSR_PRIVBITS_MASK				(~CPSR_USERBITS_MASK)
#define CPSR_ALLBITS_MASK				0xFFFFFFFF

/* SCTLR related macros & defines */
#define SCTLR_TE_MASK					0x40000000
#define SCTLR_AFE_MASK					0x20000000
#define SCTLR_TRE_MASK					0x10000000
#define SCTLR_NFI_MASK					0x08000000
#define SCTLR_EE_MASK					0x02000000
#define SCTLR_VE_MASK					0x01000000
#define SCTLR_U_MASK					0x00400000
#define SCTLR_FI_MASK					0x00200000
#define SCTLR_HA_MASK					0x00020000
#define SCTLR_RR_MASK					0x00004000
#define SCTLR_V_MASK					0x00002000
#define SCTLR_I_MASK					0x00001000
#define SCTLR_Z_MASK					0x00000800
#define SCTLR_SW_MASK					0x00000400
#define SCTLR_B_MASK					0x00000080
#define SCTLR_C_MASK					0x00000004
#define SCTLR_A_MASK					0x00000002
#define SCTLR_M_MASK					0x00000001

/* CTR related macros & defines */
#define CTR_FORMAT_MASK					0xE0000000
#define CTR_FORMAT_SHIFT				29
#define CTR_FORMAT_V6					0x0
#define CTR_FORMAT_V7					0x4
#define CTR_CWG_MASK					0x0F000000
#define CTR_CWG_SHIFT					24
#define CTR_ERG_MASK					0x00F00000
#define CTR_ERG_SHIFT					20
#define CTR_DMINLINE_MASK				0x000F0000
#define CTR_DMINLINE_SHIFT				20
#define CTR_L1IP_MASK					0x0000C000
#define CTR_L1IP_SHIFT					14
#define CTR_IMINLINE_MASK				0x0000000F
#define CTR_IMINLINE_SHIFT				0
#define CTR_V6_CTYPE_MASK				0x1E000000
#define CTR_V6_CTYPE_SHIFT				25
#define CTR_V6_S_MASK					0x01000000
#define CTR_V6_S_SHIFT					24
#define CTR_V6_DSIZE_MASK				0x00FFF000
#define CTR_V6_DSIZE_SHIFT				12
#define CTR_V6_ISIZE_MASK				0x00000FFF
#define CTR_V6_ISIZE_SHIFT				0

/* CLIDR related macros & defines */
#define CLIDR_LOUU_MASK					0x38000000
#define CLIDR_LOUU_SHIFT				27
#define CLIDR_LOC_MASK					0x07000000
#define CLIDR_LOC_SHIFT					24
#define CLIDR_LOUIS_MASK				0x00E00000
#define CLIDR_LOUIS_SHIFT				21
#define CLIDR_CTYPE7_MASK				0x001C0000
#define CLIDR_CTYPE7_SHIFT				18
#define CLIDR_CTYPE6_MASK				0x00038000
#define CLIDR_CTYPE6_SHIFT				15
#define CLIDR_CTYPE5_MASK				0x00007000
#define CLIDR_CTYPE5_SHIFT				12
#define CLIDR_CTYPE4_MASK				0x00000E00
#define CLIDR_CTYPE4_SHIFT				9
#define CLIDR_CTYPE3_MASK				0x000001C0
#define CLIDR_CTYPE3_SHIFT				6
#define CLIDR_CTYPE2_MASK				0x00000038
#define CLIDR_CTYPE2_SHIFT				3
#define CLIDR_CTYPE1_MASK				0x00000007
#define CLIDR_CTYPE1_SHIFT				0
#define CLIDR_CTYPE_NOCACHE				0x0
#define CLIDR_CTYPE_ICACHE				0x1
#define CLIDR_CTYPE_DCACHE				0x2
#define CLIDR_CTYPE_SPLITCACHE				0x3
#define CLIDR_CTYPE_UNICACHE				0x4
#define CLIDR_CTYPE_RESERVED1				0x5
#define CLIDR_CTYPE_RESERVED2				0x6
#define CLIDR_CTYPE_RESERVED3				0x7

/* CSSELR related macros & defines */
#define CSSELR_LEVEL_MASK				0x0000000E
#define CSSELR_LEVEL_SHIFT				1
#define CSSELR_IND_MASK					0x00000001
#define CSSELR_IND_SHIFT				0

/* CSSIDR related macros & defines */
#define CCSIDR_WT_MASK					0x80000000
#define CCSIDR_WT_SHIFT					31
#define CCSIDR_WB_MASK					0x40000000
#define CCSIDR_WB_SHIFT					30
#define CCSIDR_RA_MASK					0x20000000
#define CCSIDR_RA_SHIFT					29
#define CCSIDR_WA_MASK					0x10000000
#define CCSIDR_WA_SHIFT					28
#define CCSIDR_NUMSETS_MASK				0x0FFFE000
#define CCSIDR_NUMSETS_SHIFT				13
#define CCSIDR_ASSOC_MASK				0x00001FF8
#define CCSIDR_ASSOC_SHIFT				3
#define CCSIDR_LINESZ_MASK				0x00000007
#define CCSIDR_LINESZ_SHIFT				0

/* HCR */
#define HCR_INITVAL					0x00000000
#define HCR_TGE_MASK					0x08000000
#define HCR_TGE_SHIFT					27
#define HCR_TVM_MASK					0x04000000
#define HCR_TVM_SHIFT					26
#define HCR_TTLB_MASK					0x02000000
#define HCR_TTLB_SHIFT					25
#define HCR_TPU_MASK					0x01000000
#define HCR_TPU_SHIFT					24
#define HCR_TPC_MASK					0x00800000
#define HCR_TPC_SHIFT					23
#define HCR_TSW_MASK					0x00400000
#define HCR_TSW_SHIFT					22
#define HCR_TAC_MASK					0x00200000
#define HCR_TAC_SHIFT					21
#define HCR_TIDCP_MASK					0x00100000
#define HCR_TIDCP_SHIFT					20
#define HCR_TSC_MASK					0x00080000
#define HCR_TSC_SHIFT					19
#define HCR_TID3_MASK					0x00040000
#define HCR_TID3_SHIFT					18
#define HCR_TID2_MASK					0x00020000
#define HCR_TID2_SHIFT					17
#define HCR_TID1_MASK					0x00010000
#define HCR_TID1_SHIFT					16
#define HCR_TID0_MASK					0x00008000
#define HCR_TID0_SHIFT					15
#define HCR_TWE_MASK					0x00004000
#define HCR_TWE_SHIFT					14
#define HCR_TWI_MASK					0x00002000
#define HCR_TWI_SHIFT					13
#define HCR_DC_MASK					0x00001000
#define HCR_DC_SHIFT					12
#define HCR_BSU_MASK					0x00000C00
#define HCR_BSU_SHIFT					10
#define HCR_FB_MASK					0x00000200
#define HCR_FB_SHIFT					9
#define HCR_VA_MASK					0x00000100
#define HCR_VA_SHIFT					8
#define HCR_VI_MASK					0x00000080
#define HCR_VI_SHIFT					7
#define HCR_VF_MASK					0x00000040
#define HCR_VF_SHIFT					6
#define HCR_AMO_MASK					0x00000020
#define HCR_AMO_SHIFT					5
#define HCR_IMO_MASK					0x00000010
#define HCR_IMO_SHIFT					4
#define HCR_FMO_MASK					0x00000008
#define HCR_FMO_SHIFT					3
#define HCR_PTW_MASK					0x00000004
#define HCR_PTW_SHIFT					2
#define HCR_SWIO_MASK					0x00000002
#define HCR_SWIO_SHIFT					1
#define HCR_VM_MASK					0x00000001
#define HCR_VM_SHIFT					0

/* HCPTR */
#define HCPTR_INITVAL					0x00000000
#define HCPTR_TCPAC_MASK				0x80000000
#define HCPTR_TCPAC_SHIFT				31
#define HCPTR_TTA_MASK					0x00100000
#define HCPTR_TTA_SHIFT					20
#define HCPTR_TASE_MASK					0x00008000
#define HCPTR_TASE_SHIFT				15
#define HCPTR_TCP_MASK					0x00003FFF
#define HCPTR_TCP_SHIFT					0
#define HCPTR_TCP13_MASK				0x00002000
#define HCPTR_TCP13_SHIFT				13
#define HCPTR_TCP12_MASK				0x00001000
#define HCPTR_TCP12_SHIFT				12
#define HCPTR_TCP11_MASK				0x00000800
#define HCPTR_TCP11_SHIFT				11
#define HCPTR_TCP10_MASK				0x00000400
#define HCPTR_TCP10_SHIFT				10
#define HCPTR_TCP9_MASK					0x00000200
#define HCPTR_TCP9_SHIFT				9
#define HCPTR_TCP8_MASK					0x00000100
#define HCPTR_TCP8_SHIFT				8
#define HCPTR_TCP7_MASK					0x00000080
#define HCPTR_TCP7_SHIFT				7
#define HCPTR_TCP6_MASK					0x00000040
#define HCPTR_TCP6_SHIFT				6
#define HCPTR_TCP5_MASK					0x00000020
#define HCPTR_TCP5_SHIFT				5
#define HCPTR_TCP4_MASK					0x00000010
#define HCPTR_TCP4_SHIFT				4
#define HCPTR_TCP3_MASK					0x00000008
#define HCPTR_TCP3_SHIFT				3
#define HCPTR_TCP2_MASK					0x00000004
#define HCPTR_TCP2_SHIFT				2
#define HCPTR_TCP1_MASK					0x00000002
#define HCPTR_TCP1_SHIFT				1
#define HCPTR_TCP0_MASK					0x00000001
#define HCPTR_TCP0_SHIFT				0

/* HSTR */
#define HSTR_INITVAL					0x00000000
#define HSTR_TJDBX_MASK					0x00020000
#define HSTR_TJDBX_SHIFT				17
#define HSTR_TTEE_MASK					0x00010000
#define HSTR_TTEE_SHIFT					16
#define HSTR_T_MASK					0x0000BFEF
#define HSTR_T_SHIFT					0
#define HSTR_T15_MASK					0x00008000
#define HSTR_T15_SHIFT					15
#define HSTR_T13_MASK					0x00002000
#define HSTR_T13_SHIFT					13
#define HSTR_T12_MASK					0x00001000
#define HSTR_T12_SHIFT					12
#define HSTR_T11_MASK					0x00000800
#define HSTR_T11_SHIFT					11
#define HSTR_T10_MASK					0x00000400
#define HSTR_T10_SHIFT					10
#define HSTR_T9_MASK					0x00000200
#define HSTR_T9_SHIFT					9
#define HSTR_T8_MASK					0x00000100
#define HSTR_T8_SHIFT					8
#define HSTR_T7_MASK					0x00000080
#define HSTR_T7_SHIFT					7
#define HSTR_T6_MASK					0x00000040
#define HSTR_T6_SHIFT					6
#define HSTR_T5_MASK					0x00000020
#define HSTR_T5_SHIFT					5
#define HSTR_T3_MASK					0x00000008
#define HSTR_T3_SHIFT					3
#define HSTR_T2_MASK					0x00000004
#define HSTR_T2_SHIFT					2
#define HSTR_T1_MASK					0x00000002
#define HSTR_T1_SHIFT					1
#define HSTR_T0_MASK					0x00000001
#define HSTR_T0_SHIFT					0

/* HPFAR */
#define HPFAR_INITVAL					0x00000000
#define HPFAR_FIPA_MASK					0xFFFFFFF0
#define HPFAR_FIPA_SHIFT				4
#define HPFAR_FIPA_PAGE_MASK				0x00000FFF
#define HPFAR_FIPA_PAGE_SHIFT				12

/* HSR */
#define HSR_INITVAL					0x00000000
#define HSR_EC_MASK					0xFC000000
#define HSR_EC_SHIFT					26
#define HSR_IL_MASK					0x02000000
#define HSR_IL_SHIFT					25
#define HSR_ISS_MASK					0x01FFFFFF
#define HSR_ISS_SHIFT					0

/* Exception Class (EC) Values */
#define EC_UNKNOWN					0x00
#define EC_TRAP_WFI_WFE					0x01
#define EC_TRAP_MCR_MRC_CP15				0x03
#define EC_TRAP_MCRR_MRRC_CP15				0x04
#define EC_TRAP_MCR_MRC_CP14				0x05
#define EC_TRAP_LDC_STC_CP14				0x06
#define EC_TRAP_CP0_TO_CP13				0x07
#define EC_TRAP_VMRS					0x08
#define EC_TRAP_JAZELLE					0x09
#define EC_TRAP_BXJ					0x0A
#define EC_TRAP_MRRC_CP14				0x0C
#define EC_TRAP_SVC					0x11
#define EC_TRAP_HVC					0x12
#define EC_TRAP_SMC					0x13
#define EC_TRAP_STAGE2_INST_ABORT			0x20
#define EC_TRAP_STAGE1_INST_ABORT			0x21
#define EC_TRAP_STAGE2_DATA_ABORT			0x24
#define EC_TRAP_STAGE1_DATA_ABORT			0x25

/* Condition Field ISS Encodings */
#define ISS_CV_MASK					0x01000000
#define ISS_CV_SHIFT					24
#define ISS_COND_MASK					0x00F00000
#define ISS_COND_SHIFT					20

/* WFI/WFE ISS Encodings */
#define ISS_WFI_WFE_TRAPPED_MASK			0x00080000
#define ISS_WFI_WFE_TRAPPED_SHIFT			19

/* MCR/MRC ISS Encodings */
#define ISS_MCR_MRC_OPC2_MASK				0x000E0000
#define ISS_MCR_MRC_OPC2_SHIFT				17
#define ISS_MCR_MRC_OPC1_MASK				0x0001C000
#define ISS_MCR_MRC_OPC1_SHIFT				14
#define ISS_MCR_MRC_CRN_MASK				0x00003C00
#define ISS_MCR_MRC_CRN_SHIFT				10
#define ISS_MCR_MRC_RT_MASK				0x000001E0
#define ISS_MCR_MRC_RT_SHIFT				5
#define ISS_MCR_MRC_CRM_MASK				0x0000001E
#define ISS_MCR_MRC_CRM_SHIFT				1
#define ISS_MCR_MRC_DIR_MASK				0x00000001
#define ISS_MCR_MRC_DIR_SHIFT				0

/* Instruction/Data Abort ISS Encodings */
#define ISS_ABORT_ISV_MASK				0x01000000
#define ISS_ABORT_ISV_SHIFT				24
#define ISS_ABORT_SAS_MASK				0x00C00000
#define ISS_ABORT_SAS_SHIFT				22
#define ISS_ABORT_SSE_MASK				0x00200000
#define ISS_ABORT_SSE_SHIFT				21
#define ISS_ABORT_SRT_MASK				0x000F0000
#define ISS_ABORT_SRT_SHIFT				16
#define ISS_ABORT_EA_MASK				0x00000200
#define ISS_ABORT_EA_SHIFT				9
#define ISS_ABORT_CM_MASK				0x00000100
#define ISS_ABORT_CM_SHIFT				8
#define ISS_ABORT_S1PTW_MASK				0x00000080
#define ISS_ABORT_S1PTW_SHIFT				7
#define ISS_ABORT_WNR_MASK				0x00000040
#define ISS_ABORT_WNR_SHIFT				6
#define ISS_ABORT_FSR_MASK				0x0000003F
#define ISS_ABORT_FSR_SHIFT				0

/* Fault Status (FSR) Encodings */
#define FSR_TRANS_FAULT_LEVEL0				0x04
#define FSR_TRANS_FAULT_LEVEL1				0x05
#define FSR_TRANS_FAULT_LEVEL2				0x06
#define FSR_TRANS_FAULT_LEVEL3				0x07
#define FSR_ACCESS_FAULT_LEVEL0				0x08
#define FSR_ACCESS_FAULT_LEVEL1				0x09
#define FSR_ACCESS_FAULT_LEVEL2				0x0A
#define FSR_ACCESS_FAULT_LEVEL3				0x0B
#define FSR_PERM_FAULT_LEVEL0				0x0C
#define FSR_PERM_FAULT_LEVEL1				0x0D
#define FSR_PERM_FAULT_LEVEL2				0x0E
#define FSR_PERM_FAULT_LEVEL3				0x0F
#define FSR_SYNC_EXTERNAL_ABORT				0x10
#define FSR_ASYNC_EXTERNAL_ABORT			0x11
#define FSR_SYNC_TWALK_EXTERNAL_ABORT_LEVEL0		0x14
#define FSR_SYNC_TWALK_EXTERNAL_ABORT_LEVEL1		0x15
#define FSR_SYNC_TWALK_EXTERNAL_ABORT_LEVEL2		0x16
#define FSR_SYNC_TWALK_EXTERNAL_ABORT_LEVEL3		0x17
#define FSR_SYNC_PARITY_ERROR				0x18
#define FSR_ASYNC_PARITY_ERROR				0x19
#define FSR_SYNC_TWALK_PARITY_ERROR_LEVEL0		0x1C
#define FSR_SYNC_TWALK_PARITY_ERROR_LEVEL1		0x1D
#define FSR_SYNC_TWALK_PARITY_ERROR_LEVEL2		0x1E
#define FSR_SYNC_TWALK_PARITY_ERROR_LEVEL3		0x1F
#define FSR_ALIGN_FAULT					0x21
#define FSR_DEBUG_EVENT					0x22
#define FSR_TLB_CONFLICT_ABORT				0x30
#define FSR_DOMAIN_FAULT_LEVEL0				0x3C
#define FSR_DOMAIN_FAULT_LEVEL1				0x3D
#define FSR_DOMAIN_FAULT_LEVEL2				0x3E
#define FSR_DOMAIN_FAULT_LEVEL3				0x3F

/* HTTBR */
#define HTTBR_INITVAL					0x0000000000000000ULL
#define HTTBR_BADDR_MASK				0x000000FFFFFFF000ULL
#define HTTBR_BADDR_SHIFT				12

/* HTCR */
#define HTCR_INITVAL					0x80800000
#define HTCR_IMP_MASK					0x40000000
#define HTCR_IMP_SHIFT					30
#define HTCR_SH0_MASK					0x00003000
#define HTCR_SH0_SHIFT					12
#define HTCR_ORGN0_MASK					0x00000C00
#define HTCR_ORGN0_SHIFT				10
#define HTCR_IRGN0_MASK					0x00000300
#define HTCR_IRGN0_SHIFT				8
#define HTCR_T0SZ_MASK					0x00000003
#define HTCR_T0SZ_SHIFT					0

/* VTTBR */
#define VTTBR_INITVAL					0x0000000000000000ULL
#define VTTBR_VMID_MASK					0x00FF000000000000ULL
#define VTTBR_VMID_SHIFT				48
#define VTTBR_BADDR_MASK				0x000000FFFFFFF000ULL
#define VTTBR_BADDR_SHIFT				12

/* VTCR */
#define VTCR_INITVAL					0x80000000
#define VTCR_SH0_MASK					0x00003000
#define VTCR_SH0_SHIFT					12
#define VTCR_ORGN0_MASK					0x00000C00
#define VTCR_ORGN0_SHIFT				10
#define VTCR_IRGN0_MASK					0x00000300
#define VTCR_IRGN0_SHIFT				8
#define VTCR_SL0_MASK					0x000000C0
#define VTCR_SL0_SHIFT					6
#define VTCR_S_MASK					0x00000010
#define VTCR_S_SHIFT					4
#define VTCR_T0SZ_MASK					0x00000003
#define VTCR_T0SZ_SHIFT					0

/* TTBL Generic */
#define TTBL_INITIAL_TABLE_COUNT			8
#define TTBL_TABLE_SIZE					0x00001000
#define TTBL_TABLE_SIZE_SHIFT				12
#define TTBL_TABLE_ENTCNT				512
#define TTBL_TABLE_ENTSZ				8
#define TTBL_STAGE1					1
#define TTBL_STAGE2					2
#define TTBL_FIRST_LEVEL				1
#define TTBL_LEVEL1					1
#define TTBL_LEVEL2					2
#define TTBL_LEVEL3					3
#define TTBL_LAST_LEVEL					3
/* L1 index Bit[39:30] */
#define TTBL_L1_INDEX_MASK				0x000000FFC0000000ULL
#define TTBL_L1_INDEX_SHIFT				30
#define TTBL_L1_BLOCK_SIZE				0x0000000040000000ULL
#define TTBL_L1_MAP_MASK				(~(TTBL_L1_BLOCK_SIZE - 1))
/* L2 index Bit[29:21] */
#define TTBL_L2_INDEX_MASK				0x000000003FE00000ULL
#define TTBL_L2_INDEX_SHIFT				21
#define TTBL_L2_BLOCK_SIZE				0x0000000000200000ULL
#define TTBL_L2_MAP_MASK				(~(TTBL_L2_BLOCK_SIZE - 1))
/* L3 index Bit[20:12] */
#define TTBL_L3_INDEX_MASK				0x00000000001FF000ULL
#define TTBL_L3_INDEX_SHIFT				12
#define TTBL_L3_BLOCK_SIZE				0x0000000000001000ULL
#define TTBL_L3_MAP_MASK				(~(TTBL_L3_BLOCK_SIZE - 1))
#define TTBL_UPPER_MASK					0xFFF0000000000000ULL
#define TTBL_UPPER_SHIFT				52
#define TTBL_OUTADDR_MASK				0x000000FFFFFFF000ULL
#define TTBL_OUTADDR_SHIFT				12
#define TTBL_AP_SRW_U					0x0
#define TTBL_AP_S_URW					0x1
#define TTBL_AP_SR_U					0x2
#define TTBL_AP_S_UR					0x3
#define TTBL_HAP_NOACCESS				0x0
#define TTBL_HAP_READONLY				0x1
#define TTBL_HAP_WRITEONLY				0x2
#define TTBL_HAP_READWRITE				0x3
#define TTBL_LOWER_MASK					0x0000000000000FFCULL
#define TTBL_LOWER_SHIFT				2
#define TTBL_TABLE_MASK					0x0000000000000002ULL
#define TTBL_TABLE_SHIFT				1
#define TTBL_VALID_MASK					0x0000000000000001ULL
#define TTBL_VALID_SHIFT				0

/* TTBL Stage1 Table Attributes */
#define TTBL_STAGE1_TABLE_NS_MASK			0x8000000000000000ULL
#define TTBL_STAGE1_TABLE_NS_SHIFT			63
#define TTBL_STAGE1_TABLE_AP_MASK			0x6000000000000000ULL
#define TTBL_STAGE1_TABLE_AP_SHIFT			61
#define TTBL_STAGE1_TABLE_XN_MASK			0x1000000000000000ULL
#define TTBL_STAGE1_TABLE_XN_SHIFT			60
#define TTBL_STAGE1_TABLE_PXN_MASK			0x0800000000000000ULL
#define TTBL_STAGE1_TABLE_PXN_SHIFT			59

/* TTBL Stage1 Block Upper Attributes */
#define TTBL_STAGE1_UPPER_XN_MASK			0x0040000000000000ULL
#define TTBL_STAGE1_UPPER_XN_SHIFT			54
#define TTBL_STAGE1_UPPER_PXN_MASK			0x0020000000000000ULL
#define TTBL_STAGE1_UPPER_PXN_SHIFT			53
#define TTBL_STAGE1_UPPER_CONT_MASK			0x0010000000000000ULL
#define TTBL_STAGE1_UPPER_CONT_SHIFT			52

/* TTBL Stage1 Block Lower Attributes */
#define TTBL_STAGE1_LOWER_NG_MASK			0x0000000000000800ULL
#define TTBL_STAGE1_LOWER_NG_SHIFT			11
#define TTBL_STAGE1_LOWER_AF_MASK			0x0000000000000400ULL
#define TTBL_STAGE1_LOWER_AF_SHIFT			10
#define TTBL_STAGE1_LOWER_SH_MASK			0x0000000000000300ULL
#define TTBL_STAGE1_LOWER_SH_SHIFT			8
#define TTBL_STAGE1_LOWER_AP_MASK			0x00000000000000C0ULL
#define TTBL_STAGE1_LOWER_AP_SHIFT			6
#define TTBL_STAGE1_LOWER_NS_MASK			0x0000000000000020ULL
#define TTBL_STAGE1_LOWER_NS_SHIFT			5
#define TTBL_STAGE1_LOWER_AINDEX_MASK			0x000000000000001CULL
#define TTBL_STAGE1_LOWER_AINDEX_SHIFT			2

/* TTBL Stage2 Block Upper Attributes */
#define TTBL_STAGE2_UPPER_MASK				0xFFF0000000000000ULL
#define TTBL_STAGE2_UPPER_SHIFT				52
#define TTBL_STAGE2_UPPER_XN_MASK			0x0040000000000000ULL
#define TTBL_STAGE2_UPPER_XN_SHIFT			54
#define TTBL_STAGE2_UPPER_CONT_MASK			0x0010000000000000ULL
#define TTBL_STAGE2_UPPER_CONT_SHIFT			52

/* TTBL Stage2 Block Lower Attributes */
#define TTBL_STAGE2_LOWER_MASK				0x0000000000000FFCULL
#define TTBL_STAGE2_LOWER_SHIFT				2
#define TTBL_STAGE2_LOWER_AF_MASK			0x0000000000000400ULL
#define TTBL_STAGE2_LOWER_AF_SHIFT			10
#define TTBL_STAGE2_LOWER_SH_MASK			0x0000000000000300ULL
#define TTBL_STAGE2_LOWER_SH_SHIFT			8
#define TTBL_STAGE2_LOWER_HAP_MASK			0x00000000000000C0ULL
#define TTBL_STAGE2_LOWER_HAP_SHIFT			6
#define TTBL_STAGE2_LOWER_MEMATTR_MASK			0x000000000000003CULL
#define TTBL_STAGE2_LOWER_MEMATTR_SHIFT			2

/* HMAIR encodings */
#define AINDEX_SO					0
#define AINDEX_NORMAL_WT				1
#define AINDEX_NORMAL_WB				2
#define AINDEX_NORMAL_UC				3
#define HMAIR0_INITVAL					0x44FFBB00
#define HMAIR1_INITVAL					0x00000000

/* VPIDR */
#define VPIDR_INITVAL					0x00000000

/* VMPIDR */
#define VMPIDR_INITVAL					0x00000000

/* DBGVIDSR */
#define DBGVIDSR_INITVAL				0x00000000
#define DBGVIDSR_NS_MASK				0x80000000
#define DBGVIDSR_NS_SHIFT				31
#define DBGVIDSR_H_MASK					0x40000000
#define DBGVIDSR_H_SHIFT				30
#define DBGVIDSR_VMID_MASK				0x000000FF
#define DBGVIDSR_VMID_SHIFT				0

/* HSCTLR */
#define HSCTLR_INITVAL					0x30C50878
#define HSCTLR_TE_MASK					0x40000000
#define HSCTLR_TE_SHIFT					30
#define HSCTLR_EE_MASK					0x02000000
#define HSCTLR_EE_SHIFT					25
#define HSCTLR_FI_MASK					0x00200000
#define HSCTLR_FI_SHIFT					21
#define HSCTLR_WXN_MASK					0x00080000
#define HSCTLR_WXN_SHIFT				19
#define HSCTLR_I_MASK					0x00001000
#define HSCTLR_I_SHIFT					12
#define HSCTLR_C_MASK					0x00000004
#define HSCTLR_C_SHIFT					2
#define HSCTLR_A_MASK					0x00000002
#define HSCTLR_A_SHIFT					1
#define HSCTLR_M_MASK					0x00000001
#define HSCTLR_M_SHIFT					0

/* DBGBXVR */
#define DBGBXVR_INITVAL					0x00000000
#define DBGBXVR_VMID_MASK				0x000000FF
#define DBGBXVR_VMID_SHIFT				0

/* PAR */
#define PAR_PA_MASK					0xFFFFF000
#define PAR_PA_SHIFT					12
#define PAR_LPAE_MASK					0x00000800
#define PAR_LPAE_SHIFT					11
#define PAR_NOS_MASK					0x00000400
#define PAR_NOS_SHIFT					10
#define PAR_NS_MASK					0x00000200
#define PAR_NS_SHIFT					9
#define PAR_SH_MASK					0x00000080
#define PAR_SH_SHIFT					7
#define PAR_INNER_MASK					0x00000070
#define PAR_INNER_SHIFT					4
#define PAR_OUTER_MASK					0x0000000C
#define PAR_OUTEr_SHIFT					2
#define PAR_SS_MASK					0x00000002
#define PAR_SS_SHIFT					1
#define PAR_F_MASK					0x00000001
#define PAR_F_SHIFT					0

/* PAR64 */
#define PAR64_ATTR_MASK					0xFF00000000000000ULL
#define PAR64_ATTR_SHIFT				56
#define PAR64_PA_MASK					0x000000FFFFFFF000ULL
#define PAR64_PA_SHIFT					12
#define PAR64_LPAE_MASK					0x0000000000000800ULL
#define PAR64_LPAE_SHIFT				11
#define PAR64_NS_MASK					0x0000000000000200ULL
#define PAR64_NS_SHIFT					9
#define PAR64_SH_MASK					0x0000000000000180ULL
#define PAR64_SH_SHIFT					7
#define PAR64_F_MASK					0x0000000000000001ULL
#define PAR64_F_SHIFT					0

/* ID_PFR1 */
#define ID_PFR1_GEN_TIMER_MASK				0x000f0000
#define ID_PFR1_GEN_TIMER_SHIFT				16
#define ID_PFR1_VIRTEX_MASK				0x0000f000
#define ID_PFR1_VIRTEX_SHIFT				12
#define ID_PFR1_M_PROFILE_MASK				0x00000f00
#define ID_PFR1_M_PROFILE_SHIFT				8
#define ID_PFR1_SECUREX_MASK				0x000000f0
#define ID_PFR1_SECUREX_SHIFT				4
#define ID_PFR1_PRG_MODEL_MASK				0x0000000f
#define ID_PFR1_PRG_MODEL_SHIFT				0
#endif
