/**
 * Copyright (c) 2018 Anup Patel.
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
 * @file cpu_vcpu_helper.c
 * @author Anup Patel (anup@brainfault.org)
 * @brief source of VCPU helper functions
 */

#include <vmm_devtree.h>
#include <vmm_error.h>
#include <vmm_heap.h>
#include <vmm_smp.h>
#include <vmm_stdio.h>
#include <vmm_pagepool.h>
#include <vmm_timer.h>
#include <vmm_host_aspace.h>
#include <arch_barrier.h>
#include <arch_guest.h>
#include <arch_mmu.h>
#include <arch_vcpu.h>
#include <vio/vmm_vserial.h>
#include <generic_mmu.h>

#include <cpu_hwcap.h>
#include <cpu_tlb.h>
#include <cpu_sbi.h>
#include <cpu_vcpu_fp.h>
#include <cpu_vcpu_sbi.h>
#include <cpu_vcpu_trap.h>
#include <cpu_vcpu_nested.h>
#include <cpu_vcpu_helper.h>
#include <cpu_vcpu_timer.h>
#include <cpu_guest_serial.h>
#include <riscv_csr.h>
#include <riscv_lrsc.h>
#include <riscv_timex.h>

#define RISCV_ISA_ALLOWED	(riscv_isa_extension_mask(a) | \
				 riscv_isa_extension_mask(c) | \
				 riscv_isa_extension_mask(d) | \
				 riscv_isa_extension_mask(f) | \
				 riscv_isa_extension_mask(i) | \
				 riscv_isa_extension_mask(m) | \
				 riscv_isa_extension_mask(h) | \
				 riscv_isa_extension_mask(SSTC))

#ifdef CONFIG_TLB_LOCKING
// Tracks whether a given lockable TLB entry is used (0) or not (1)
#ifdef CONFIG_TLB_XVISOR_COLOUR
static u64 tlb_lockings_free_bitmap = ((1 << CONFIG_TLB_NUM_LOCKED_ENTRIES) - 1) & ~((1UL << (CONFIG_TLB_XVISOR_COLOUR-1)));
#else
static u64 tlb_lockings_free_bitmap = (1 << CONFIG_TLB_NUM_LOCKED_ENTRIES) - 1;
#endif
#endif

static int guest_vserial_notification(struct vmm_notifier_block *nb,
					unsigned long evt, void *data)
{
	int ret = NOTIFY_OK;
	struct vmm_vserial_event *e = data;
	struct riscv_guest_serial *gs = container_of(nb,
						struct riscv_guest_serial,
						vser_client);
	if (evt ==  VMM_VSERIAL_EVENT_CREATE) {
		if (!gs->vserial &&
		    !strncmp(e->vser->name, gs->guest->name,
			     strlen(gs->guest->name))) {
			gs->vserial = e->vser;
		}
	} else if (evt == VMM_VSERIAL_EVENT_DESTROY) {
		if (e->vser == gs->vserial) {
			gs->vserial = NULL;
		}
	} else
		ret = NOTIFY_DONE;
	return ret;
}

int arch_guest_init(struct vmm_guest *guest)
{
	struct riscv_guest_priv *priv;
	struct riscv_guest_serial *gserial;
	u32 pgtbl_attr, pgtbl_hw_tag;
	int rc;

	if (!guest->reset_count) {
		if (!riscv_isa_extension_available(NULL, h) ||
		    !sbi_has_0_2_rfence())
			return VMM_EINVALID;

		guest->arch_priv = vmm_malloc(sizeof(struct riscv_guest_priv));
		if (!guest->arch_priv) {
			return VMM_ENOMEM;
		}
		priv = riscv_guest_priv(guest);

		priv->time_delta = -get_cycles64();

		pgtbl_hw_tag = 0;
		pgtbl_attr = MMU_ATTR_REMOTE_TLB_FLUSH;
		if (riscv_stage2_vmid_available()) {
			pgtbl_hw_tag = guest->id;
			pgtbl_attr |= MMU_ATTR_HW_TAG_VALID;
		}
		priv->pgtbl = mmu_pgtbl_alloc(MMU_STAGE2, -1,
					      pgtbl_attr, pgtbl_hw_tag);
		if (!priv->pgtbl) {
			vmm_free(guest->arch_priv);
			guest->arch_priv = NULL;
			return VMM_ENOMEM;
		}

		priv->guest_serial = vmm_malloc(sizeof(struct riscv_guest_serial));
		if (!priv->guest_serial) {
			mmu_pgtbl_free(riscv_guest_priv(guest)->pgtbl);
			vmm_free(guest->arch_priv);
			guest->arch_priv = NULL;
			return VMM_ENOMEM;
		}

		gserial = riscv_guest_serial(guest);
		gserial->guest = guest;
		gserial->vser_client.notifier_call = &guest_vserial_notification;
		gserial->vser_client.priority = 0;
		rc = vmm_vserial_register_client(&gserial->vser_client);
		if (rc) {
			vmm_free(gserial);
			mmu_pgtbl_free(riscv_guest_priv(guest)->pgtbl);
			vmm_free(guest->arch_priv);
			guest->arch_priv = NULL;
			return rc;
		}
	}

	return VMM_OK;
}

int arch_guest_deinit(struct vmm_guest *guest)
{
	int rc;
	struct riscv_guest_serial *gs;

	if (guest->arch_priv) {
		gs = riscv_guest_serial(guest);

		if ((rc = mmu_pgtbl_free(riscv_guest_priv(guest)->pgtbl))) {
			return rc;
		}
		if (gs) {
			vmm_vserial_unregister_client(&gs->vser_client);
			vmm_free(gs);
		}
		vmm_free(guest->arch_priv);
	}

	return VMM_OK;
}

int arch_guest_add_region(struct vmm_guest *guest, struct vmm_region *region)
{
#ifdef CONFIG_TLB_LOCKING
	arch_tlb_lock_vpn_t lock_vpn = {0};
	arch_tlb_lock_id_t lock_id = {0};
	struct mmu_page pg;
	char const *dt_attr = NULL;
	arch_pte_t *lock_pte = NULL;
	struct mmu_pgtbl *lock_pte_pgtbl = NULL;
	u64 size_left = 0, num_1g = 0, num_2m = 0, num_4k = 0, num_needed_indices = 0, num_reserved_indices = 0;
    u64 idx = 0, selected_indices = 0, mut_align = 0, mut_align_bits = 0;
    u64 cur_gphys_addr = 0, cur_hphys_addr = 0, cur_size = 0;
	int rc = 0, target = 0, cur_size_enum = 0;
	irq_flags_t f;

	arch_cpu_irq_save(f);

	// Check that at least one locking entry is configured and that
	// we have space still
	if(CONFIG_TLB_NUM_LOCKED_ENTRIES && tlb_lockings_free_bitmap){

		rc = vmm_devtree_read_string(region->node, VMM_DEVTREE_TLB_LOCKING_ATTR_NAME, &dt_attr);
		if (rc) {
			goto tlb_lock_free_fail;
		}

		// Is this a DTLB only mapping?
		if(!strcmp(dt_attr, VMM_DEVTREE_TLB_LOCKING_VAL_DATA)){
			target = 1;
		// Or an ITLB only mapping?
		} else if(!strcmp(dt_attr, VMM_DEVTREE_TLB_LOCKING_VAL_INSTRUCTION)){
			target = 2;
		// Or both?
		} else if(!strcmp(dt_attr, VMM_DEVTREE_TLB_LOCKING_VAL_BOTH)){
			target = 3;
		// Okay no idea what this is
		} else {
			vmm_printf("%s: Unknown TLB locking mode: %s\n", __func__, dt_attr);
			goto tlb_lock_free_fail;
		}

		// To be able to create a TLB locking we need the region to only consist of
        // a single mapping (so that we don't have inconsistent page table state)
		if(region->maps_count > 1){
			vmm_printf("%s: Lock-incompatible region (@0x%lx, 0x%lx)\n",
				__func__, region->gphys_addr, region->phys_size);
			goto tlb_lock_free_fail;
		}

        mut_align_bits = (u64) region->gphys_addr | (u64) region->maps[0].hphys_addr;

        // Check how the mutual alignment works out to select the largest mappings possible
        if(!(mut_align_bits & ((1 << 30) - 1))){
            mut_align = 3;
        } else if (!(mut_align_bits & ((1 << 21) - 1))) {
            mut_align = 2;
        } else {
            mut_align = 1;
        }

        // Figure out how many mappings we need
        size_left = region->phys_size;

        // Figure out how many giga pages we need
        if(mut_align >= 3 && size_left >= (1 << 30)){
            num_1g = size_left >> 30;
            size_left -= num_1g << 30;
        }

        // Figure out how many 2 mega pages we need
        if(mut_align >= 2 && size_left >= (1 << 21)){
            num_2m = size_left >> 21;
            size_left -= num_2m << 21;
        }

        // Figure out how many pages we need
        if(size_left >= (1 << 12)){
            num_4k = size_left >> 12;
            size_left -= num_4k << 12;
        }

        if(size_left != 0){
            vmm_printf("%s: The size of the region is not 4k aligned! (region->phys_size = 0x%lx)\n",
                       __func__, region->phys_size);
            goto tlb_lock_free_fail;
        }

        // How many locked entries do we need in total?
        num_needed_indices = num_1g + num_2m + num_4k;

        // If that number already outgrows the maximum possible, we abort here
        if(num_needed_indices > CONFIG_TLB_NUM_LOCKED_ENTRIES){
            vmm_printf("%s: Impossible configuration. Locking this mapping would require %lu locked entries"
                       " but hardware only supports %lu at max!\n", __func__, num_needed_indices, (u64) CONFIG_TLB_NUM_LOCKED_ENTRIES);
            goto tlb_lock_free_fail;
        }


        while(num_reserved_indices < num_needed_indices){

            while(idx < CONFIG_TLB_NUM_LOCKED_ENTRIES && !((tlb_lockings_free_bitmap >> idx) & 1)){
                idx++;
            }

            if(idx >= CONFIG_TLB_NUM_LOCKED_ENTRIES){
                vmm_printf("%s: Not enough lockable entries left (bitmap = 0x%lx)!\n", __func__, tlb_lockings_free_bitmap);
                goto tlb_lock_free_fail;
            }

            selected_indices |= 1 << idx++;
            num_reserved_indices++;
        }

		tlb_lockings_free_bitmap &= ~selected_indices;

		vmm_printf("%s: Mapping 0x%lx bytes, 0x%lx -> 0x%lx with locking bitmap 0x%lx in %lu lockable entries for %s%s%s\n",
				   __func__, region->phys_size, region->gphys_addr, region->maps[0].hphys_addr,
				   selected_indices, num_reserved_indices,
                   (target & 1) ? "DTLB" : "", (target == 3) ? " and " : "", (target & 2) ? "ITLB" : "");

		// The saved lock_id is the bitmap of the used entries
		region->lock_id = selected_indices;

        idx = 0;
        while(!(selected_indices & 1)){
            idx++;
            selected_indices >>= 1;
        }

        // Use this to track how much is left to map
        size_left = region->phys_size;
        cur_gphys_addr = region->gphys_addr;
        cur_hphys_addr = region->maps[0].hphys_addr;

        while(num_reserved_indices){
            // Zero the page description struct
            memset(&pg, 0, sizeof(pg));

            if(num_1g){
                cur_size = 1 << 30;
                cur_size_enum = 3;
                num_1g--;
            } else if (num_2m) {
                cur_size = 1 << 21;
                cur_size_enum = 2;
                num_2m--;
            } else {
                cur_size = 1 << 12;
                cur_size_enum = 1;
            }

            // Set-up the page description struct
            pg.ia = cur_gphys_addr;
            pg.sz = cur_size;
            pg.oa = cur_hphys_addr;

            arch_mmu_pgflags_set(&pg.flags, MMU_STAGE2, region->flags);

            // Try to map the page in Stage2
            rc = mmu_map_page(riscv_guest_priv(guest)->pgtbl, &pg);
            if (rc) {
                vmm_printf("%s: Unable to map the page in the guest pagetable (rc = %d)!\n",
                           __func__, rc);
                goto tlb_lock_free_fail;
            }

            lock_vpn.size = cur_size_enum;
            lock_vpn.virt_mode = 1;
            lock_vpn.data = target & 1;
            lock_vpn.instr = (target & 2) >> 1;
            lock_vpn.s_st_enbl = 0;	// TODO! This works only for a bare-metal guest
            lock_vpn.g_st_enbl = 1;
            lock_vpn.vpn = cur_gphys_addr >> 12;

            lock_id.asid = 0;
            lock_id.vmid = mmu_pgtbl_hw_tag(riscv_guest_priv(guest)->pgtbl);

            rc = mmu_find_pte(riscv_guest_priv(guest)->pgtbl, cur_gphys_addr, &lock_pte, &lock_pte_pgtbl);
            if(rc){
                vmm_printf("%s: Unable to find PTE for 0x%lx (rc = %d)\n",
                           __func__, region->gphys_addr, rc);
                goto tlb_lock_free_fail;
            }

            u64 satp = 0, hgatp = 0;

            asm volatile(
                "csrrs %0, satp, x0\n		\
                 csrrs %1, hgatp, x0\n"
                : "=r"(satp), "=r"(hgatp)
                ::
            );

            vmm_printf("%s: Current SATP = 0x%lx, current HGATP = 0x%lx\n%s: assembled lock vpn = 0x%lx, assembled lock id = 0x%x\n",
                       __func__, satp, hgatp, __func__, arch_mmu_pack_tlb_lock_vpn(lock_vpn), arch_mmu_pack_tlb_lock_id(lock_id));
            vmm_printf("%s: PTE for locked page = 0x%lx\n", __func__, *lock_pte);


            // set the registers for our locking
            switch(idx){
			case 0:
                asm volatile(
                    "csrrw x0, 0x5C3, %0\n	\
					 csrrw x0, 0x5C4, %1\n	\
					 csrrw x0, 0x5C5, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			case 1:
                asm volatile(
                    "csrrw x0, 0x5C6, %0\n	\
					 csrrw x0, 0x5C7, %1\n	\
					 csrrw x0, 0x5C8, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			case 2:
                asm volatile(
                    "csrrw x0, 0x5C9, %0\n	\
					 csrrw x0, 0x5CA, %1\n	\
					 csrrw x0, 0x5CB, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			case 3:
                asm volatile(
                    "csrrw x0, 0x5CC, %0\n	\
					 csrrw x0, 0x5CD, %1\n	\
					 csrrw x0, 0x5CE, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			case 4:
                asm volatile(
                    "csrrw x0, 0x5CF, %0\n	\
					 csrrw x0, 0x5D0, %1\n	\
					 csrrw x0, 0x5D1, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			case 5:
                asm volatile(
                    "csrrw x0, 0x5D2, %0\n	\
					 csrrw x0, 0x5D3, %1\n	\
					 csrrw x0, 0x5D4, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			case 6:
                asm volatile(
                    "csrrw x0, 0x5D5, %0\n	\
					 csrrw x0, 0x5D6, %1\n	\
					 csrrw x0, 0x5D7, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			case 7:
                asm volatile(
                    "csrrw x0, 0x5D8, %0\n	\
					 csrrw x0, 0x5D9, %1\n	\
					 csrrw x0, 0x5DA, %2\n"
                    :: "r"(*lock_pte), "r"(arch_mmu_pack_tlb_lock_vpn(lock_vpn)), "r"(arch_mmu_pack_tlb_lock_id(lock_id))
                    :
                );
                break;
			default:
                vmm_printf("%s: Index %lu not supported!\n", __func__, idx);
                break;
            }

            cur_gphys_addr += cur_size;
            cur_hphys_addr += cur_size;

            selected_indices >>= 1;
            idx++;
            num_reserved_indices--;

            // Select the next index to use
            if(num_reserved_indices){
                while(!(selected_indices & 1)){
                    idx++;
                    selected_indices >>= 1;
                }
            }
        }
	}

tlb_lock_free_fail:
	arch_cpu_irq_restore(f);

#endif

	return VMM_OK;
}

int arch_guest_del_region(struct vmm_guest *guest, struct vmm_region *region)
{
#ifdef CONFIG_TLB_LOCKING
	irq_flags_t f;
    u64 remaining_entries = 0, cur_idx = 0;

	arch_cpu_irq_save(f);

	// Does this region have a locking?
	if(region->lock_id){
        remaining_entries = region->lock_id;

        while(remaining_entries){

            while(!(remaining_entries & 1)){
                cur_idx++;
                remaining_entries >>= 1;
            }

		    switch(cur_idx){
			    case 0:
				    asm volatile(
					    "csrrw x0, 0x5C3, x0\n	\
					     csrrw x0, 0x5C4, x0\n	\
					     csrrw x0, 0x5C5, x0\n"
					     :::
				    );
				    break;
			    case 1:
				    asm volatile(
					    "csrrw x0, 0x5C6, x0\n	\
					     csrrw x0, 0x5C7, x0\n	\
					     csrrw x0, 0x5C8, x0\n"
					     :::
				    );
				    break;
			    case 2:
				    asm volatile(
					    "csrrw x0, 0x5C9, x0\n	\
					     csrrw x0, 0x5CA, x0\n	\
					     csrrw x0, 0x5CB, x0\n"
					     :::
				    );
                    break;
			    case 3:
				    asm volatile(
					    "csrrw x0, 0x5CC, x0\n	\
					     csrrw x0, 0x5CD, x0\n	\
					     csrrw x0, 0x5CE, x0\n"
					     :::
				    );
				    break;
			    case 4:
                    asm volatile(
                        "csrrw x0, 0x5CF, x0\n	\
					     csrrw x0, 0x5D0, x0\n	\
					     csrrw x0, 0x5D1, x0\n"
					     :::
				    );
				    break;
			    case 5:
				    asm volatile(
					    "csrrw x0, 0x5D2, x0\n	\
					     csrrw x0, 0x5D3, x0\n	\
					     csrrw x0, 0x5D4, x0\n"
					     :::
				    );
				    break;
			    case 6:
				    asm volatile(
					    "csrrw x0, 0x5D5, x0\n	\
					     csrrw x0, 0x5D6, x0\n	\
					     csrrw x0, 0x5D7, x0\n"
					     :::
				    );
				    break;
			    case 7:
				    asm volatile(
					    "csrrw x0, 0x5D8, x0\n	\
					     csrrw x0, 0x5D9, x0\n	\
					     csrrw x0, 0x5DA, x0\n"
					     :::
				    );
				    break;
			    default:
				    vmm_printf("%s: Unsupported locking index: %lu\n", __func__, region->lock_id-1);
				    break;
		    }

            tlb_lockings_free_bitmap |= (1 << cur_idx);

            cur_idx++;
            remaining_entries >>= 1;
        }

		region->lock_id = 0;
	}

	arch_cpu_irq_restore(f);
#endif

	return VMM_OK;
}

int arch_vcpu_init(struct vmm_vcpu *vcpu)
{
	int rc = VMM_OK;
	const char *attr;
	virtual_addr_t sp, sp_exec;

	/* Determine stack location */
	if (vcpu->is_normal) {
		sp = 0;
		sp_exec = vcpu->stack_va + vcpu->stack_sz;
		sp_exec = sp_exec & ~(__SIZEOF_POINTER__ - 1);
	} else {
		sp = vcpu->stack_va + vcpu->stack_sz;
		sp = sp & ~(__SIZEOF_POINTER__ - 1);
		if (!vcpu->reset_count) {
			/* First time allocate exception stack */
			sp_exec = vmm_pagepool_alloc(VMM_PAGEPOOL_NORMAL,
				VMM_SIZE_TO_PAGE(CONFIG_IRQ_STACK_SIZE));
			if (!sp_exec) {
				return VMM_ENOMEM;
			}
			sp_exec += CONFIG_IRQ_STACK_SIZE;
		} else {
			sp_exec = riscv_regs(vcpu)->sp_exec;
		}
	}

	/* For both Orphan & Normal VCPUs */
	memset(riscv_regs(vcpu), 0, sizeof(arch_regs_t));
	riscv_regs(vcpu)->sepc = vcpu->start_pc;
	riscv_regs(vcpu)->sstatus = SSTATUS_SPP | SSTATUS_SPIE;
	riscv_regs(vcpu)->sp = sp;
	riscv_regs(vcpu)->sp_exec = sp_exec;
	riscv_regs(vcpu)->hstatus = 0;

	/* For Orphan VCPUs we are done */
	if (!vcpu->is_normal) {
		return VMM_OK;
	}

	/* Following initialization for normal VCPUs only */

	/* First time initialization of private context */
	if (!vcpu->reset_count) {
		/* Check allowed compatible string */
		rc = vmm_devtree_read_string(vcpu->node,
				VMM_DEVTREE_COMPATIBLE_ATTR_NAME, &attr);
		if (rc) {
			goto fail;
		}
		if (strcmp(attr, "riscv,generic") != 0) {
			rc = VMM_EINVALID;
			goto fail;
		}

		/* Alloc private context */
		vcpu->arch_priv = vmm_zalloc(sizeof(struct riscv_priv));
		if (!vcpu->arch_priv) {
			rc = VMM_ENOMEM;
			goto fail;
		}

		/* Set register width */
		riscv_priv(vcpu)->xlen = riscv_xlen;

		/* Allocate ISA feature bitmap */
		riscv_priv(vcpu)->isa =
			vmm_zalloc(bitmap_estimate_size(RISCV_ISA_EXT_MAX));
		if (!riscv_priv(vcpu)->isa) {
			rc = VMM_ENOMEM;
			goto fail_free_priv;
		}

		/* Parse VCPU ISA string */
		attr = NULL;
		rc = vmm_devtree_read_string(vcpu->node, "riscv,isa", &attr);
		if (rc || !attr) {
			rc = VMM_EINVALID;
			goto fail_free_isa;
		}
		rc = riscv_isa_parse_string(attr, &riscv_priv(vcpu)->xlen,
					    riscv_priv(vcpu)->isa,
					    RISCV_ISA_EXT_MAX);
		if (rc) {
			goto fail_free_isa;
		}
		if (riscv_priv(vcpu)->xlen > riscv_xlen) {
			rc = VMM_EINVALID;
			goto fail_free_isa;
		}
		riscv_priv(vcpu)->isa[0] &= RISCV_ISA_ALLOWED;

		/* VCPU ISA bitmap should be ANDed with Host ISA bitmap */
		bitmap_and(riscv_priv(vcpu)->isa, riscv_priv(vcpu)->isa,
			   riscv_isa_extension_host(), RISCV_ISA_EXT_MAX);

		/* H-extension only available when AIA CSRs are available */
		if (!riscv_isa_extension_available(NULL, SxAIA)) {
			riscv_priv(vcpu)->isa[0] &=
					~riscv_isa_extension_mask(h);
		}

		/* Initialize nested state */
		rc = cpu_vcpu_nested_init(vcpu);
		if (rc) {
			goto fail_free_isa;
		}

		/* Initialize timer state */
		rc = cpu_vcpu_timer_init(vcpu);
		if (rc) {
			goto fail_free_nested;
		}

		/*
		 * Initialize SBI state
		 * NOTE: This must be the last thing to initialize.
		 */
		rc = cpu_vcpu_sbi_init(vcpu);
		if (rc) {
			goto fail_free_timer;
		}
	}

	/* Set a0 to VCPU sub-id (i.e. virtual HARTID) */
	riscv_regs(vcpu)->a0 = vcpu->subid;

	/* Update HSTATUS */
	riscv_regs(vcpu)->hstatus |= HSTATUS_VTW;
	riscv_regs(vcpu)->hstatus |= HSTATUS_SPVP;
	riscv_regs(vcpu)->hstatus |= HSTATUS_SPV;

	/* TODO: Update HSTATUS.VSXL for 32bit Guest on 64-bit Host */

	/* TODO: Update HSTATUS.VSBE for big-endian Guest */

	/* Reset stats gathering */
	memset(riscv_stats_priv(vcpu), 0, sizeof(struct riscv_priv_stats));

	/* Update VCPU CSRs */
	riscv_priv(vcpu)->hie = 0;
	riscv_priv(vcpu)->hip = 0;
	riscv_priv(vcpu)->hvip = 0;
	riscv_priv(vcpu)->henvcfg = 0;
	riscv_priv(vcpu)->vsstatus = 0;
	riscv_priv(vcpu)->vstvec = 0;
	riscv_priv(vcpu)->vsscratch = 0;
	riscv_priv(vcpu)->vsepc = 0;
	riscv_priv(vcpu)->vscause = 0;
	riscv_priv(vcpu)->vstval = 0;
	riscv_priv(vcpu)->vsatp = 0;

	/* By default, make CY, TM, and IR counters accessible in VU mode */
	riscv_priv(vcpu)->scounteren = 7;

	/* Reset nested state */
	cpu_vcpu_nested_reset(vcpu);

	/* Reset FP state */
	cpu_vcpu_fp_reset(vcpu);

	/* Reset timer */
	cpu_vcpu_timer_reset(vcpu);

	return VMM_OK;

fail_free_timer:
	cpu_vcpu_timer_deinit(vcpu);
fail_free_nested:
	cpu_vcpu_nested_deinit(vcpu);
fail_free_isa:
	vmm_free(riscv_priv(vcpu)->isa);
	riscv_priv(vcpu)->isa = NULL;
fail_free_priv:
	vmm_free(vcpu->arch_priv);
	vcpu->arch_priv = NULL;
fail:
	return rc;
}

int arch_vcpu_deinit(struct vmm_vcpu *vcpu)
{
	virtual_addr_t sp_exec;

	/* Free-up exception stack for Orphan VCPU */
	if (!vcpu->is_normal) {
		sp_exec = riscv_regs(vcpu)->sp_exec - CONFIG_IRQ_STACK_SIZE;
		vmm_pagepool_free(VMM_PAGEPOOL_NORMAL, sp_exec,
				  VMM_SIZE_TO_PAGE(CONFIG_IRQ_STACK_SIZE));
	}

	/* For both Orphan & Normal VCPUs */

	/* Clear arch registers */
	memset(riscv_regs(vcpu), 0, sizeof(arch_regs_t));

	/* For Orphan VCPUs do nothing else */
	if (!vcpu->is_normal) {
		return VMM_OK;
	}

	/* Cleanup SBI */
	cpu_vcpu_sbi_deinit(vcpu);

	/* Cleanup timer */
	cpu_vcpu_timer_deinit(vcpu);

	/* Cleanup nested state */
	cpu_vcpu_nested_deinit(vcpu);

	/* Free ISA bitmap */
	vmm_free(riscv_priv(vcpu)->isa);
	riscv_priv(vcpu)->isa = NULL;

	/* Free private context */
	vmm_free(vcpu->arch_priv);
	vcpu->arch_priv = NULL;

	return VMM_OK;
}

void arch_vcpu_switch(struct vmm_vcpu *tvcpu,
		      struct vmm_vcpu *vcpu,
		      arch_regs_t *regs)
{
	struct riscv_priv *priv;

	if (tvcpu) {
		memcpy(riscv_regs(tvcpu), regs, sizeof(*regs));
		if (tvcpu->is_normal) {
			priv = riscv_priv(tvcpu);
			priv->hie = csr_read(CSR_HIE);
			priv->hip = csr_read(CSR_HIP);
			priv->hvip = csr_read(CSR_HVIP);
			priv->vsstatus = csr_read(CSR_VSSTATUS);
			priv->vstvec = csr_read(CSR_VSTVEC);
			priv->vsscratch = csr_read(CSR_VSSCRATCH);
			priv->vsepc = csr_read(CSR_VSEPC);
			priv->vscause = csr_read(CSR_VSCAUSE);
			priv->vstval = csr_read(CSR_VSTVAL);
			priv->vsatp = csr_read(CSR_VSATP);
			priv->scounteren = csr_read(CSR_SCOUNTEREN);
			cpu_vcpu_fp_save(tvcpu, regs);
			cpu_vcpu_timer_save(tvcpu);
		}
		clrx();
	}

	memcpy(regs, riscv_regs(vcpu), sizeof(*regs));
	if (vcpu->is_normal) {
		priv = riscv_priv(vcpu);
		csr_write(CSR_HIE, priv->hie);
		csr_write(CSR_HVIP, priv->hvip);
		csr_write(CSR_VSSTATUS, priv->vsstatus);
		csr_write(CSR_VSTVEC, priv->vstvec);
		csr_write(CSR_VSSCRATCH, priv->vsscratch);
		csr_write(CSR_VSEPC, priv->vsepc);
		csr_write(CSR_VSCAUSE, priv->vscause);
		csr_write(CSR_VSTVAL, priv->vstval);
		csr_write(CSR_VSATP, priv->vsatp);
		csr_write(CSR_SCOUNTEREN, priv->scounteren);
		cpu_vcpu_envcfg_update(vcpu, riscv_nested_virt(vcpu));
		cpu_vcpu_timer_restore(vcpu);
		cpu_vcpu_fp_restore(vcpu, regs);
		cpu_vcpu_gstage_update(vcpu, riscv_nested_virt(vcpu));
		cpu_vcpu_irq_deleg_update(vcpu, riscv_nested_virt(vcpu));
	} else {
		cpu_vcpu_irq_deleg_update(vcpu, FALSE);
	}
}

void arch_vcpu_post_switch(struct vmm_vcpu *vcpu,
			   arch_regs_t *regs)
{
	// If configured accordingly, and if the vcpu is associated with a guest
	// set the corresponding allowed colours
#ifdef CONFIG_TLB_COLOURING
	// If this vcpu is from a guest => use the allowed colours
	// otherwise use the Xvisor colour
	if(vcpu->guest){
		csr_write(CSR_LAST_CLRS, vcpu->guest->allowed_colours_bitmask);
	} else {
		csr_write(CSR_LAST_CLRS, CONFIG_TLB_XVISOR_COLOUR);
	}

#endif
}

void cpu_vcpu_envcfg_update(struct vmm_vcpu *vcpu, bool nested_virt)
{
	u64 henvcfg = (nested_virt) ? 0 : riscv_priv(vcpu)->henvcfg;

#ifdef CONFIG_32BIT
	csr_write(CSR_HENVCFG, (u32)henvcfg);
	csr_write(CSR_HENVCFGH, (u32)(henvcfg >> 32));
#else
	csr_write(CSR_HENVCFG, henvcfg);
#endif
}

void cpu_vcpu_irq_deleg_update(struct vmm_vcpu *vcpu, bool nested_virt)
{
	if (vcpu->is_normal && nested_virt) {
		/* Disable interrupt delegation */
		csr_write(CSR_HIDELEG, 0);

		/* Enable sip/siph and sie/sieh trapping */
		if (riscv_isa_extension_available(NULL, SxAIA)) {
			csr_set(CSR_HVICTL, HVICTL_VTI);
		}
	} else {
		/* Enable interrupt delegation */
		csr_write(CSR_HIDELEG, HIDELEG_DEFAULT);

		/* Disable sip/siph and sie/sieh trapping */
		if (riscv_isa_extension_available(NULL, SxAIA)) {
			csr_clear(CSR_HVICTL, HVICTL_VTI);
		}
	}
}

void cpu_vcpu_gstage_update(struct vmm_vcpu *vcpu, bool nested_virt)
{
	struct mmu_pgtbl *pgtbl = (nested_virt) ?
				  riscv_nested_priv(vcpu)->pgtbl :
				  riscv_guest_priv(vcpu->guest)->pgtbl;

	mmu_stage2_change_pgtbl(pgtbl);
	if (!mmu_pgtbl_has_hw_tag(pgtbl)) {
		/*
		 * Invalidate entries related to all guests from both
		 * G-stage TLB and VS-stage TLB.
		 *
		 * NOTE: Due to absence of VMID, there is not VMID tagging
		 * in VS-stage TLB as well so to avoid one Guest seeing
		 * VS-stage mappings of other Guest we have to invalidate
		 * VS-stage TLB enteries as well.
		 */
		__hfence_gvma_all();
		__hfence_vvma_all();
	}
}

void cpu_vcpu_dump_general_regs(struct vmm_chardev *cdev,
				arch_regs_t *regs)
{
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "       zero", regs->zero, "         ra", regs->ra);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         sp", regs->sp, "         gp", regs->gp);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         tp", regs->tp, "         s0", regs->s0);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         s1", regs->s1, "         a0", regs->a0);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         a1", regs->a1, "         a2", regs->a2);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         a3", regs->a3, "         a4", regs->a4);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         a5", regs->a5, "         a6", regs->a6);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         a7", regs->a7, "         s2", regs->s2);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         s3", regs->s3, "         s4", regs->s4);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         s5", regs->s5, "         s6", regs->s6);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         s7", regs->s7, "         s8", regs->s8);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         s9", regs->s9, "        s10", regs->s10);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "        s11", regs->s11, "         t0", regs->t0);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         t1", regs->t1, "         t2", regs->t2);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         t3", regs->t3, "         t4", regs->t4);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "         t5", regs->t5, "         t6", regs->t6);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "       sepc", regs->sepc, "    sstatus", regs->sstatus);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "    hstatus", regs->hstatus, "    sp_exec", regs->sp_exec);
}

void cpu_vcpu_dump_private_regs(struct vmm_chardev *cdev,
				struct vmm_vcpu *vcpu)
{
	int rc;
	char isa[128];
	struct riscv_priv *priv = riscv_priv(vcpu);
	struct riscv_guest_priv *gpriv = riscv_guest_priv(vcpu->guest);

	rc = riscv_isa_populate_string(priv->xlen, priv->isa,
					isa, sizeof(isa));
	if (rc) {
		vmm_cprintf(cdev, "Failed to populate ISA string\n");
		return;
	}

	vmm_cprintf(cdev, "\n");
	vmm_cprintf(cdev, "    %s=%s\n",
		    "        isa", isa);
	vmm_cprintf(cdev, "\n");
#ifdef CONFIG_64BIT
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR"\n",
		    " htimedelta", (ulong)gpriv->time_delta);
#else
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    " htimedelta", (ulong)(gpriv->time_delta),
		    "htimedeltah", (ulong)(gpriv->time_delta >> 32));
#endif
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "        hie", priv->hie, "        hip", priv->hip);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "       hvip", priv->hvip, "   vsstatus", priv->vsstatus);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "      vsatp", priv->vsatp, "     vstvec", priv->vstvec);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "  vsscratch", priv->vsscratch, "      vsepc", priv->vsepc);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "    vscause", priv->vscause, "     vstval", priv->vstval);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR"\n",
		    " scounteren", priv->scounteren);

	cpu_vcpu_nested_dump_regs(cdev, vcpu);

	cpu_vcpu_fp_dump_regs(cdev, vcpu);
}

void cpu_vcpu_dump_exception_regs(struct vmm_chardev *cdev,
				  unsigned long scause, unsigned long stval,
				  unsigned long htval, unsigned long htinst)
{
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "     scause", scause, "      stval", stval);
	vmm_cprintf(cdev, "    %s=0x%"PRIADDR" %s=0x%"PRIADDR"\n",
		    "      htval", htval, "     htinst", htinst);
}

void arch_vcpu_regs_dump(struct vmm_chardev *cdev, struct vmm_vcpu *vcpu)
{
	cpu_vcpu_dump_general_regs(cdev, riscv_regs(vcpu));

	if (vcpu->is_normal) {
		cpu_vcpu_dump_private_regs(cdev, vcpu);
	}
}

static const char trap_names[][32] = {
	[CAUSE_MISALIGNED_FETCH]		= "Misaligned Fetch Fault",
	[CAUSE_FETCH_ACCESS]			= "Fetch Access Fault",
	[CAUSE_ILLEGAL_INSTRUCTION]		= "Illegal Instruction Fault",
	[CAUSE_BREAKPOINT]			= "Breakpoint Fault",
	[CAUSE_MISALIGNED_LOAD]			= "Misaligned Load Fault",
	[CAUSE_LOAD_ACCESS]			= "Load Access Fault",
	[CAUSE_MISALIGNED_STORE]		= "Misaligned Store Fault",
	[CAUSE_STORE_ACCESS]			= "Store Access Fault",
	[CAUSE_USER_ECALL]			= "User Ecall",
	[CAUSE_SUPERVISOR_ECALL]		= "Supervisor Ecall",
	[CAUSE_VIRTUAL_SUPERVISOR_ECALL]	= "Virtual Supervisor Ecall",
	[CAUSE_MACHINE_ECALL]			= "Machine Ecall",
	[CAUSE_FETCH_PAGE_FAULT]		= "Fetch Page Fault",
	[CAUSE_LOAD_PAGE_FAULT]			= "Load Page Fault",
	[CAUSE_STORE_PAGE_FAULT]		= "Store Page Fault",
	[CAUSE_FETCH_GUEST_PAGE_FAULT]		= "Fetch Guest Page Fault",
	[CAUSE_LOAD_GUEST_PAGE_FAULT]		= "Load Guest Page Fault",
	[CAUSE_VIRTUAL_INST_FAULT]		= "Virtual Instruction Fault",
	[CAUSE_STORE_GUEST_PAGE_FAULT]		= "Store Guest Page Fault",
};

void arch_vcpu_stat_dump(struct vmm_chardev *cdev, struct vmm_vcpu *vcpu)
{
	int i;
	bool have_traps = FALSE;

	for (i = 0; i < RISCV_PRIV_MAX_TRAP_CAUSE; i++) {
		if (!riscv_stats_priv(vcpu)->trap[i]) {
			continue;
		}
		vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n", trap_names[i],
			    riscv_stats_priv(vcpu)->trap[i]);
		have_traps = TRUE;
	}

	if (have_traps) {
		vmm_cprintf(cdev, "\n");
	}

	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested Enter",
		    riscv_stats_priv(vcpu)->nested_enter);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested Exit",
		    riscv_stats_priv(vcpu)->nested_exit);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested Virtual Interrupt",
		    riscv_stats_priv(vcpu)->nested_vsirq);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested S-mode CSR Access",
		    riscv_stats_priv(vcpu)->nested_smode_csr_rmw);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested HS-mode CSR Access",
		    riscv_stats_priv(vcpu)->nested_hext_csr_rmw);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested Load Guest Page Fault",
		    riscv_stats_priv(vcpu)->nested_load_guest_page_fault);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested Store Guest Page Fault",
		    riscv_stats_priv(vcpu)->nested_store_guest_page_fault);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested Fetch Guest Page Fault",
		    riscv_stats_priv(vcpu)->nested_fetch_guest_page_fault);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested HFENCE.VVMA Instruction",
		    riscv_stats_priv(vcpu)->nested_hfence_vvma);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested HFENCE.GVMA Instruction",
		    riscv_stats_priv(vcpu)->nested_hfence_gvma);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested HLV Instruction",
		    riscv_stats_priv(vcpu)->nested_hlv);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested HSV Instruction",
		    riscv_stats_priv(vcpu)->nested_hsv);
	vmm_cprintf(cdev, "%-32s: 0x%"PRIx64"\n",
		    "Nested SBI Ecall",
		    riscv_stats_priv(vcpu)->nested_sbi);
}
