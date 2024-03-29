/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
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

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

static struct kmem_cache *pgd_cache;
#ifdef YMH_USE_SEPARATE_BLOCKS
extern int removePage(unsigned long long page_vaddr, int bPTP);
extern void printBlocksInfo_LIVE(void);
static void *pgds[2048];
static int pgds_idx = 0;

static void addPgd(void *pgdAddr) {
	pgds[pgds_idx++] = pgdAddr;
}

static void removePgd(void *pgdAddr) {
	int i;
	for (i = 0; i < pgds_idx; i++)
		if (pgds[i] == pgdAddr) {
			pgds[i] = 0ULL;
			return;
		}
	myprintk("REMOVE_PGD ERROR - PGD is allocated from where?\n");
}

static void printAllPgds(void) {
	int i;
	for (i = 0; i < pgds_idx; i++)
		myprintk("%04d: 0x%llX\n", i, (unsigned long long) pgds[i]);
}
#endif

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	if (PGD_SIZE == PAGE_SIZE) {
		
		pgd_t *rtn = (pgd_t *)__get_free_page(PGALLOC_GFP | ___GFP_YMH_PTP | ___GFP_YMH_PTP_PGD);

		#ifdef YMH_USE_SEPARATE_BLOCKS
		addPgd((void *)rtn);
		#endif

		return rtn;
	}
	else
		return kmem_cache_alloc(pgd_cache, PGALLOC_GFP);
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (PGD_SIZE == PAGE_SIZE) {
		free_page((unsigned long)pgd);
	}
	else
		kmem_cache_free(pgd_cache, pgd);
}

void __init pgd_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}
