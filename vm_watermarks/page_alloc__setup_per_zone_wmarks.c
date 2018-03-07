
/**
Code read of 4.13 linux kernel on how watermarks get calculate
Code does various watermark calculation which can be seen in form of google sheet below
https://docs.google.com/spreadsheets/d/1FBHGPk6p0uui7Ned5mzWQHHa9nFDD329PijRW_kXB6A/edit#gid=576868409
**/






/**
 * setup_per_zone_wmarks - called when min_free_kbytes changes
 * or when memory is hot-{added|removed}
 *
 * Ensures that the watermark[min,low,high] values for each zone are set
 * correctly with respect to min_free_kbytes.
 */
void setup_per_zone_wmarks(void)
{
        mutex_lock(&zonelists_mutex);
        __setup_per_zone_wmarks();
        mutex_unlock(&zonelists_mutex);
}






static void __setup_per_zone_wmarks(void)
{

/** 

arch/x86/include/asm/page_types.h

#define PAGE_SHIFT    12 

this means 2^12 = 4096 which is page size on x86 architecture 

**/



/**

Right shift bitwise operator can be used to do divide by 2

i = 14; // Bit pattern 00001110
j = i >> 1; // here we have the bit pattern shifted by 1 thus we get 00000111 = 7 which is 14/2

each binary position shift represent division by power of 2 

j >> 1 == j/2
j >> 2 == j/4
j >> 3 == j/8


inverse of division is multipleication which holds true for left shift operator 

int i = 4; // bit pattern equivalent is binary 100 
int j = i << 2; // makes it binary 10000, which multiplies the original number by 4 i.e. 16 

**/

        // divided by 4  ( 12-10 = 2, so 2^2 = 4)
        // this is just convering memory size into 4k pages
        unsigned long pages_min = min_free_kbytes >> (PAGE_SHIFT - 10); 
        // pages_min == min_free_kbytes in 4k page count


        unsigned long lowmem_pages = 0;

        /**
        struct zone  is defined in include/linux/mmzone.h

        **/

        struct zone *zone;
        unsigned long flags;

        /* Calculate total number of !ZONE_HIGHMEM pages */
        for_each_zone(zone) {
                if (!is_highmem(zone)) // check for older memory hardware on x86
                        // count all zone managed pages (which do not include reserved pages)
                        lowmem_pages += zone->managed_pages;
        }

        for_each_zone(zone) {
                u64 tmp;

                spin_lock_irqsave(&zone->lock, flags);

                // pages_min multiplied by zone managed pages
                // which gets divided by managed page counts in all zones
                tmp = (u64)pages_min * zone->managed_pages;


                // do_div(a,b) will do a/b and store quotient in a and returns denominator 
                do_div(tmp, lowmem_pages);


                if (is_highmem(zone)) {
                        /*
                         * __GFP_HIGH and PF_MEMALLOC allocations usually don't
                         * need highmem pages, so cap pages_min to a small
                         * value here.
                         *
                         * The WMARK_HIGH-WMARK_LOW and (WMARK_LOW-WMARK_MIN)
                         * deltas control asynch page reclaim, and so should
                         * not be capped for highmem.
                         */
                        unsigned long min_pages;

                        min_pages = zone->managed_pages / 1024;
                        min_pages = clamp(min_pages, SWAP_CLUSTER_MAX, 128UL);
                        zone->watermark[WMARK_MIN] = min_pages;
                } else {
                        /*
                         * If it's a lowmem zone, reserve a number of pages
                         * proportionate to the zone's size.
                         */



                         /**
                         Lower watermark for this zone will be 
                         page_min * pages managed by this zone / (sum of managed pages in all zones)
                         **/
                        zone->watermark[WMARK_MIN] = tmp;
                }


                /*
                 * Set the kswapd watermarks distance according to the
                 * scale factor in proportion to available memory, but
                 * ensure a minimum size on small systems.
                 */


                // max_t macro defined in tools/vm/page-types.c , its signed comapre and return max

                // multi_frac defined in include/linux/kernel.h
                // multi_frac(a,b,c) = (a * b)/c



                // watermark_scale_factor = 10 defined above but configurable by sysctl 
                // scale factor can move LOW and HIGHT watermark calculation depedency from 
                // min_free_kbytes to managed pages in that zone. (observed in 4.13 was not in 4.4)


                /**
                tmp is getting set for whichever is max value out of 
                - tmp / 4 
                - managed pages * 0.001
                **/ 

                tmp = max_t(u64, tmp >> 2,
                            mult_frac(zone->managed_pages,
                                      watermark_scale_factor, 10000));

                /** this is where low and high get set where
                - original tmp was page_min * pages managed by this zone / (sum of managed pages in all zones)
                - above WMARK_MIN = tmp
                - WMARK_LOW = WMARK_MIN + max(tmp/4 , managed pages * 0.001
                - WMARK_HIGH = WMARK_MIN + max(tmp/4 , managed pages * 0.001) *  2
                **/
                
                zone->watermark[WMARK_LOW]  = min_wmark_pages(zone) + tmp;
                zone->watermark[WMARK_HIGH] = min_wmark_pages(zone) + tmp * 2;

                spin_unlock_irqrestore(&zone->lock, flags);
        }

        /* update totalreserve_pages */
        calculate_totalreserve_pages();
}





/*
 * setup_per_zone_lowmem_reserve - called whenever
 *      sysctl_lowmem_reserve_ratio changes.  Ensures that each zone
 *      has a correct pages reserved value, so an adequate number of
 *      pages are left in the zone after a successful __alloc_pages().
 */


/*
* note that 
*
*
*/
static void setup_per_zone_lowmem_reserve(void)
{

       /*
        * pglist_data defined in include/linux/mmzone.h 
        * each pglist_data structure defines mem page layout
        * for each zone.
        * 
        *
        * pglist_data has assigned per NUMA node
        *
        *
        *
        *
        */
        struct pglist_data *pgdat;
        enum zone_type j, idx;

        // Iterate through each NUMA
        for_each_online_pgdat(pgdat) {


                // Following loop through zones on given NUMA node
                for (j = 0; j < MAX_NR_ZONES; j++) {


                        /*
                        * struct zone is defined in include/linux/mmzone.h
                        * 
                        * lowmem_reserve[] used from zone structure is an array with size 5
                        * and lowmem_reserve[0] is always zero
                        * this keeps protection page count for each zone
                        *
                        *
                        */
                        // this might be pulling zone
                        struct zone *zone = pgdat->node_zones + j;
                        unsigned long managed_pages = zone->managed_pages;

                        // initialize here to get it used by while (idx) loop

                        zone->lowmem_reserve[j] = 0;

                        // idx=j because digits in  sysctl_lowmem_reserve_ratio and
                        // number of zones are the same 
                        
                        idx = j;



                        /*
                        *  Lets take example of vm.lowmem_reserve_ratio = 256   256     32      1
                        *  zone , size  , spanned , present, managed 
                        *  ZONE_DMA , 16M , 4095 , 3993 , 3972
                        *  ZONE_DMA32 , 4G , 1044480 , 492878 , 476486 
                        *  ZONE_Normal0, 30G, 7864320, 7864320, 7728372
                        *  ZONE_Normal1, 32G, 8388608, 8388608, 8256805

                           * spanned_pages is the total pages spanned by the zone, including
                           * holes, which is calculated as:
                           *      spanned_pages = zone_end_pfn - zone_start_pfn;
                           *
                           * present_pages is physical pages existing within the zone, which
                           * is calculated as:
                           *      present_pages = spanned_pages - absent_pages(pages in holes);
                           *
                           * managed_pages is present pages managed by the buddy system, which
                           * is calculated as (reserved_pages includes pages allocated by the
                           * bootmem allocator):
                           *      managed_pages = present_pages - reserved_pages;
                           *
                           * So present_pages may be used by memory hotplug or memory power
                           * management logic to figure out unmanaged pages by checking
                           * (present_pages - managed_pages). And managed_pages should be used
                           * by page allocator and vm scanner to calculate all kinds of watermarks
                           * and thresholds.
                        */



                        /*
                                when idx = j = 0 following while loop never get executed
                        */


                        /*

                                when idx = j = 1
                                sysctl_lowmem_reserve_ratio[0] = 256
                                
                                lower_zone = ZONE_DMA
                                zone tracked by j = ZONE_DMA32
                                ZONE_DMA.lowmem_reserve[1] = DMA32 476486 / 256 =  1861        

                                 managed_pages = 476486 + 3972 = 480458

                        */

                        /*
                                when idx = j = 2 
                                 sysctl_lowmem_reserve_ratio[1] = 256
                                 lower_zone = ZONE_DMA32
                                 zone tracked by j ZONE_NORMAL0
                                 
                                 ZONE_DMA32.lowmem_reserve[2] = 7728372/256 = 30188


                                managed_pages = 7728372 + 476486 = 8204858


                                idx-- 
                                lower_zone = ZONE_DMA
                                zone tracked by j ZONE_NORMAL0
                                ZONE_DMA.lowmem_reserve[2] = 8204858 / 256 =  32050        
                                

                        */

                        /*

                                when idx = j = 2 
                                 sysctl_lowmem_reserve_ratio[2] = 32
                                lower_zone = NORMAL0
                                

                                both above numbers 30188 and 32050 stays constant after this becaue lower zone becomes NORMAL
                                
                        */

                        





                        while (idx) {
                                struct zone *lower_zone;

                                idx--;

                                if (sysctl_lowmem_reserve_ratio[idx] < 1)
                                        sysctl_lowmem_reserve_ratio[idx] = 1;

                                lower_zone = pgdat->node_zones + idx;
                                
                                lower_zone->lowmem_reserve[j] = managed_pages /
                                        sysctl_lowmem_reserve_ratio[idx];


                                // and you up managed pages of above zone by number of managed pages of lower zone
                                managed_pages += lower_zone->managed_pages;
                        }
                }


        }

        /* update totalreserve_pages */
        calculate_totalreserve_pages();
}





static void calculate_totalreserve_pages(void)
{
        struct pglist_data *pgdat;
        unsigned long reserve_pages = 0;
        enum zone_type i, j;

        for_each_online_pgdat(pgdat) {

                pgdat->totalreserve_pages = 0;

                for (i = 0; i < MAX_NR_ZONES; i++) {
                        struct zone *zone = pgdat->node_zones + i;
                        long max = 0;

                        /* Find valid and maximum lowmem_reserve in the zone */
                        for (j = i; j < MAX_NR_ZONES; j++) {
                                if (zone->lowmem_reserve[j] > max)
                                        max = zone->lowmem_reserve[j];
                        }

                        /* we treat the high watermark as reserved pages. */
                        max += high_wmark_pages(zone);

                        if (max > zone->managed_pages)
                                max = zone->managed_pages;

                        pgdat->totalreserve_pages += max;

                        reserve_pages += max;
                }
        }
        totalreserve_pages = reserve_pages;
}

