

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

