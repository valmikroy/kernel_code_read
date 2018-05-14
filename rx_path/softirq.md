

- Softirq is managed as task attached per CPU to offload h/w irq work in following structure with element `struct task_struct *ksoftirqd`


```c
/*
 * CPU type, hardware bug flags, and per-CPU state.  Frequently used
 * state comes earlier:
 */
struct cpuinfo_ia64 {
        unsigned int softirq_pending;
        unsigned long itm_delta;        /* # of clock cycles between clock ticks */
        unsigned long itm_next;         /* interval timer mask value to use for next clock tick */
        unsigned long nsec_per_cyc;     /* (1000000000<<IA64_NSEC_PER_CYC_SHIFT)/itc_freq */
        unsigned long unimpl_va_mask;   /* mask of unimplemented virtual address bits (from PAL) */
        unsigned long unimpl_pa_mask;   /* mask of unimplemented physical address bits (from PAL) */
        unsigned long itc_freq;         /* frequency of ITC counter */
        unsigned long proc_freq;        /* frequency of processor */
        unsigned long cyc_per_usec;     /* itc_freq/1000000 */
        unsigned long ptce_base;
        unsigned int ptce_count[2];
        unsigned int ptce_stride[2];
        
        #XXX
        struct task_struct *ksoftirqd;  /* kernel softirq daemon for this CPU */



#ifdef CONFIG_SMP
        unsigned long loops_per_jiffy;
        int cpu;
        unsigned int socket_id; /* physical processor socket id */
        unsigned short core_id; /* core id */
        unsigned short thread_id; /* thread id */
        unsigned short num_log; /* Total number of logical processors on
                                 * this socket that were successfully booted */
        unsigned char cores_per_socket; /* Cores per processor socket */
        unsigned char threads_per_core; /* Threads per core */
#endif

        /* CPUID-derived information: */
        unsigned long ppn;
        unsigned long features;
        unsigned char number;
        unsigned char revision;
        unsigned char model;
        unsigned char family;
        unsigned char archrev;
        char vendor[16];
        char *model_name;

#ifdef CONFIG_NUMA
        struct ia64_node_data *node_data;
#endif
};
```

- `ksoftirqd_should_run` to detect pending softirqs and `run_ksoftirqd` to run upon pending softirq detected.  `run_ksoftirqd` eventually end up calling `__do_softirq`

```c
static struct smp_hotplug_thread softirq_threads = {
        .store                  = &ksoftirqd,           // XXX somehow this leaks out of above `struct cpuinfo_ia64`
      
        .thread_should_run      = ksoftirqd_should_run, // XXX  check if any softirq is pending or not
        
        .thread_fn              = run_ksoftirqd,        // XXX  run this function if above ksoftirqd_should_run detects pending softirqs
        .thread_comm            = "ksoftirqd/%u",
};
```
- `__do_softirq` 
   - figures if any softirq pending with `local_softirq_pending` 
   - and use the count to loop through each pending list of softirq task which is defined as `static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp`
   - and every element of array is `struct softirq_action` which has `*action` pointer which get called as execution of softirq task
   - `open_softirq` is place where above `*action` pointer get registered, for example
```c

# net/core/dev.c

open_softirq(NET_TX_SOFTIRQ, net_tx_action);

/* ..... */

open_softirq(NET_RX_SOFTIRQ, net_rx_action);

```
