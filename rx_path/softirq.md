

- Softirq is managed as task attached per CPU to offload h/w irq work in following structure with element `struct task_struct *ksoftirqd`


```c
/*
 * CPU type, hardware bug flags, and per-CPU state.  Frequently used
 * state comes earlier:
 */
struct cpuinfo_ia64 {
        unsigned int softirq_pending;
        /* ..... */
        
        #XXX
        struct task_struct *ksoftirqd;  /* kernel softirq daemon for this CPU */

        /* ..... */
        
}
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
