

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

static int __init net_dev_init(void)
{
        /* ..... */

        open_softirq(NET_TX_SOFTIRQ, net_tx_action);
        open_softirq(NET_RX_SOFTIRQ, net_rx_action);

        /* ..... */

}
```
- accounting of softirq is publish by `account_irq_exit_time(current)` under `/proc/softirqs`

- One more pass at `net_dev_init` and related `softnet_data` elements
 

```c
static int __init net_dev_init(void)
{

        /* ..... */

        for_each_possible_cpu(i) {
                /*
                 work_struct is part of workqueue interface,  
                 it defines actions to execute in softirq interface
                */
                struct work_struct *flush = per_cpu_ptr(&flush_works, i);
                
                /*
                 softnet_data gets defined for each cpu
                */
                struct softnet_data *sd = &per_cpu(softnet_data, i);

                
                INIT_WORK(flush, flush_backlog); /* provision to flush net device in case of turning it down */

                /*
                 - struct sk_buff_head     input_pkt_queue;
                 - input_pkt_queue keeps track of unprocessed packets which came from NIC
                 - input_pkt_queue has upper limit defined by net.core.netdev_max_backlog 
                */
                skb_queue_head_init(&sd->input_pkt_queue); 
                
                /*
                 - struct sk_buff_head     process_queue; 
                 - this defines backlog of packets
                 - eventually they will be pushed to IP layer space with process_backlog() -> deliver_skb()
                */
                skb_queue_head_init(&sd->process_queue);   // 
                INIT_LIST_HEAD(&sd->poll_list);
                sd->output_queue_tailp = &sd->output_queue;
#ifdef CONFIG_RPS
                sd->csd.func = rps_trigger_softirq;
                sd->csd.info = sd;
                sd->cpu = i;
#endif

                sd->backlog.poll = process_backlog;
                sd->backlog.weight = weight_p;
        }

        /* ..... */


}

```
