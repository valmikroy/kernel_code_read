### `net_dev_init` and related `softnet_data` elements
`subsys_initcall(net_dev_init);` at the end of `net/core/dev.c` suggests that `net_dev_init` get called at boot time.



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

                /* 
                 provision to flush net device in case of turning it down 
                */
                INIT_WORK(flush, flush_backlog); 


                skb_queue_head_init(&sd->input_pkt_queue); 
                

                skb_queue_head_init(&sd->process_queue);   
                
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
- `skb_queue_head_init(&sd->input_pkt_queue);`
   - `struct sk_buff_head     input_pkt_queue;`
   - input_pkt_queue keeps track of unprocessed packets which came from NIC
   - input_pkt_queue has upper limit defined by net.core.netdev_max_backlog 
   
   
- `skb_queue_head_init(&sd->process_queue);`
   - `struct sk_buff_head     process_queue;`
   - this defines backlog of packets
   - eventually they will be pushed to IP layer space through `process_backlog()` -> `deliver_skb()`
   - looks at `sd->backlog.poll = process_backlog;` which used to process `sd->process_queue`
       
   
- `INIT_LIST_HEAD(&sd->poll_list);`
   - `struct list_head        poll_list;`
   - `poll_list` present in both `softnet_data` and `napi_struct` 
   - during `napi_poll` execution `napi_struct`'s `poll_list` get appended to `softnet_data`'s  

- `sd->backlog.weight = weight_p;`
napi poll device weight gets assigned here 

- `sd->csd.func = rps_trigger_softirq;`
   - this function used by `net_rps_send_ipi` to act upon `*rps_ipi_next` `softnet_data` pointer inside given `sd`. This is how RPS has been implemented where each `sd` keeps track of packet's own hash calculated CPU and send RPI with `rps_ipi_next`  

