`net_rx_action` is entry point for softirq of network packet processing.

```c
static __latent_entropy void net_rx_action(struct softirq_action *h)
{
        struct softnet_data *sd = this_cpu_ptr(&softnet_data);
        unsigned long time_limit = jiffies +
                usecs_to_jiffies(netdev_budget_usecs);
        int budget = netdev_budget;
        LIST_HEAD(list);
        LIST_HEAD(repoll);

        local_irq_disable();
        list_splice_init(&sd->poll_list, &list);
        local_irq_enable();

        for (;;) {
                struct napi_struct *n;

                if (list_empty(&list)) {
                        if (!sd_has_rps_ipi_waiting(sd) && list_empty(&repoll))
                                goto out;
                        break;
                }

                n = list_first_entry(&list, struct napi_struct, poll_list);
                budget -= napi_poll(n, &repoll);

                /* If softirq window is exhausted then punt.
                 * Allow this to run for 2 jiffies since which will allow
                 * an average latency of 1.5/HZ.
                 */
                if (unlikely(budget <= 0 ||
                             time_after_eq(jiffies, time_limit))) {
                        sd->time_squeeze++;
                        break;
                }
        }

        local_irq_disable();

        list_splice_tail_init(&sd->poll_list, &list);
        list_splice_tail(&repoll, &list);
        list_splice(&list, &sd->poll_list);
        if (!list_empty(&sd->poll_list))
                __raise_softirq_irqoff(NET_RX_SOFTIRQ);

        net_rps_action_and_irq_enable(sd);
out:
        __kfree_skb_flush();
}
```
