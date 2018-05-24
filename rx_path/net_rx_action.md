`net_rx_action` is entry point for softirq of network packet processing.

-
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

- 
```c
static int napi_poll(struct napi_struct *n, struct list_head *repoll)
{
        void *have;
        int work, weight;

        list_del_init(&n->poll_list);

        have = netpoll_poll_lock(n);

        weight = n->weight;

        /* This NAPI_STATE_SCHED test is for avoiding a race
         * with netpoll's poll_napi().  Only the entity which
         * obtains the lock and sees NAPI_STATE_SCHED set will
         * actually make the ->poll() call.  Therefore we avoid
         * accidentally calling ->poll() when NAPI is not scheduled.
         */
        work = 0;
        if (test_bit(NAPI_STATE_SCHED, &n->state)) {
                work = n->poll(n, weight);
                trace_napi_poll(n, work, weight);
        }

        WARN_ON_ONCE(work > weight);

        if (likely(work < weight))
                goto out_unlock;

        /* Drivers must not modify the NAPI state if they
         * consume the entire weight.  In such cases this code
         * still "owns" the NAPI instance and therefore can
         * move the instance around on the list at-will.
         */
        if (unlikely(napi_disable_pending(n))) {
                napi_complete(n);
                goto out_unlock;
        }

        if (n->gro_list) {
                /* flush too old packets
                 * If HZ < 1000, flush all packets.
                 */
                napi_gro_flush(n, HZ >= 1000);
        }

        /* Some drivers may have called napi_schedule
         * prior to exhausting their budget.
         */
        if (unlikely(!list_empty(&n->poll_list))) {
                pr_warn_once("%s: Budget exhausted after napi rescheduled\n",
                             n->dev ? n->dev->name : "backlog");
                goto out_unlock;
        }

        list_add_tail(&n->poll_list, repoll);

out_unlock:
        netpoll_poll_unlock(have);

        return work;
}
```

-
```c
/**
 * ixgbe_poll - NAPI Rx polling callback
 * @napi: structure for representing this polling device
 * @budget: how many packets driver is allowed to clean
 *
 * This function is used for legacy and MSI, NAPI mode
 **/
int ixgbe_poll(struct napi_struct *napi, int budget)
{
        struct ixgbe_q_vector *q_vector =
                                container_of(napi, struct ixgbe_q_vector, napi);
        struct ixgbe_adapter *adapter = q_vector->adapter;
        struct ixgbe_ring *ring;
        int per_ring_budget, work_done = 0;
        bool clean_complete = true;

#ifdef CONFIG_IXGBE_DCA
        if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
                ixgbe_update_dca(q_vector);
#endif

        ixgbe_for_each_ring(ring, q_vector->tx) {
                if (!ixgbe_clean_tx_irq(q_vector, ring, budget))
                        clean_complete = false;
        }

        /* Exit if we are called by netpoll */
        if (budget <= 0)
                return budget;

        /* attempt to distribute budget to each queue fairly, but don't allow
         * the budget to go below 1 because we'll exit polling */
        if (q_vector->rx.count > 1)
                per_ring_budget = max(budget/q_vector->rx.count, 1);
        else
                per_ring_budget = budget;

        ixgbe_for_each_ring(ring, q_vector->rx) {
                int cleaned = ixgbe_clean_rx_irq(q_vector, ring,
                                                 per_ring_budget);

                work_done += cleaned;
                if (cleaned >= per_ring_budget)
                        clean_complete = false;
        }

        /* If all work not completed, return budget and keep polling */
        if (!clean_complete)
                return budget;

        /* all work done, exit the polling mode */
        napi_complete_done(napi, work_done);
        if (adapter->rx_itr_setting & 1)
                ixgbe_set_itr(q_vector);
        if (!test_bit(__IXGBE_DOWN, &adapter->state))
                ixgbe_irq_enable_queues(adapter, BIT_ULL(q_vector->v_idx));

        return min(work_done, budget - 1);
}

```

```c
struct ixgbe_q_vector {
        struct ixgbe_adapter *adapter;
#ifdef CONFIG_IXGBE_DCA
        int cpu;            /* CPU for DCA */
#endif
        u16 v_idx;              /* index of q_vector within array, also used for
                                 * finding the bit in EICR and friends that
                                 * represents the vector for this ring */
        u16 itr;                /* Interrupt throttle rate written to EITR */
        struct ixgbe_ring_container rx, tx;

        struct napi_struct napi;
        cpumask_t affinity_mask;
        int numa_node;
        struct rcu_head rcu;    /* to avoid race with update stats on free */
        char name[IFNAMSIZ + 9];

        /* for dynamic allocation of rings associated with this q_vector */
        struct ixgbe_ring ring[0] ____cacheline_internodealigned_in_smp;
};
```
