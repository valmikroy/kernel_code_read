Handling of hardware interrupt in terms of `ixgbe` device driver. You can easily figure out function which handlers irq by tracing `IRQ_HANDLED`

- Hardware interrupt handler `ixgbe_msix_clean_rings` gets registerd as callback through `request_irq` which called through following callchain
```
ixgbe_open - triggered by ifconfig up 
 ixgbe_request_irq  
  ixgbe_request_msix_irqs
   request_irq - registers  ixgbe_msix_clean_rings for interrupt handling

```



- When packet arrives on NIC , it get transfered to RX queue aka RX ring buffer via DMA and `ixgbe_msix_clean_rings` gets called which only schedules for napi poll and exits 

```c
static irqreturn_t ixgbe_msix_clean_rings(int irq, void *data)
{
        struct ixgbe_q_vector *q_vector = data;

        /* EIAM disabled interrupts (on this vector) for us */

        if (q_vector->rx.ring || q_vector->tx.ring)
                napi_schedule_irqoff(&q_vector->napi);

        return IRQ_HANDLED;
}
```

- NAPI processing gets triggered by h/w irq by calling `napi_schedule_irqoff(&q_vector->napi)` which runs in softirq context, compeltely outside of h/w irq. Over here NAPI poll gets called with `napi_struct` as argument which has attached to given RX ring buffer.

- succession of  `napi_schedule_irqoff`
```c
static inline void napi_schedule_irqoff(struct napi_struct *n)
{
        if (napi_schedule_prep(n))
                __napi_schedule_irqoff(n);
}
```
As shown above, it calls `napi_schedule_prep` which does few checks against `n->state` like if NAPI run is already running. Progressing through `__napi_schedule_irqoff` further it calls `____napi_schedule` with `struct softnet_data` for that CPU along with passed `napi_struct` attached to given ring buffer
```c
void __napi_schedule_irqoff(struct napi_struct *n)
{
        ____napi_schedule(this_cpu_ptr(&softnet_data), n);
}
EXPORT_SYMBOL(__napi_schedule_irqoff);
```

- `____napi_schedule`

We are still in h/w irq context and processing packet linked list (`napi->poll_list`) get merged with `softnet_data`'s poll list for that CPU with help of `list_add_tail` and softirq gets raised

```c
static inline void ____napi_schedule(struct softnet_data *sd,
                                     struct napi_struct *napi)
{
        list_add_tail(&napi->poll_list, &sd->poll_list);
        __raise_softirq_irqoff(NET_RX_SOFTIRQ);
}
```


