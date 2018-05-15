Handling of hardware interrupt in terms of `ixgbe` device driver. You can easily figure out function which handlers irq by tracing `IRQ_HANDLED`

- To handle RX hardware irq `ixgbe_msix_clean_rings` gets called 

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

`ixgbe_msix_clean_rings` gets registered as callback through `request_irq` which called through following callchain
```
ixgbe_open - triggered by ifconfig up 
 ixgbe_request_irq  
  ixgbe_request_msix_irqs
   request_irq - registers  ixgbe_msix_clean_rings for interrupt handling

```
