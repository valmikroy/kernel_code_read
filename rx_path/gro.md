During softirq context `ixgbe_clean_rx_irq` gets executed as part of procesing packet one by one, where allocation of `skb`s happens. Once they allocated if GRO is enabled on NIC then kernel need to check with protocal layer to pass on any feedback to NIC layer.

GRO get trigged by `napi_gro_receive(napi_struct , skb)` via `ixgbe_rx_skb` and reaches to `dev_gro_receive` which formulates feedback from protocal layer analyzing each flag on packet.

```c
// loop from dev_gro_receive()

     rcu_read_lock();
        list_for_each_entry_rcu(ptype, head, list) {
                if (ptype->type != type || !ptype->callbacks.gro_receive)
                        continue;

                skb_set_network_header(skb, skb_gro_offset(skb));
                skb_reset_mac_len(skb);
                NAPI_GRO_CB(skb)->same_flow = 0;
                NAPI_GRO_CB(skb)->flush = skb_is_gso(skb) || skb_has_frag_list(skb);
                NAPI_GRO_CB(skb)->free = 0;
                NAPI_GRO_CB(skb)->encap_mark = 0;
                NAPI_GRO_CB(skb)->recursion_counter = 0;
                NAPI_GRO_CB(skb)->is_fou = 0;
                NAPI_GRO_CB(skb)->is_atomic = 1;
                NAPI_GRO_CB(skb)->gro_remcsum_start = 0;

                /* Setup for GRO checksum validation */
                switch (skb->ip_summed) {
                case CHECKSUM_COMPLETE:
                        NAPI_GRO_CB(skb)->csum = skb->csum;
                        NAPI_GRO_CB(skb)->csum_valid = 1;
                        NAPI_GRO_CB(skb)->csum_cnt = 0;
                        break;
                case CHECKSUM_UNNECESSARY:
                        NAPI_GRO_CB(skb)->csum_cnt = skb->csum_level + 1;
                        NAPI_GRO_CB(skb)->csum_valid = 0;
                        break;
                default:
                        NAPI_GRO_CB(skb)->csum_cnt = 0;
                        NAPI_GRO_CB(skb)->csum_valid = 0;
                }

                pp = ptype->callbacks.gro_receive(&napi->gro_list, skb);
                break;
        }
        rcu_read_unlock();
```
Above 
- `NAPI_GRO_CB` macros will check for for various flags 
- `ptype->callbacks.gro_receive(&napi->gro_list, skb)` line checks if GRO time to flush packet by checking all fragements has been assembled.
- if ready to flush then following loop gets executed to call `napi_gro_complete`
```c
        if (pp) {
                struct sk_buff *nskb = *pp;

                *pp = nskb->next;
                nskb->next = NULL;
                napi_gro_complete(nskb);
                napi->gro_count--;

```

