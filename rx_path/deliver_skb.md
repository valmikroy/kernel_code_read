Call for `deliver_skb` comes from `__netif_receive_skb_core` in form of two loops 
- on for taps , this is for packet capturing library, looks like below
```c
        list_for_each_entry_rcu(ptype, &ptype_all, list) {
                if (pt_prev)
                        ret = deliver_skb(skb, pt_prev, orig_dev);
                pt_prev = ptype;
        }
```
- packet get pushed to layer above either by `deliver_skb` or direct call to `pt_prev->func`

- `deliver_skb` looks like as follows
```c
static inline int deliver_skb(struct sk_buff *skb,
                              struct packet_type *pt_prev,
                              struct net_device *orig_dev)
{
        if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC)))
                return -ENOMEM;
        refcount_inc(&skb->users);
        return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}
```

If you look at last line, `packet_type` has pointer to function which does protocol specific steps.

- Those protocal related function get added with help of `dev_add_pack` , for example IP protocal related function defined in `net/ipv4/af_inet.c`. Added by

```c

dev_add_pack(&ip_packet_type);

// where ip_packet_type is

static struct packet_type ip_packet_type __read_mostly = {
        .type = cpu_to_be16(ETH_P_IP),
        .func = ip_rcv,
};

```
above shows that `ip_rcv` is function pointer which called by `pt_prev->func`

- `ip_rcv` will hand off packet to `ip_rcv_finish` via `NF_HOOK` as below
```c
        return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
                       net, NULL, skb, dev, NULL,
                       ip_rcv_finish);
```
`NF_HOOK` is where netfilter , iptables rules get applied on packet.


