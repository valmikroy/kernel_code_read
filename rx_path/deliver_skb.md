
#### deliver_skb
Call for `deliver_skb` comes from `__netif_receive_skb_core` in form of two loops 
- on for taps , this is for packet capturing library, looks like below
```c
        // one for taps aka tcpdump
        list_for_each_entry_rcu(ptype, &ptype_all, list) {
                if (pt_prev)
                        ret = deliver_skb(skb, pt_prev, orig_dev);
                pt_prev = ptype;
        }

        // deliver packet to next protocol layer
        list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
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


#### IP layer functions
- Those protocal related function get added with help of `dev_add_pack` , for example IP protocal related function defined in `net/ipv4/af_inet.c`. Added by

```c

dev_add_pack(&ip_packet_type);

// where ip_packet_type is

static struct packet_type ip_packet_type __read_mostly = {
        .type = cpu_to_be16(ETH_P_IP),
        .func = ip_rcv,
};

```
above shows that `ip_rcv` is function pointer which called by `pt_prev->func` and defined in `net/ipv4/ip_input.c`

- `ip_rcv` will hand off packet to `ip_rcv_finish` via `NF_HOOK` as below
```c
        return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
                       net, NULL, skb, dev, NULL,
                       ip_rcv_finish);
```
`NF_HOOK` is where netfilter , iptables rules get applied on packet.

- `ip_rcv_finish` goes through optimization to determine routing table entry aka `dst_entry` for given packet which `early_demux` which shown some drop in througput and hasve provision to disable it with `net.ipv4.ip_early_demux`.

- somehow `ip_rcv_finish` manage to deliver call to `ip_local_deliver` which pass this packet after resembling to `ip_local_deliver_finish` via `NFHOOK`
```c
int ip_local_deliver(struct sk_buff *skb)
{
        /*
         *      Reassemble IP fragments.
         */
        struct net *net = dev_net(skb->dev);

        if (ip_is_fragment(ip_hdr(skb))) {
                if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
                        return 0;
        }

        return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
                       net, NULL, skb, skb->dev, NULL,
                       ip_local_deliver_finish);
}
```
- `ip_local_deliver_finish` will update metrics under `/proc/net/snmp` along with `/proc/net/netstat` with `IpExt` prefix.
```
IpExt:  InNoRoutes  InTruncatedPkts  InMcastPkts  OutMcastPkts  InBcastPkts  OutBcastPkts  InOctets   OutOctets  InMcastOctets  OutMcastOctets  InBcastOctets  OutBcastOctets  InCsumErrors  InNoECTPkts  InECT1Pkts  InECT0Pkts  InCEPkts
IpExt:  0           0                0            0             0            0             904786187  149846886  0              0               0              0               0             802979       0           21726       0
```

   - `InReceives` - total packets reached `ip_rcv` before any intigrity checks
   - `InHdrErrors` - currupted headers
   - `InAddrErrors` - address unreachable, `dst_entry` not found 
   - `ForwDatagrams` - forwarded packets
   - `InUnknownProtos` - packet which does not have valid function pointer at `pt_prev->func`
   - `InDiscards` - discaded due to mem allocation or cheksum failure when packets are trimmed
   - `InDelivers` - passed packet to protcol layer
   - `InCsumErrors` - packets with checksum errors
