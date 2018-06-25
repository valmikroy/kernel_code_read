UDP layer handling functions are defined in `net/ipv4/udp.c`

#### net_protocol udp_protocol 
In `net/ipv4/af_inet.c` udp packet processing entry function defined 
```c
static struct net_protocol udp_protocol = {
        .early_demux =  udp_v4_early_demux,
        .early_demux_handler =  udp_v4_early_demux,
        .handler =      udp_rcv,
        .err_handler =  udp_err,
        .no_policy =    1,
        .netns_ok =     1,
};
```

#### __udp4_lib_rcv
`udp_rcv` calls `__udp4_lib_rcv` which first try to do `dst_entry` table lookup which has been setup and passed up by IP layer.
```c
        // dst_entry look up suceeds
        sk = skb_steal_sock(skb);
        if (sk) {
                struct dst_entry *dst = skb_dst(skb);
                
                / **** /

                ret = udp_queue_rcv_skb(sk, skb);
                sock_put(sk);
        }

        if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
                return __udp4_lib_mcast_deliver(net, skb, uh,
                                                saddr, daddr, udptable, proto);
        // dst_entry does NOT exists
        sk = __udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
        if (sk) {
                int ret;

                if (inet_get_convert_csum(sk) && uh->check && !IS_UDPLITE(sk))
                        skb_checksum_try_convert(skb, IPPROTO_UDP, uh->check,
                                                 inet_compute_pseudo);

                ret = udp_queue_rcv_skb(sk, skb);

             
                / **** /
        }

```

#### udp_queue_rcv_skb and __udp_queue_rcv_skb

`udp_queue_rcv_skb` will do three things
- check for encasulation if yes, pass packet up in stack
- UDP lite check 
- checksum check


