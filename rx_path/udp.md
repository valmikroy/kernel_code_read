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


If all good then pass it on to `__udp_queue_rcv_skb` which looks like
```c
int __udp_enqueue_schedule_skb(struct sock *sk, struct sk_buff *skb)
{
        
        // sk_receive_queue represents socket receive queue where skbs are lined up
        struct sk_buff_head *list = &sk->sk_receive_queue;

        / **** /
        
        // sk_rmem_alloc keep track of amount of memory allocated for socket 
        // above skbs in sk_receive_queue will get factored in sk_rmem_alloc
        // sk_rmem_alloc has sk_rcvbuf as upper threshold 
        
        rmem = atomic_read(&sk->sk_rmem_alloc);
        if (rmem > sk->sk_rcvbuf)
                goto drop;
        
        
        / **** /
       
       // start condensing if size is more than half of given threshold
        if (rmem > (sk->sk_rcvbuf >> 1)) {
                skb_condense(skb);

                busy = busylock_acquire(sk);
        }
        
        // this finds new skb's size in whole
        size = skb->truesize;

        / **** /
 
        // verify if above skb can be fit within allowed memory allocation
        
        rmem = atomic_add_return(size, &sk->sk_rmem_alloc);
        if (rmem > (size + sk->sk_rcvbuf))
                goto uncharge_drop;

        / **** /
                // This adds skb into receive queue of socket
                __skb_queue_tail(list, skb);
                
        / **** /
uncharge_drop:
        atomic_sub(skb->truesize, &sk->sk_rmem_alloc);

drop:
        atomic_inc(&sk->sk_drops);
        busylock_release(busy);
        return err;
}
```
This is where softirq context gets over.


#### __skb_recv_udp and udp_recvmsg

Later `udp_recvmsg` called as part of system call `read()` over UDP socket which will pass on control to  `__skb_recv_udp` which goes through socket received queue and walk through all SKB's to copy data to userspace and free those SKBs.

This takes place in process context


#### some stats update 
```
$ cat /proc/net/snmp | grep Udp\:
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 16314 0 0 17161 0 0
```
Much like the detailed statistics found in this file for the IP protocol, you will need to read the protocol layer source to determine exactly when and where these values are incremented.

- InDatagrams: Incremented when recvmsg was used by a userland program to read datagram. Also incremented when a UDP packet is encapsulated and sent back for processing.
- NoPorts: Incremented when UDP packets arrive destined for a port where no program is listening.
- InErrors: Incremented in several cases: no memory in the receive queue, when a bad checksum is seen, and if sk_add_backlog fails to add the datagram.
- OutDatagrams: Incremented when a UDP packet is handed down without error to the IP protocol layer to be sent.
- RcvbufErrors: Incremented when sock_queue_rcv_skb reports that no memory is available; this happens if sk->sk_rmem_alloc is greater than or equal to sk->sk_rcvbuf.
- SndbufErrors: Incremented if the IP protocol layer reported an error when trying to send the packet and no error queue has been setup. Also incremented if no send queue space or kernel memory are available.
- InCsumErrors: Incremented when a UDP checksum failure is detected. Note that in all cases I could find, InCsumErrors is incrememnted at the same time as InErrors. Thus, InErrors - InCsumErros should yield the count of memory related errors on the receive side.
