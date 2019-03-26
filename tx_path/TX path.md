# TX path

- system call `sendto` , `sendmsg` called on socket FD
- socket subsystem for protocal family , here `AF_INET`
- protocal family will arrange data into packets
- packets pass through routing layer, poulating all routing caches and ARP queries
- from protocol layer to device agnostic layer 
- I think XPS gets chosen, that means which CPU to process this packet
- Called device driver transmit function 
- Hits queue discipline of a the device
- data goes to driver space from qdisc 
- driver create DMA mapping and does a transfer to RAM
- driver signals the device for readieness of transmission, device fetches data from RAM and transmits it
- once transmission is complete it raises interrupt
- on successful transmission , driver triggers NAPI poll loop to start `NET_RX`
- poll function runs through `NET_RX` to unmap DMA regions and free packet data





UDP socket call in userspace will look like following 

```
sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
```

AF_INET family covers protocol stacks like 

- TCP
- UDP
- ICMP
- RAW

Above registration happens through `inet_init` in `net/ipv4/af_inet.c` which calls `(void)sock_register(&inet_family_ops)` and given `inet_family_ops` has 

```
static const struct net_proto_family inet_family_ops = {
  .family = PF_INET,
  .create = inet_create,
  .owner  = THIS_MODULE,
};
```

AF and PF notations has no difference , check  ` #define PF_INET   AF_INET` in `include/linux/socket.h`  

At the time of socket creation `inet_create` gets called which goes through all availble protocols and pick up matching one to pick up registered operations for given protocol families like TCP, UDP and others. 

```
static int inet_create(struct net *net, struct socket *sock, int protocol,
           int kern)
{

/* snip */


  /* Look for the requested type/protocol pair. */
lookup_protocol:
  err = -ESOCKTNOSUPPORT;
  rcu_read_lock();
  list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {

    err = 0;
    /* Check the non-wild match. */
    if (protocol == answer->protocol) {
      if (protocol != IPPROTO_IP)
        break;
    } else {
      /* Check for the two wild cases. */
      if (IPPROTO_IP == protocol) {
        protocol = answer->protocol;
        break;
      }
      if (IPPROTO_IP == answer->protocol)
        break;
    }
    err = -EPROTONOSUPPORT;
  }

/* snip */

  sock->ops = answer->ops;
  answer_prot = answer->prot;
  answer_flags = answer->flags;
  rcu_read_unlock();

/* snip */

}
```





Operations for each protocol family are defined in form of struct `inet_protosw` and there is array  of structures as below in `net/ipv4/af_inet.c`

``` 
static struct inet_protosw inetsw_array[] =
{
  {
    .type =       SOCK_STREAM,
    .protocol =   IPPROTO_TCP,
    .prot =       &tcp_prot,
    .ops =        &inet_stream_ops,
    .flags =      INET_PROTOSW_PERMANENT |
            INET_PROTOSW_ICSK,
  },

  {
    .type =       SOCK_DGRAM,
    .protocol =   IPPROTO_UDP,
    .prot =       &udp_prot,
    .ops =        &inet_dgram_ops,
    .flags =      INET_PROTOSW_PERMANENT,
       },
/* snip */

};
```

and if you follow someting like `inet_dgram_ops` among those clusters in same file , you will get IP ops struct `proto_ops` as well as protocol ops struct `proto` 

```
const struct proto_ops inet_dgram_ops = {

/* snip */

  .sendmsg     = inet_sendmsg,
  .recvmsg     = inet_recvmsg,

/* snip */


};


struct proto udp_prot = {
/* snip */

  .sendmsg     = udp_sendmsg,
  .recvmsg     = udp_recvmsg,

/* snip */
};

```



In case of UDP when following gets called to write data on the socket

`ret = sendto(socket, buffer, buflen, 0, &dest, sizeof(dest));`

Then system call `sendto` defined inside `net/socket.c`  

```
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
    unsigned int, flags, struct sockaddr __user *, addr,
    int, addr_len)
{
  /* snip */

  err = sock_sendmsg(sock, &msg);

  /* snip */

}
```

which calls `sock_sendmsg` , through chain of wrapper calls this reaches to `sock_sendmsg_nosec`

```
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
  int ret = sock->ops->sendmsg(sock, msg, msg_data_left(msg));
  BUG_ON(ret == -EIOCBQUEUED);
  return ret;
} 
```

Here `sock->ops->sendmsg` gets utilize which was setup in `inet_create` , where its setup as `inet_sendmsg` by struct `inet_dgram_ops`.

If you look at `inet_sendmsg` which is same for all protocols under `AF_INET`

```
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
  struct sock *sk = sock->sk;

  sock_rps_record_flow(sk);
  /* snip */
  
  return sk->sk_prot->sendmsg(sk, msg, size);
}
```

`sk->sk_prot->sendmsg` is mapped to `udp_sendmsg`  from proto ops structure (I do not know where this mapping happens).



Note on `likely` and `unlikely` macros inside kernel

```
if (unlikely(fd < 0))
{
    /* Do something */
}

if (likely(!err))
{
    /* Do something */
}

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

They are hint to the compiler to emit instructions that will cause branch prediction to favour the "likely" side of a jump instruction. This can be a big win, if the prediction is correct it means that the jump instruction is basically free and will take zero cycles. On the other hand if the prediction is wrong, then it means the processor pipeline needs to be flushed and it can cost several cycles. So long as the prediction is correct most of the time, this will tend to be good for performance.

Like all such performance optimisations you should only do it after extensive profiling to ensure the code really is in a bottleneck, and probably given the micro nature, that it is being run in a tight loop. Generally the Linux developers are pretty experienced so I would imagine they would have done that. They don't really care too much about portability as they only target gcc, and they have a very close idea of the assembly they want it to generate.
```


## UDP layer

`udp_sendmsg` introduce corking of packets where packets get buffered until it reaches to the max size of `sk->sk_write_queue` . 

Corking can be setup with two conditions
- using `setsockopt` systemcall to pass `UDP_CORK` as the socket option
- pass `MSG_MORE` as one of the flags when calling `send`, `sendto` or `sendmsg`


Lets go through the code fragments from `net/ipv4/udp.c`

```
int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
  struct inet_sock *inet = inet_sk(sk);
  struct udp_sock  *up = udp_sk(sk);

/* snip */


  if (up->pending) {
    /*   
     * There are pending frames.
     * The socket lock must be held while it's corked.
     */
    lock_sock(sk);
    if (likely(up->pending)) {
      if (unlikely(up->pending != AF_INET)) {
        release_sock(sk);
        return -EINVAL;
      }    
      goto do_append_data;
    }    
    release_sock(sk);
  }

/* snip */


do_append_data:
  up->len += ulen;
  err = ip_append_data(sk, fl4, getfrag, msg, ulen,
           sizeof(struct udphdr), &ipc, &rt,
           corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
  if (err)
    udp_flush_pending_frames(sk);
  else if (!corkreq)
    err = udp_push_pending_frames(sk);
  else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
    up->pending = 0;
  release_sock(sk);
  
/* snip */


}
  
```



If you look at `ip_append_data` which calls `__ip_append_data` after some checks in following form

```
  return __ip_append_data(sk, fl4, &sk->sk_write_queue, &inet->cork.base,
        sk_page_frag(sk), getfrag,
        from, length, transhdrlen, flags);
        
```



Max amount of data which can be queued is size of `sk->sk_write_queue` which is goverened by `net.core.wmem_max` and `net.core.wmem_default`and can be customized with `SO_SNDBUFFORCE` flag in `setsockopt` with application has `CAP_NET_ADMIN` capabilities.



Routing to destination address get fetched from the cache if socket is opened before, we refer it as a fast path

```
// From userspace sendto gets called as below which reaches to udp_sendmsg 
ret = sendto(socket, buffer, buflen, 0, &dest, sizeof(dest));


int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{

  struct inet_sock *inet = inet_sk(sk);
  struct rtable *rt = NULL;
  int connected = 0;

  __be32 daddr, faddr, saddr;
  __be16 dport;

   /* snip */


  /*
   *  Get and verify the address.
   */
  if (msg->msg_name) {
    DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
    if (msg->msg_namelen < sizeof(*usin))
      return -EINVAL;
    if (usin->sin_family != AF_INET) {
      if (usin->sin_family != AF_UNSPEC)
        return -EAFNOSUPPORT;
    }

    daddr = usin->sin_addr.s_addr;
    dport = usin->sin_port;
    if (dport == 0)
      return -EINVAL;
  } else {
    if (sk->sk_state != TCP_ESTABLISHED)
      return -EDESTADDRREQ;
    daddr = inet->inet_daddr;
    dport = inet->inet_dport;
    /* Open fast path for connected socket.
       Route will not be used, if at least one option is set.
     */
    connected = 1;
  }
      
      
    /* snip */


    if (connected)
    	rt = (struct rtable *)sk_dst_check(sk, 0);


    /* snip */

}
```



Next, the source address, device index, and any timestamping options which were set on the socket (like `SOCK_TIMESTAMPING_TX_HARDWARE`, `SOCK_TIMESTAMPING_TX_SOFTWARE`,` SOCK_WIFI_STATUS`) are retrieved and stored:

```
ipc.addr = inet->inet_saddr;
ipc.oif = sk->sk_bound_dev_if;
sock_tx_timestamp(sk, &ipc.tx_flags);
```



Source address information along with packet level tune up parameters like `ttl` and `tos` can be setup on per packet by calling `ip_cmsg_send` on each packet like following 

```
  if (msg->msg_controllen) {
    err = ip_cmsg_send(sk, msg, &ipc, sk->sk_family == AF_INET6);
    if (unlikely(err)) {
      kfree(ipc.opt);
      return err;
    }
    if (ipc.opt)
      free = 1;
    connected = 0;
  }
```

Above `ip_cmsg_send`  pasrses auxillary infromation provided by `struct msghdr *msg` in the form of  `struct in_pktinfo`  , if such options are not present then current socket options will be used which present in `inet` of given socket as following

```if (!ipc.opt) {
  if (!ipc.opt) {
    struct ip_options_rcu *inet_opt;
      
    rcu_read_lock();
    inet_opt = rcu_dereference(inet->inet_opt);
    if (inet_opt) {
      memcpy(&opt_copy, inet_opt,
             sizeof(*inet_opt) + inet_opt->opt.optlen);
      ipc.opt = &opt_copy.opt;
    } 
    rcu_read_unlock();
  }     
```

If SRR (IP Strict Source Route) bit is set then it notes down address of first router  as `faddr` and marked socket as not connected

```
what is SRR?

Strict Source Routing allows an originating system to list the specific routers that a datagram must visit on the way to its destination. No deviation from this list is allowed.
```

```
  if (ipc.opt && ipc.opt->opt.srr) {
    if (!daddr)
      return -EINVAL;
    faddr = ipc.opt->opt.faddr;
    connected = 0;
  }   
```

Then TOS IP flags are getting read and checked for following options 
- `SO_DONTROUTE` via `setsockopt`or `MSG_DONTROUTE` via `sendto` or`sendmsg`
- `is_strictroute` set  for 'IP Strict Source and Route Route'  aka SSRR
Both options are checking for options which ask to avoid any kind of network routing.

If `tos` has`0x1` (`RTO_ONLINK`) added to its bit set and socket is considered not 'connected'.

```  
tos = get_rttos(&ipc, inet);
  if (sock_flag(sk, SOCK_LOCALROUTE) ||
      (msg->msg_flags & MSG_DONTROUTE) ||
      (ipc.opt && ipc.opt->opt.is_strictroute)) {
    tos |= RTO_ONLINK;
    connected = 0;
  }
```



Then it will check for multicast and possible contradictory overrides setup by `IP_PKTINFO` 
```
  if (ipv4_is_multicast(daddr)) {
    if (!ipc.oif)
      ipc.oif = inet->mc_index;
    if (!saddr)
      saddr = inet->mc_addr;
    connected = 0;
  } else if (!ipc.oif)
    ipc.oif = inet->uc_index;
```

After all this checks and conditional unsetting of `connected` flag , it try to choose fast path with help of `sk_dst_check` or slow path where it does manul task of constructing a flow structure.
```
// FAST PATH
  if (connected)
    rt = (struct rtable *)sk_dst_check(sk, 0);

// SLOW PATH
  if (!rt) {
    struct net *net = sock_net(sk);
    __u8 flow_flags = inet_sk_flowi_flags(sk);

    fl4 = &fl4_stack;

    flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
           RT_SCOPE_UNIVERSE, sk->sk_protocol,
           flow_flags,
           faddr, saddr, dport, inet->inet_sport,
           sk->sk_uid);

    security_sk_classify_flow(sk, flowi4_to_flowi(fl4)); // SELinux 
    rt = ip_route_output_flow(net, fl4, sk); // look up routing table for flow structure
    
        /* snip */
  
}
```
Failure to find routing information will result in increments in MIB counters
```
    if (IS_ERR(rt)) {
      err = PTR_ERR(rt);
      rt = NULL;
      if (err == -ENETUNREACH)
        IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
      goto out;
    }
```
Check for boardcast packet and proceed with packet send
```
    err = -EACCES;
    if ((rt->rt_flags & RTCF_BROADCAST) &&
        !sock_flag(sk, SOCK_BROADCAST))
      goto out;
```
Ultimately routing structure gets cached on socket if its declared `connected`
```
    if (connected)
      sk_dst_set(sk, dst_clone(&rt->dst));
```

Next is handling of `MSG_CONFIRM` flag setup by `send`, `sendto` or `sendmsg` to keep ARP cache warm by going through back and forth `goto` statements
```
  if (msg->msg_flags&MSG_CONFIRM)
    goto do_confirm;
back_from_confirm:

        /* snip */

do_confirm:
  if (msg->msg_flags & MSG_PROBE)  // just probe a path with MSG_PROBE
    dst_confirm_neigh(&rt->dst, &fl4->daddr);
  if (!(msg->msg_flags&MSG_PROBE) || len)
    goto back_from_confirm;
```

First use case for trasmission is, uncorked fast path where you build `skb`  with `ip_make_skb` and call `udp_send_skb`. 
```
  /* Lockless fast path for the non-corking case. */
  if (!corkreq) {
    skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
          sizeof(struct udphdr), &ipc, &rt,
          msg->msg_flags); 
    err = PTR_ERR(skb);
    if (!IS_ERR_OR_NULL(skb))
      err = udp_send_skb(skb, fl4);
    goto out;
  }
```
In above code, `ip_make_skb` end up calling `__ip_append_data` which is also called by `ip_append_data` in case of corked socket below 

```
do_append_data:
  up->len += ulen;
  err = ip_append_data(sk, fl4, getfrag, msg, ulen,
           sizeof(struct udphdr), &ipc, &rt,
           corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
  if (err)
    udp_flush_pending_frames(sk);
  else if (!corkreq)
    err = udp_push_pending_frames(sk);
  else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
    up->pending = 0;
  release_sock(sk);

```
And  above `udp_push_pending_frames` is just a wrapper around `udp_send_skb`.

In any case, if `skb`formation fails then `err` is set to `-ENOBUFS` and `UDP_MIB_SNDBUFERRORS` is updated. Upon success `UDP_MIB_OUTDATAGRAMS` counter gets updated.  

`__ip_append_data` is at heart of udp transmissions and does following things
- keep a track of size of  `sk_write_queue` and allocate buffers with `sock_wmalloc` accordingly. It also checks for `NETIF_F_SG` which allows to check if NIC supports scatter/gather IO (Vectored IO), if yes, then fragments of buffers can be addressed for a transfer.

In the end `udp_send_skb` called which after some UDP checksuming rituals transmit packet by calling `ip_send_skb` updating various  `IPSTAT_MIB_` and `UDP_MIB_` stats which are reflected in `/proc/net/snmp`.

Stats under `/proc/net/udp` gets populated by `udp4_format_sock` in `net/ipv4/udp.c`. One of the useful field is `inode` which is mapped under `/proc/[pid]/fd` and helps us to find out which process owns this UDP socket.

## IP layer

Eventually, any call pertaining to send reaches to `ip_send_skb`. This is very short function which calls `ip_local_out`   and if it fails then update ip statistics with `IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS)`. 

`ip_local_out` calls `__ip_local_out` which populated length of packet in IP headers (which gets genrated in same function with `struct iphdr *iph = ip_hdr(skb)`)and calculate checksum with `ip_send_check`,  eventually it calls `nf_hook`.

`nf_hook` is wrapper around `nf_hook_thresh` which spot checks if it should proceed further with filters or not and returns true or false as a status upon execution of `dst_output`.  Checkout `nf_hook`

```
        return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, skb, NULL,
                       skb_dst(skb)->dev, dst_output);
```
Any IPTables rules gets executed in CPU context of any send system call so CPU pinning can create inadvertent effect due to CPU pinning. 

Above `dst_output` function looks at `dst` entry in given `skb` and calls attached `output` function as following 

```
 static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return skb_dst(skb)->output(net, sk, skb);
}
```
and most of the time that `output` pointer is calling `ip_output`.

`ip_output` does some MIB statstistical updates and then pass control to `ip_finish_output` by using `NF_HOOK_COND`.

Look at the call of `NF_HOOK_COND` and its signature.

```c
return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
          net, sk, skb, NULL, skb->dev,
          ip_finish_output,
          !(IPCB(skb)->flags & IPSKB_REROUTED))
# prototype 

static inline int 
NF_HOOK_COND(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,struct sk_buff *skb, struct net_device *in, struct net_device *out,
int (*okfn)(struct net *, struct sock *, struct sk_buff *), bool cond)
```

In above, it will call `ip_finish_output` only if `!(IPCB(skb)->flags & IPSKB_REROUTED)` is true otherwise it will call `kfree_skb` through `nf_hook`.

`ip_finish_output` looks like following does 
- CGROUP related EGRESS
- discover MTU size
- GSO related calls if its turned on or send to `ip_fragment`
- in the end call `ip_finish_output2` 

```c
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  unsigned int mtu;
  int ret;

  ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
  if (ret) {
    kfree_skb(skb);
    return ret;
  }

#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
  /* Policy lookup after SNAT yielded a new policy */
  if (skb_dst(skb)->xfrm) {
    IPCB(skb)->flags |= IPSKB_REROUTED;
    return dst_output(net, sk, skb);
  }
#endif
  mtu = ip_skb_dst_mtu(sk, skb);
  if (skb_is_gso(skb))
    return ip_finish_output_gso(net, sk, skb, mtu);

  if (skb->len > mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU))
    return ip_fragment(net, sk, skb, mtu, ip_finish_output2);

  return ip_finish_output2(net, sk, skb);
}
```



Note about Path MTU discovery 

- This option is strongly encouraged so lowest MTU on the path will get used for IP packets to avoid any kind of fragmentation. I think we have seen this issue with multicast.

- setup PMTU option with `setsockopt` with `SOL_IP` and `IP_MTU_DISCOVER` and optical value would be `IP_PMTUDISC_DO` means always do path MTU Discovery.

  - If you do above and try to send data larger than PMTU then you get `EMSGSIZE` error.
  - You can use `getsockopt` with the `SOL_IP` and `IP_MTU` optname to retrieve PMTU for your use. 

- In advance options, you can use `IP_PMTUDISC_PROBE` to tell kernel to set 'Don't Fragment' bit but allows you to send data larger than PMTU (what's point ?)





#### IP Neighbour discovery 

Neighbour IP discovery starts under `ip_finish_output2` and transmission to it ends by calling `dev_queue_xmit`.

```c
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
        struct dst_entry *dst = skb_dst(skb);
        struct rtable *rt = (struct rtable *)dst;
        struct net_device *dev = dst->dev;
        unsigned int hh_len = LL_RESERVED_SPACE(dev);
        struct neighbour *neigh;
        u32 nexthop;

        if (rt->rt_type == RTN_MULTICAST) {
                IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTMCAST, skb->len);
        } else if (rt->rt_type == RTN_BROADCAST)
                IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTBCAST, skb->len);

    
    
    
    
        /* Be paranoid, rather than too clever. */
        if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
                struct sk_buff *skb2;

                skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
            
                    /* snip */
            
                consume_skb(skb);
                skb = skb2;
        }

    
        /* snip */

        rcu_read_lock_bh();
        nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);
        neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
        if (unlikely(!neigh))
                neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
        if (!IS_ERR(neigh)) {
                int res;

                sock_confirm_neigh(skb, neigh);
                res = neigh_output(neigh, skb);

                rcu_read_unlock_bh();
                return res;
        }
    
        rcu_read_unlock_bh();

        net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
                            __func__);
        kfree_skb(skb);
        return -EINVAL;
}

```



First two section of this function 

- one which does statistic counter updates for multicast or broadcast
- second is section where `skb` length gets adjusted for link layer related data

Then it enters in IP neighbour discovery code path.

- Neighbour information stored in `struct neighbour`
- First it checks for that information with `__ipv4_neigh_lookup_noref` if not found then it calls `__neigh_create`. This is when you are sending data to particualr machine for the first time.
- Once you get neighbour then it needs to execute `output` function which will guide us to reach to that neighbour. This output function sets up some infromation params for path to neighbour and executes `dev_queue_xmit`. `neigh_output` wraps that functionality.

```C
static inline int neigh_output(struct neighbour *n, struct sk_buff *skb)
{
        const struct hh_cache *hh = &n->hh;

        if ((n->nud_state & NUD_CONNECTED) && hh->hh_len)
                return neigh_hh_output(hh, skb);
        else
                return n->output(n, skb);
}
```

There are two paths

- `neigh_hh_output`  called when state of socket is `NUD_CONNECTED` and hardware header is cached. This function does some modification of cache header and calls `dev_queue_xmit`.

- if above conditions are not met then call `n->output` is something need to be pointed at, during progression of `__neigh_create`. Initial, in this progression it gets setup with `neigh_blackhole`. Then depedning on neighbours condition either its up & connected then `neigh->ops_connected_output` and if unsure about neighbours availbiliy due to lack of response to probe for time more that `/proc/sys/net/ipv4/neigh/default/delay_first_probe_time` seconds, then pointed to `neigh->ops->output` . 

- Both `connected_output` and `output` are pointing to `neigh_resolve_output` through `neigh->ops` which is `struct neigh_ops`.

- `neigh_resolve_output` does three things

  - if neighbour is not resolved (`NUD_NONE`) state then it starts ARP request for probing by refering to `/proc/sys/net/ipv4/neigh/default/{app_solicit,mcast_solicit}`.
  - If its in `NUD_STALE` then it gets updated to `NUD_DELAYED` and time set to probe it later
  - if its in `NUD_INCOMPLETE` state then check for queued packets are below threshold defined in `/proc/sys/net/ipv4/neigh/default/unres_qlen` by dropping them. `NEIGH_CACHE_STAT_INC` gets used to update stats.

  All three checks later, packet is handed down to `dev_queue_xmit(skb)`.

 

##NIC Device layer 

```c
static int __dev_queue_xmit(struct sk_buff *skb, void *accel_priv)
{
        struct net_device *dev = skb->dev;
        struct netdev_queue *txq;
        struct Qdisc *q;
        int rc = -ENOMEM;

        skb_reset_mac_header(skb);
    
    
        /* snip */

        /* Disable soft irqs for various locks below. Also
         * stops preemption for RCU.
         */
        rcu_read_lock_bh();

        skb_update_prio(skb);

    
        /* snip */
 
        txq = netdev_pick_tx(dev, skb, accel_priv);
    
        /* to be continued */

}
```



`__dev_queue_xmit` stumbles upon selecting a transmit queue by executing `netdev_pick_tx` 

- `netdev_pick_tx` check for availblity of `ndo_select_queue` which is NIC device driver implmentation to select hardware queue.
- above selection is followed by `__netdev_pick_tx` which gets queue index with `sk_tx_queue_get` which was previously cached on the socket with `sk_tx_queue_set` in the same function.
- If index returned by `sk_tx_queue_get` is invalid then
  - either query XPS for new index with `get_xps_queue`
  - or create new index with `skb_tx_hash`
  - cache that queue on the socket with `sk_tx_queue_set` 

```C
static u16 __netdev_pick_tx(struct net_device *dev, struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        int queue_index = sk_tx_queue_get(sk);

        if (queue_index < 0 || skb->ooo_okay ||
            queue_index >= dev->real_num_tx_queues) {
                int new_index = get_xps_queue(dev, skb);

                if (new_index < 0)
                        new_index = skb_tx_hash(dev, skb);

                if (queue_index != new_index && sk &&
                    sk_fullsock(sk) &&
                    rcu_access_pointer(sk->sk_dst_cache))
                        sk_tx_queue_set(sk, new_index);

                queue_index = new_index;
        }

        return queue_index;
}

struct netdev_queue *netdev_pick_tx(struct net_device *dev,
                                    struct sk_buff *skb,
                                    void *accel_priv)
{
        int queue_index = 0;

#ifdef CONFIG_XPS
        u32 sender_cpu = skb->sender_cpu - 1;

        if (sender_cpu >= (u32)NR_CPUS)
                skb->sender_cpu = raw_smp_processor_id() + 1;
#endif

        if (dev->real_num_tx_queues != 1) {
                const struct net_device_ops *ops = dev->netdev_ops;

                if (ops->ndo_select_queue)
                        queue_index = ops->ndo_select_queue(dev, skb, accel_priv,
                                                            __netdev_pick_tx);
                else
                        queue_index = __netdev_pick_tx(dev, skb);

                if (!accel_priv)
                        queue_index = netdev_cap_txqueue(dev, queue_index);
        }

        skb_set_queue_mapping(skb, queue_index);
        return netdev_get_tx_queue(dev, queue_index);
}
```

Let look at `__skb_tx_hash` which is wrapped by `skb_tx_hash`, it first looks for forwarding conditions where it already mapped with hash for RX queue, if yes then it uses same hash to calculate TX queue hash.

Later it checks for presence of hardware queue with `dev->num_tc` and try to get priority `qoffset` and `qcount` based on `setsockopt` option of `IP_TOS` which can be retrieved from `skb->priority`. In the end it uses `skb_get_hash` to calculate TX queue. 



```C
u16 __skb_tx_hash(const struct net_device *dev, struct sk_buff *skb,
                  unsigned int num_tx_queues)
{
        u32 hash;
        u16 qoffset = 0;
        u16 qcount = num_tx_queues;

        if (skb_rx_queue_recorded(skb)) {
                hash = skb_get_rx_queue(skb);
                while (unlikely(hash >= num_tx_queues))
                        hash -= num_tx_queues;
                return hash;
        }

        if (dev->num_tc) {
                u8 tc = netdev_get_prio_tc_map(dev, skb->priority);

                qoffset = dev->tc_to_txq[tc].offset;
                qcount = dev->tc_to_txq[tc].count;
        }

        return (u16) reciprocal_scale(skb_get_hash(skb), qcount) + qoffset;
}
```



 















  





