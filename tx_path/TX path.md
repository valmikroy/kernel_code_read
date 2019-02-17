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

In the end `udp_send_skb` called which after some checksuming rituals transmit packet by calling `ip_send_skb` updating various  `IPSTAT_MIB_` and `UDP_MIB_` stats which are reflected in `/proc/net/snmp`.

Stats under `/proc/net/udp` gets populated by `udp4_format_sock` in `net/ipv4/udp.c`. One of the useful field is `inode` which is mapped under `/proc/[pid]/fd` and helps us to find out which process owns this UDP socket.




















  





