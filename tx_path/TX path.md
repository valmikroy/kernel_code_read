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

`udp_sendmsg` looks like following 





