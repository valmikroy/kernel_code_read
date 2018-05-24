- Ethtool has access to hooks directly from driver space like stats are getting registered in `ixgbe` through `struct ixgbe_stats ixgbe_gstrings_stats[]`. Funtionality of ethtool comes from various function pointer populated at ` struct ethtool_ops ixgbe_ethtool_ops`. 

- Query to NIC stats can be done through `sudo ethtool -S <interface>` which is very driver specific and normalized version in kernel has stored at `/proc/net/dev` 

- There is interesting stuff we can try with setting up queues (aka rings) dedicated for rx and tx which then can attached to separate setup of interrupts. 

- adjusting ring descriptor sizes, but for that you need much more upstream tune up.

- there is flow indirection table adjustments on NIC and those little confusing on `ixgbe` with `Intel Ethernet 82599ES`
```
abhsawan@v:~$ sudo ethtool -x enp2s0f0
RX flow hash indirection table for enp2s0f0 with 40 RX ring(s):
    0:      0     1     2     3     4     5     6     7
    8:      8     9    10    11    12    13    14    15
   16:      0     1     2     3     4     5     6     7
   24:      8     9    10    11    12    13    14    15
   32:      0     1     2     3     4     5     6     7
   40:      8     9    10    11    12    13    14    15
   48:      0     1     2     3     4     5     6     7
   56:      8     9    10    11    12    13    14    15
   64:      0     1     2     3     4     5     6     7
   72:      8     9    10    11    12    13    14    15
   80:      0     1     2     3     4     5     6     7
   88:      8     9    10    11    12    13    14    15
   96:      0     1     2     3     4     5     6     7
  104:      8     9    10    11    12    13    14    15
  112:      0     1     2     3     4     5     6     7
  120:      8     9    10    11    12    13    14    15
RSS hash key:
67:ca:83:3f:d7:02:3a:0e:f6:5d:c1:3f:62:32:53:99:5c:a4:d1:00:e2:f9:23:7f:b9:e4:ca:92:61:67:6c:51:aa:0f:a9:62:4c:b2:c6:a4
```

Above output shows 16 queues but 40 RX rings. So RSS hash key in output divides data into 128 buckets and those buckets gets distributed in 16 queues which TMK at much lower level in hardware and they somehow gets mapped to 40 ring descriptors. Also `ixgbe` driver in linux kernel source is way different than intel driver.     

   - `ethtool -X <interface> equal 2`
   - `ethtool -X <interface> weight 6 2`


- There is support for ntuples support which can allow you to control above queues from hardware level perspective for consistatnt cache hit rate
