- When device driver gets loaded , it calls `module_init` with driver initialization function `ixgbe_init_module` in following code
```c
static int __init ixgbe_init_module(void)
{
        /* ..... */

        ixgbe_wq = create_singlethread_workqueue(ixgbe_driver_name);

        /* ..... */

        ret = pci_register_driver(&ixgbe_driver);

        /* ..... */

        return 0;
}

module_init(ixgbe_init_module);

```
This creates `workqueue` which is way to offload work to softirq thread

-  call for `pci_register_driver` is with `ixgbe_driver` which is instance of `struct pci_driver`
```c
static struct pci_driver ixgbe_driver = {
        .name     = ixgbe_driver_name,
        .id_table = ixgbe_pci_tbl,
        .probe    = ixgbe_probe,
        .remove   = ixgbe_remove,
        /* ..... */

};
```
this structure holds function pointers for various pci device actions like `ixgbe_probe`, `ixgbe_remove` and list of famility of devices `ixgbe_pci_tbl` supported by given driver.

- `ixgbe_probe` does list of things

```c
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
        struct net_device *netdev;
        
        /* ..... */
        
        const struct ixgbe_info *ii = ixgbe_info_tbl[ent->driver_data];
        
        /* ..... */
        
         err = pci_enable_device_mem(pdev);

        /* ..... */

        if (!dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
                pci_using_dac = 1;
        } else {
                err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
                
                /* ..... */
                
                pci_using_dac = 0;
        }        

        /* ..... */
        

        err = pci_request_mem_regions(pdev, ixgbe_driver_name);



        netdev = alloc_etherdev_mq(sizeof(struct ixgbe_adapter), indices);

         /* ..... */
         
        SET_NETDEV_DEV(netdev, &pdev->dev);

         /* ..... */

        netdev->netdev_ops = &ixgbe_netdev_ops;
        ixgbe_set_ethtool_ops(netdev);

         /* ..... */
        ixgbe_sw_init(adapter, ii)
        
        /* ..... */
        err = ixgbe_init_interrupt_scheme(adapter);

       /* ..... */

}        
        
```        

   -  identifies device by looking up `ixgbe_pci_tbl` to determine approriate hw related parameters like link and mac related operations.
   - enables device
   - enable DMA masks
   - allocates PCI memory mapped region through `IOMMU`
   - populates `struct net_device` which is unique to each network device and its initilization goes through following callchain
```
    alloc_etherdev_mq(sizeof(struct ixgbe_adapter), indices)
       alloc_etherdev_mqs(sizeof_priv, count, count)
          alloc_etherdev_mqs(int sizeof_priv, unsigned int txqs,
                                      unsigned int rxqs)
            alloc_netdev_mqs(int sizeof_priv, const char *name,
                unsigned char name_assign_type,
                void (*setup)(struct net_device *),
                unsigned int txqs, unsigned int rxqs)                                   
```
this particular structure is really huge and placeholder for many supporting device structures.

- every instance of `struct net_device` which is unique to each network hardware device has instance of `struct net_device_ops` attached to it which provides function pointer to all actions NIC device been supported.
```c
static const struct net_device_ops ixgbe_netdev_ops = {
        .ndo_open               = ixgbe_open,
        .ndo_stop               = ixgbe_close,
        .ndo_start_xmit         = ixgbe_xmit_frame,
        .ndo_select_queue       = ixgbe_select_queue,
        .ndo_set_rx_mode        = ixgbe_set_rx_mode,

        /* ..... */

```


above `netdev->netdev_ops = &ixgbe_netdev_ops` does above associations and above function pointers used by command like `ifconfig up/down`

- userspace command ethtool also requires special function pointers which gets populated by call to `ixgbe_set_ethtool_ops(netdev)` and instance of `struct ethtool_ops` gets attached to `netdev->ethtool_ops` 
```c
static const struct ethtool_ops ixgbe_ethtool_ops = {
        .get_drvinfo            = ixgbe_get_drvinfo,
        .get_regs_len           = ixgbe_get_regs_len,
        .get_regs               = ixgbe_get_regs,
        .get_wol                = ixgbe_get_wol,
        .set_wol                = ixgbe_set_wol,
        .nway_reset             = ixgbe_nway_reset,
        .get_link               = ethtool_op_get_link,
        .get_eeprom_len         = ixgbe_get_eeprom_len,
        .get_eeprom             = ixgbe_get_eeprom,
        .set_eeprom             = ixgbe_set_eeprom,
        .get_ringparam          = ixgbe_get_ringparam,
        .set_ringparam          = ixgbe_set_ringparam,
        .get_pauseparam         = ixgbe_get_pauseparam,
        /* ..... */
```

- NIC deliveres data in form of queues where hash functions used to divide traffic into set of buckets based on meta data information of packet (like src/dst ip/port), there is memory space in form of ring buffer attached to the queue which gets created during initialization of NIC with chain of calls triggered by `ixgbe_init_interrupt_scheme(adapter)` where `adapter` is `struct ixgbe_adapter *`.
```c
ixgbe_init_interrupt_scheme(adapter)               /* RSS queues count decided by ixgbe_sw_init(adapter, ii) */
  ixgbe_alloc_q_vectors(adapter)                   /* setups RSS queues */
    ixgbe_alloc_q_vector                           /* get called in loop for each queue */
              netif_napi_add(adapter->netdev, &q_vector->napi,ixgbe_poll, 64)
                               
```
eventually above call chain reaches to ` netif_napi_add(adapter->netdev, &q_vector->napi,ixgbe_poll, 64)`  where 
   - `q_vector->napi` is instance of `struct napi_struct` attached to each queue
   - `ixgbe_poll` function gets called for every `napi_schedule` call from softirq context
   - `64` is device driver weight , more on this during runtime description.
   
- `q_vector` is instance of `struct ixgbe_q_vector` which is attached to every ring
```c
struct ixgbe_q_vector {
        struct ixgbe_adapter *adapter;
#ifdef CONFIG_IXGBE_DCA
        int cpu;            /* CPU for DCA */
#endif
        u16 v_idx;              /* index of q_vector within array, also used for
                                 * finding the bit in EICR and friends that
                                 * represents the vector for this ring */
        u16 itr;                /* Interrupt throttle rate written to EITR */
        struct ixgbe_ring_container rx, tx;

        struct napi_struct napi;
        cpumask_t affinity_mask;
        int numa_node;
        struct rcu_head rcu;    /* to avoid race with update stats on free */
        char name[IFNAMSIZ + 9];

        /* for dynamic allocation of rings associated with this q_vector */
        struct ixgbe_ring ring[0] ____cacheline_internodealigned_in_smp;
};
```


