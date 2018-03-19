/**
 * Linux RX path journey for ixgbe driver
 *
 *  keep following structure infromation handy 
 *  struct net_device 
 **/






static const struct net_device_ops ixgbe_netdev_ops = {
        .ndo_open               = ixgbe_open,
        .ndo_stop               = ixgbe_close,
        .ndo_start_xmit         = ixgbe_xmit_frame,
        .ndo_select_queue       = ixgbe_select_queue,
        .ndo_set_rx_mode        = ixgbe_set_rx_mode,
        .ndo_validate_addr      = eth_validate_addr,
        .ndo_set_mac_address    = ixgbe_set_mac,
        .ndo_change_mtu         = ixgbe_change_mtu,
        .ndo_tx_timeout         = ixgbe_tx_timeout,
        .ndo_set_tx_maxrate     = ixgbe_tx_maxrate,
        .ndo_vlan_rx_add_vid    = ixgbe_vlan_rx_add_vid,
        .ndo_vlan_rx_kill_vid   = ixgbe_vlan_rx_kill_vid,
        .ndo_do_ioctl           = ixgbe_ioctl,
        .ndo_set_vf_mac         = ixgbe_ndo_set_vf_mac,
        .ndo_set_vf_vlan        = ixgbe_ndo_set_vf_vlan,
        .ndo_set_vf_rate        = ixgbe_ndo_set_vf_bw,
        .ndo_set_vf_spoofchk    = ixgbe_ndo_set_vf_spoofchk,
        .ndo_set_vf_rss_query_en = ixgbe_ndo_set_vf_rss_query_en,
        .ndo_set_vf_trust       = ixgbe_ndo_set_vf_trust,
        .ndo_get_vf_config      = ixgbe_ndo_get_vf_config,
        .ndo_get_stats64        = ixgbe_get_stats64,
        .ndo_setup_tc           = __ixgbe_setup_tc,
#ifdef CONFIG_NET_POLL_CONTROLLER
        .ndo_poll_controller    = ixgbe_netpoll,
#endif
#ifdef IXGBE_FCOE
        .ndo_fcoe_ddp_setup = ixgbe_fcoe_ddp_get,
        .ndo_fcoe_ddp_target = ixgbe_fcoe_ddp_target,
        .ndo_fcoe_ddp_done = ixgbe_fcoe_ddp_put,
        .ndo_fcoe_enable = ixgbe_fcoe_enable,
        .ndo_fcoe_disable = ixgbe_fcoe_disable,
        .ndo_fcoe_get_wwn = ixgbe_fcoe_get_wwn,
        .ndo_fcoe_get_hbainfo = ixgbe_fcoe_get_hbainfo,
#endif /* IXGBE_FCOE */
        .ndo_set_features = ixgbe_set_features,
        .ndo_fix_features = ixgbe_fix_features,
        .ndo_fdb_add            = ixgbe_ndo_fdb_add,
        .ndo_bridge_setlink     = ixgbe_ndo_bridge_setlink,
        .ndo_bridge_getlink     = ixgbe_ndo_bridge_getlink,
        .ndo_dfwd_add_station   = ixgbe_fwd_add,
        .ndo_dfwd_del_station   = ixgbe_fwd_del,
        .ndo_udp_tunnel_add     = ixgbe_add_udp_tunnel_port,
        .ndo_udp_tunnel_del     = ixgbe_del_udp_tunnel_port,
        .ndo_features_check     = ixgbe_features_check,
        .ndo_xdp                = ixgbe_xdp,
};



static struct pci_driver ixgbe_driver = {
        .name     = ixgbe_driver_name,
        .id_table = ixgbe_pci_tbl,
        .probe    = ixgbe_probe,
        .remove   = ixgbe_remove,
#ifdef CONFIG_PM
        .suspend  = ixgbe_suspend,
        .resume   = ixgbe_resume,
#endif
        .shutdown = ixgbe_shutdown,
        .sriov_configure = ixgbe_pci_sriov_configure,
        .err_handler = &ixgbe_err_handler
};


/**
 * ixgbe_init_module - Driver Registration Routine
 *
 * ixgbe_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init ixgbe_init_module(void)
{
        int ret;
        pr_info("%s - version %s\n", ixgbe_driver_string, ixgbe_driver_version);
        pr_info("%s\n", ixgbe_copyright);

	/**
         * XXX
         * Workqueue is something is used in kernel to execute asynchronous tasks 
         * queue where asychronous action function pointer kept is workqueue and
         * thread which executes it called worker aka kworker
         * Documentation / core-api / workqueue.rst
         **/
        ixgbe_wq = create_singlethread_workqueue(ixgbe_driver_name);
        if (!ixgbe_wq) {
                pr_err("%s: Failed to create workqueue\n", ixgbe_driver_name);
                return -ENOMEM;
        }

        ixgbe_dbg_init();

        /**
         * XXX
         * ixgbe_driver is struct pci_driver above
         * check for ixgbe_pci_tbl which has all vendor information 
         * for each board supported by this driver
         *
         * */
        ret = pci_register_driver(&ixgbe_driver);
        if (ret) {
                destroy_workqueue(ixgbe_wq);
                ixgbe_dbg_exit();
                return ret;
        }

#ifdef CONFIG_IXGBE_DCA
        dca_register_notify(&dca_notifier);
#endif

        return 0;
}

module_init(ixgbe_init_module);



/**
 * ixgbe_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in ixgbe_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * ixgbe_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{

        /**
         * This is network device function
         *
         **/
	struct net_device *netdev;



	struct ixgbe_adapter *adapter = NULL;
	struct ixgbe_hw *hw;
	const struct ixgbe_info *ii = ixgbe_info_tbl[ent->driver_data];
	int i, err, pci_using_dac, expected_gts;
	unsigned int indices = MAX_TX_QUEUES;
	u8 part_str[IXGBE_PBANUM_LENGTH];
	bool disable_dev = false;
#ifdef IXGBE_FCOE
	u16 device_caps;
#endif
	u32 eec;


        /* .............. */



	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	if (!dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
		pci_using_dac = 1;
	} else {
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev,
				"No usable DMA configuration, aborting\n");
			goto err_dma;
		}
		pci_using_dac = 0;
	}

	err = pci_request_mem_regions(pdev, ixgbe_driver_name);



        /* .............. */


	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);
	pci_save_state(pdev);


        /* .............. */



	netdev = alloc_etherdev_mq(sizeof(struct ixgbe_adapter), indices);
	if (!netdev) {
		err = -ENOMEM;
		goto err_alloc_etherdev;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

        /* .............. */

        /**
         * XXX
         * ixgbe_netdev_ops is structure where you will get 
         * all functionalities supported by this device driver 
         * function pasted above.
         * 
         * for ex: when network device start/stop with help of ifconfig 
         * which fuctions to execute are pointed by ndo_stop and ndo_start kind of keys
         **/
        netdev->netdev_ops = &ixgbe_netdev_ops;


        
        /* .............. */

	/**
         * XXX
         *  function ixgbe_init_interrupt_scheme 
         *  setup up queues and allocate irq vectors for this
         *  
         *
         *  function pasted below
         **/


	 err = ixgbe_init_interrupt_scheme(adapter);



        /**
         *  struct ixgbe_adapter *adapter;
         *  const struct ixgbe_info *ii = ixgbe_info_tbl[ent->driver_data];
         *
         **/


        err = ixgbe_sw_init(adapter, ii);

        /**
         * check how to setups ring buffer below
         *
         **/

}



/**
 * ixgbe_sw_init - Initialize general software structures (struct ixgbe_adapter)
 * @adapter: board private structure to initialize
 *
 * ixgbe_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int ixgbe_sw_init(struct ixgbe_adapter *adapter,
                         const struct ixgbe_info *ii)
{
        struct ixgbe_hw *hw = &adapter->hw;
        struct pci_dev *pdev = adapter->pdev;
        unsigned int rss, fdir;
        u32 fwsm;
        int i;

        /* .............. */



        /* Set common capability flags and settings */
        /**
         * XXX
         * below RSS limit comes to 16 because of constant
         *
         **/
        rss = min_t(int, ixgbe_max_rss_indices(adapter), num_online_cpus());
        adapter->ring_feature[RING_F_RSS].limit = rss;

        /* .............. */


        fdir = min_t(int, IXGBE_MAX_FDIR_INDICES, num_online_cpus());
        adapter->ring_feature[RING_F_FDIR].limit = fdir;

	
        /* .............. */

}



/**
 * ixgbe_init_interrupt_scheme - Determine proper interrupt scheme
 * @adapter: board private structure to initialize
 *
 * We determine which interrupt scheme to use based on...
 * - Kernel support (MSI, MSI-X)
 *   - which can be user-defined (via MODULE_PARAM)
 * - Hardware queue count (num_*_queues)
 *   - defined by miscellaneous hardware support/features (RSS, etc.)
 **/
int ixgbe_init_interrupt_scheme(struct ixgbe_adapter *adapter)
{
        int err;

        /* Number of supported queues */

        /*
         * XXX
         * below function calls ixgbe_set_rss_queues and get set to 16
         * with statement 
         *  rss_i = max_t(u16, fcoe_i, rss_i);
         *  
         *  where 
         *  
         *  rss_i =  adapter->ring_feature[RING_F_RSS].limit 
         *  
         *  which got setup in ixgbe_sw_init above
         *
         **/

        ixgbe_set_num_queues(adapter);

        /* Set interrupt mode */
        ixgbe_set_interrupt_capability(adapter);


        /**
         * XXX
         * ixgbe_alloc_q_vectors -> ixgbe_alloc_q_vector -> calls        
         *
         * netif_napi_add(adapter->netdev, &q_vector->napi, ixgbe_poll, 64);
         * 
         *
         * q_vector is struct ixgbe_q_vector which represents every type of queue
         * check struct below
         *
         *  in reality ixgbe_alloc_q_vectors loops over each rx and tx queue (and more like xdp) 
         *  and attach napi poll function one by one to each queue
         *
         *  it also initiate DMA using API
         *  https://github.com/torvalds/linux/blob/v3.13/Documentation/DMA-API-HOWTO.txt
         **/
        err = ixgbe_alloc_q_vectors(adapter);


        if (err) {
                e_dev_err("Unable to allocate memory for queue vectors\n");
                goto err_alloc_q_vectors;
        }

        ixgbe_cache_ring_register(adapter);

        e_dev_info("Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u XDP Queue count = %u\n",
                   (adapter->num_rx_queues > 1) ? "Enabled" : "Disabled",
                   adapter->num_rx_queues, adapter->num_tx_queues,
                   adapter->num_xdp_queues);

        set_bit(__IXGBE_DOWN, &adapter->state);

        return 0;

err_alloc_q_vectors:
        ixgbe_reset_interrupt_capability(adapter);
        return err;
}




/* MAX_Q_VECTORS of these are allocated,
 * but we only use one per queue-specific vector.
 */
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

        /* XXX
         * every vector has notion of NUMA , humm
         *
         **/
        int numa_node;

        /**
         * XXX
         * RCU - Read Copy UPdate
         * allows read to happened simulteneously with updates
         * https://lwn.net/Articles/262464/
         *
         **/ 
        struct rcu_head rcu;    /* to avoid race with update stats on free */
        char name[IFNAMSIZ + 9];

        /* for dynamic allocation of rings associated with this q_vector */
        struct ixgbe_ring ring[0] ____cacheline_internodealigned_in_smp;
};





/** 
 * 
 * XXX
 * netif_napi_add setup poll function which part get executed in softirq context
 *
 * but you need action for hardware irq context which get setup by 
 * ixgbe_request_irq()
 * -> ixgbe_request_msix_irqs
 *    -> request_irq(entry->vector, &ixgbe_msix_clean_rings, 0,q_vector->name, q_vector);
 * 
 *
 * once this is done then 
 *  ixgbe_irq_enable
 *  -> ixgbe_irq_enable_queues get called to enable irq taking from NIC
 *
 *
 **/



/**
 * XXX Random notes
 *
 * - check IXGBE_NETDEV_STAT in driver to know from where ethtool -S stats coming from. 
 * - ethtool -x calls following loop
 *    https://github.com/torvalds/linux/blob/v3.13/drivers/net/ethernet/intel/igb/igb_main.c#L2833-L2834
 *       sudo ethtool -X eth0 equal 16 
 *     this means you can spread load across all 16 queues equally 
 *
 *
 *      sudo ethtool -X eth0 weight 6 2
 *    this means queue 0 will have more weight than queue 1
 *
 * - ntuple can be used but how you can distribute haproxy 16 proc traffic to different queues
 *
 *
 **/



/**
 * XXX
 * So part of above code is that NIC functionality divided into two parts
 * - hardware interrupt context setup for each queue
 * - provision for softirq context which is part of struct softnet_data 
 * - netif_napi_add is someone bridge gap to let napi_poll to find out NIC specific poll function 
 * - napi_poll eventually become part of net_rx_action which get called in softirq context  
 **/



/**
 * XXX SOFTIRQ
 *
 * The __do_softirq function does a few interesting things:
 *
 *      - determines which softirq is pending
 *       - softirq time is accounted for statistics purposes
 *       - softirq execution statistics are incremented
 *       - the softirq handler for the pending softirq (which was registered with a call to open_softirq) is executed.
 *
 *
 **/

/*
 * XXX net_dev_init creates struct softnet_data for each CPU
 *
 *
 **/


static int __init net_dev_init(void)
{
  /* ... */

        for_each_possible_cpu(i) {
                struct work_struct *flush = per_cpu_ptr(&flush_works, i);
                struct softnet_data *sd = &per_cpu(softnet_data, i);

                INIT_WORK(flush, flush_backlog);

                skb_queue_head_init(&sd->input_pkt_queue);
                skb_queue_head_init(&sd->process_queue);

                /* ... */

        }

  /* .............. */

  open_softirq(NET_TX_SOFTIRQ, net_tx_action);
  open_softirq(NET_RX_SOFTIRQ, net_rx_action);

 /* ... */
}


/*
 *
 *       XXX Packet arrives
 *       ixgbe_msix_other gets executed 
 *
 *       looks like ixgbe_service_event_schedule transfers data to rings
 *
 *       this also triggers napi_schedule to start i softirq context 
 *       if its not already started
 *       CPU on which this h/w interrupt get executed also executes softirq 
 *       for it to improve CPU cache hit rate.
 *       XXX RPS can change this XXX
 *
 *       this function also keeps track of rate of interrupts its arriving so 
 *       'interrupt throttling' and 'Interrupt Coalescing' can be achived
 *
 **/


static irqreturn_t ixgbe_msix_other(int irq, void *data)
{
  struct ixgbe_adapter *adapter = data;

 /* ... */

        if (reinit_count) {
                /* no more flow director interrupts until after init */
                IXGBE_WRITE_REG(hw, IXGBE_EIMC, IXGBE_EIMC_FLOW_DIR);
                adapter->flags2 |= IXGBE_FLAG2_FDIR_REQUIRES_REINIT;

                /* XXX 
                 * Assume somehow following function reach to 
                 *
                 *  napi_schedule_irqoff(&q_vector->napi);
                 *
                 *  where &q_vector->napi is napi_struct
                 *
                 * */
                ixgbe_service_event_schedule(adapter);
        }
 /* ... */

  return IRQ_HANDLED;

}




void __napi_schedule(struct napi_struct *n)
{
        unsigned long flags;

        local_irq_save(flags);

        /* XXX 
         * this_cpu_ptr will return pointer to this CPUs softnet_data  
         *
         * */
        ____napi_schedule(this_cpu_ptr(&softnet_data), n);

        local_irq_restore(flags);
}
EXPORT_SYMBOL(__napi_schedule);




/* Called with irq disabled */
static inline void ____napi_schedule(struct softnet_data *sd,
                                     struct napi_struct *napi)
{

        /* check for napi_struct below */
        list_add_tail(&napi->poll_list, &sd->poll_list);



        /* 
         * This triggers net_rx_action if its not already running
         *      
         * net_rx_action eventually calls poll fuction registered by driver above     
         * */
        __raise_softirq_irqoff(NET_RX_SOFTIRQ);
}



/*
 *
 * napi_struct looks like following
 *
 **/


struct napi_struct {
        /* The poll_list must only be managed by the entity which
         * changes the state of the NAPI_STATE_SCHED bit.  This means
         * whoever atomically sets that bit can add this napi_struct
         * to the per-CPU poll_list, and whoever clears that bit
         * can remove from the list right before clearing the bit.
         */
        struct list_head        poll_list; /* XXX THis gets added in linked list of softdata struct of CPU */

        unsigned long           state;
        int                     weight;
        unsigned int            gro_count;
        int                     (*poll)(struct napi_struct *, int);
#ifdef CONFIG_NETPOLL
        int                     poll_owner;
#endif
        struct net_device       *dev;
        struct sk_buff          *gro_list;
        struct sk_buff          *skb;
        struct hrtimer          timer;
        struct list_head        dev_list;
        struct hlist_node       napi_hash_node;
        unsigned int            napi_id;
};


/**
 *
 *
 *
 * XXX Interrupt coalescing and Interrupt throttling available 
 * 
 * adaptive-rx can be turned on for two factor based throttling 
 * - either with delay before rasing interrupt after packet arrives
 * - wait for maximum number of frames to be arrive  before raising interrupt
 *
 *
 *  
 *  Finally, you can adjust the which CPUs each of those IRQs will be handled 
 *  by modifying /proc/irq/IRQ_NUMBER/smp_affinity for each IRQ number.
 *
 *
 **/



/**
 *
 * XXX __raise_softirq_irqoff from ____napi_schedule calls net_rx_action
 *
 *
 *
 **/

static __latent_entropy void net_rx_action(struct softirq_action *h)
{
        struct softnet_data *sd = this_cpu_ptr(&softnet_data);
        unsigned long time_limit = jiffies +
                usecs_to_jiffies(netdev_budget_usecs);

        /* XXX budget is govened by sysctl param net.core.netdev_budget */
        int budget = netdev_budget;
        LIST_HEAD(list);
        LIST_HEAD(repoll);

        local_irq_disable();
        list_splice_init(&sd->poll_list, &list);
        local_irq_enable();

        /*
         * XXX this loop
         * - keeping track of a work budget (which can be adjusted), and
         * - Checking the elapsed time in terms of jiffied
         *
         */
        for (;;) {
                struct napi_struct *n;

                if (list_empty(&list)) {
                        if (!sd_has_rps_ipi_waiting(sd) && list_empty(&repoll))
                                goto out;
                        break;
                }

                n = list_first_entry(&list, struct napi_struct, poll_list);

                /** XXX
                 * every napi_poll call return amount of packets procssed which get 
                 * deducted from budget
                 **/

                budget -= napi_poll(n, &repoll);

                /* If softirq window is exhausted then punt.
                 * Allow this to run for 2 jiffies since which will allow
                 * an average latency of 1.5/HZ.
                 */
                if (unlikely(budget <= 0 ||
                             time_after_eq(jiffies, time_limit))) {
                        sd->time_squeeze++;
                        break;
                }
        }

        local_irq_disable();

        list_splice_tail_init(&sd->poll_list, &list);
        list_splice_tail(&repoll, &list);
        list_splice(&list, &sd->poll_list);
        if (!list_empty(&sd->poll_list))
                __raise_softirq_irqoff(NET_RX_SOFTIRQ);
/* 
 * XXX this place triggers RPS 
 *
 * net_rps_action_and_irq_enable takes softnet_data->rps_ipi_list 
 * and send it to remote CPUs with net_rps_send_ipi()
 *
 * */
        net_rps_action_and_irq_enable(sd); 
out:
        __kfree_skb_flush();
}


/**
 *
 * XXX part of the contract between driver poll and net_rx_action

 * - If a driver’s poll function consumes its entire weight (which is hardcoded to 64) 
 *   it must NOT modify NAPI state. The net_rx_action loop will take over. (Agreement 1)
 *
 * - If a driver’s poll function does NOT consume its entire weight, it must disable NAPI. 
 *   NAPI will be re-enabled next time an IRQ is received and the driver’s IRQ handler calls napi_schedule. (Agreement 2)
 *
 *
 **/

/*
 * XXX Above net_rx_action calls napi_poll
 * 
 * so driver poll registered above with
 * netif_napi_add(adapter->netdev, &q_vector->napi, ixgbe_poll, 64);
 * 
 * where 64 is weight set in napi_struct->weight
 * 
 * this make sure that number of frames processed are lesser than weight == 64
 *  
 * so if my budget  net.core.netdev_budget = 300
 *
 * then 
 * - 300/64 = 5 times net_rx_action loop will execute 
 * - or atleast 2 jiffied of time long
 * 
 * XXX
 * so you can increase budget till you see squeezing in time ?
 *
 */
static int napi_poll(struct napi_struct *n, struct list_head *repoll)
{

        void *have;
        int work, weight;

        list_del_init(&n->poll_list);

        have = netpoll_poll_lock(n);

        weight = n->weight;

        /* This NAPI_STATE_SCHED test is for avoiding a race
         * with netpoll's poll_napi().  Only the entity which
         * obtains the lock and sees NAPI_STATE_SCHED set will
         * actually make the ->poll() call.  Therefore we avoid
         * accidentally calling ->poll() when NAPI is not scheduled.
         */
        

        
        work = 0;
        if (test_bit(NAPI_STATE_SCHED, &n->state)) {
                work = n->poll(n, weight); /* this is where ixgbe poll function called as n->poll */
                trace_napi_poll(n, work, weight);
        }

        WARN_ON_ONCE(work > weight);

        if (likely(work < weight))
                goto out_unlock;


        /* Drivers must not modify the NAPI state if they
         * consume the entire weight.  In such cases this code
         * still "owns" the NAPI instance and therefore can
         * move the instance around on the list at-will.
         */
        if (unlikely(napi_disable_pending(n))) {
                napi_complete(n); /* XXX Agreement 1 from above */
                goto out_unlock;
        }

        if (n->gro_list) {
                /* flush too old packets
                 * If HZ < 1000, flush all packets.
                 */
                napi_gro_flush(n, HZ >= 1000);
        }

        /* Some drivers may have called napi_schedule
         * prior to exhausting their budget.
         */
        if (unlikely(!list_empty(&n->poll_list))) {
                pr_warn_once("%s: Budget exhausted after napi rescheduled\n",
                             n->dev ? n->dev->name : "backlog");
                goto out_unlock;
        }

        list_add_tail(&n->poll_list, repoll);
        


        out_unlock:
        netpoll_poll_unlock(have);

        return work;

}





/**
 * ixgbe_poll - NAPI Rx polling callback
 * @napi: structure for representing this polling device
 * @budget: how many packets driver is allowed to clean
 *
 * This function is used for legacy and MSI, NAPI mode
 **/
int ixgbe_poll(struct napi_struct *napi, int budget)
{
        struct ixgbe_q_vector *q_vector =
                                container_of(napi, struct ixgbe_q_vector, napi);
        struct ixgbe_adapter *adapter = q_vector->adapter;
        struct ixgbe_ring *ring;
        int per_ring_budget, work_done = 0;
        bool clean_complete = true;

#ifdef CONFIG_IXGBE_DCA
        if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
                ixgbe_update_dca(q_vector);
#endif

        ixgbe_for_each_ring(ring, q_vector->tx) {
                if (!ixgbe_clean_tx_irq(q_vector, ring, budget))
                        clean_complete = false;
        }

        /* Exit if we are called by netpoll */
        if (budget <= 0)
                return budget;

        /* attempt to distribute budget to each queue fairly, but don't allow
         * the budget to go below 1 because we'll exit polling */
        if (q_vector->rx.count > 1)
                per_ring_budget = max(budget/q_vector->rx.count, 1);
        else
                per_ring_budget = budget;

        ixgbe_for_each_ring(ring, q_vector->rx) {
                /* XXX ixgbe_clean_rx_irq() does all heavy lifting */
                int cleaned = ixgbe_clean_rx_irq(q_vector, ring,
                                                 per_ring_budget);

                work_done += cleaned;
                if (cleaned >= per_ring_budget)
                        clean_complete = false;
        }

        /* If all work not completed, return budget and keep polling */
        if (!clean_complete)
                return budget;

        /* all work done, exit the polling mode */
        napi_complete_done(napi, work_done);
        if (adapter->rx_itr_setting & 1)
                ixgbe_set_itr(q_vector);
        if (!test_bit(__IXGBE_DOWN, &adapter->state))
                ixgbe_irq_enable_queues(adapter, BIT_ULL(q_vector->v_idx));

        return min(work_done, budget - 1);
}



/**
 * ixgbe_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @q_vector: structure containing interrupt and ring information
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing.  The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the syste.
 *
 * Returns amount of work completed
 **/
static int ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
                               struct ixgbe_ring *rx_ring,
                               const int budget)
{


        unsigned int total_rx_bytes = 0, total_rx_packets = 0;
        struct ixgbe_adapter *adapter = q_vector->adapter;
#ifdef IXGBE_FCOE
        int ddp_bytes;
        unsigned int mss = 0;
#endif /* IXGBE_FCOE */
        u16 cleaned_count = ixgbe_desc_unused(rx_ring);
        bool xdp_xmit = false;


        /*XXX budget based on number of packets*/
        while (likely(total_rx_packets < budget)) {



        /* .............. */

                rx_buffer = ixgbe_get_rx_buffer(rx_ring, rx_desc, &skb, size);

        /* .............. */

                if (IS_ERR(skb)) {

                } else if (skb) {

                        /*XXX pick data from ring for packet , frament by fragment*/
                        ixgbe_add_rx_frag(rx_ring, rx_buffer, skb, size);

                } else if (ring_uses_build_skb(rx_ring)) {

                        /*XXX my guess this when NIC can build SKBs */
                        skb = ixgbe_build_skb(rx_ring, rx_buffer,
                                              &xdp, rx_desc);
                } else {

                        skb = ixgbe_construct_skb(rx_ring, rx_buffer,
                                                  &xdp, rx_desc);
                }


        /* .............. */

                ixgbe_put_rx_buffer(rx_ring, rx_buffer, skb);
                cleaned_count++;

                /* place incomplete frames back on ring for completion 
                 * aka end of packet check
                 * */
                if (ixgbe_is_non_eop(rx_ring, rx_desc, skb))
                        continue;

                /* verify the packet layout is correct */
                if (ixgbe_cleanup_headers(rx_ring, rx_desc, skb))
                        continue;

                /* probably a little skewed due to removing CRC */
                total_rx_bytes += skb->len;

                /* populate checksum, timestamp, VLAN, and protocol */
                ixgbe_process_skb_fields(rx_ring, rx_desc, skb);

        /* .............. */


                /*XXX 
                 * this calls napi_gro_receive()
                 * and  napi_gro_receive has function entry tracepoint
                 *
                 * napi_gro_receive calls dev_gro_receive
                 *
                 * */
                 ixgbe_rx_skb(q_vector, skb);

                /* update budget accounting */
                 total_rx_packets++;

        }

        /* .............. */

        u64_stats_update_begin(&rx_ring->syncp);
        rx_ring->stats.packets += total_rx_packets;
        rx_ring->stats.bytes += total_rx_bytes;
        u64_stats_update_end(&rx_ring->syncp);
        q_vector->rx.total_packets += total_rx_packets;
        q_vector->rx.total_bytes += total_rx_bytes;

        return total_rx_packets;


}



/** XXX 
 * What is purpose behind existance of GRO ?
 *
 * The main idea behind LRO or GRO methods is that reducing the number of
 * packets passed up the network stack by combining “similar enough” packets
 * together can reduce CPU usage. For example, imagine a case where a large
 * file transfer is occurring and most of the packets contain chunks of data in
 * the file. Instead of sending small packets up the stack one at a time, the
 * incoming packets can be combined into one packet with a huge payload. That
 * packet can then be passed up the stack. This allows the protocol layers to
 * process a single packet’s headers while delivering bigger chunks of data to
 * the user program.
 *
 *
 * Why GRO is prefered over LRO ?
 *
 * The problem with this sort of optimization is, of course, information loss.
 * If a packet had some important option or flag set, that option or flag could
 * be lost if the packet is coalesced into another. And this is exactly why
 * most people don’t use or encourage the use of LRO. LRO implementations,
 * generally speaking, had very lax rules for coalescing packets.
 *
 *
 *  if you have ever used tcpdump and seen unrealistically large incoming
 *  packet sizes, it is most likely because your system has GRO enabled. As
 *  you’ll see soon, packet capture taps are inserted further up the stack,
 *  after GRO has already happened.
 *
 **/


static enum gro_result dev_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
        struct sk_buff **pp = NULL;
        struct packet_offload *ptype;
        __be16 type = skb->protocol;
        struct list_head *head = &offload_base;
        int same_flow;
        enum gro_result ret;
        int grow;

        if (netif_elide_gro(skb->dev))
                goto normal;

        gro_list_prepare(napi, skb);

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

                /**
                 * XXX
                 * Protocal (ptype) has callback function for GRO which take
                 * list of gro pkts from napi struct and make some decisions (
                 * for example, the TCP protocol will need to decide if/when to
                 * ACK a packet that is being coalesced into an existing
                 * packet. )
                 *
                 **/

                pp = ptype->callbacks.gro_receive(&napi->gro_list, skb);
                break;
        }
        rcu_read_unlock();

        if (&ptype->list == head)
                goto normal;

        if (IS_ERR(pp) && PTR_ERR(pp) == -EINPROGRESS) {
                ret = GRO_CONSUMED;
                goto ok;
        }

        same_flow = NAPI_GRO_CB(skb)->same_flow;
        ret = NAPI_GRO_CB(skb)->free ? GRO_MERGED_FREE : GRO_MERGED;

        /** XXX
         * If the protocol layers indicated that it is time to flush the GRO’d
         * packet, that is taken care of next. This happens with a call to
         * napi_gro_complete, which calls a gro_complete callback for the
         * protocol layers and then passes the packet up the stack by calling
         * netif_receive_skb.
         **/
        if (pp) {
                struct sk_buff *nskb = *pp;

                *pp = nskb->next;
                nskb->next = NULL;
                napi_gro_complete(nskb);
                napi->gro_count--;
        }


        if (same_flow)
                goto ok;

        /*XXX no more packet merges*/
        if (NAPI_GRO_CB(skb)->flush)
                goto normal;

        if (unlikely(napi->gro_count >= MAX_GRO_SKBS)) {
                struct sk_buff *nskb = napi->gro_list;

                /* locate the end of the list to select the 'oldest' flow */
                while (nskb->next) {
                        pp = &nskb->next;
                        nskb = *pp;
                }
                *pp = NULL;
                nskb->next = NULL;
                napi_gro_complete(nskb);
        } else {
                napi->gro_count++;
        }
        NAPI_GRO_CB(skb)->count = 1;
        NAPI_GRO_CB(skb)->age = jiffies;
        NAPI_GRO_CB(skb)->last = skb;
        skb_shinfo(skb)->gso_size = skb_gro_len(skb);
        /*XXX packets were not merged ,appending more in gro_list */
        skb->next = napi->gro_list;
        napi->gro_list = skb;

        ret = GRO_HELD;

pull:
        grow = skb_gro_offset(skb) - skb_headlen(skb);
        if (grow > 0)
                gro_pull_from_frag0(skb, grow);
ok:
        return ret;

normal:
        ret = GRO_NORMAL;
        goto pull;
}


/**
 * XXX napi_skb_finish get called on return of dev_gro_receive 
 * to free up memory or call netif_receive_skb_internal to push data
 * up in network stack
 *
 **/

static gro_result_t napi_skb_finish(gro_result_t ret, struct sk_buff *skb)
{
        switch (ret) {
        case GRO_NORMAL:
                //XXX pushing data upwords
                if (netif_receive_skb_internal(skb))
                        ret = GRO_DROP;
                break;

        case GRO_DROP:
                kfree_skb(skb);
                break;

        case GRO_MERGED_FREE:
                if (NAPI_GRO_CB(skb)->free == NAPI_GRO_FREE_STOLEN_HEAD)
                        napi_skb_free_stolen_head(skb);
                else
                        __kfree_skb(skb);
                break;

        case GRO_HELD:
        case GRO_MERGED:
        case GRO_CONSUMED:
                break;
        }

        return ret;
}

gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
        skb_mark_napi_id(skb, napi);
        trace_napi_gro_receive_entry(skb);

        skb_gro_reset_offset(skb);

        return napi_skb_finish(dev_gro_receive(napi, skb), skb);
}
EXPORT_SYMBOL(napi_gro_receive);



/** XXX note of RPS
 * 
 * RPS is implementation of RSS in software 
 *
 * RPS maintains hash function which will be used to load balance betweeen CPU
 * packet processing. It maintains hash table which is generated based on
 * incoming data. (this changes with RFS) 
 *
 * When hardware interrupt happens for packet and softirq for same packet start
 * executing on CPU core with above hash functions it detects desired CPU for
 * processing of packet and if its different then it raises Inter-processor
 * Interrupt 
 *
 * at bottom of net_rx_action()
 * net_rps_action_and_irq_enable takes softnet_data->rps_ipi_list and send it
 * to remote CPUs with net_rps_send_ipi()
 *
 * but this called after all net_rx_action -> polling -> gro activities get completed
 *
 *
 *
 * WARNING: enabling RPS to distribute packet processing to CPUs which were
 * previously not processing packets will cause the number of `NET_RX` softirqs
 * to increase for that CPU, as well as the `si` or `sitime` in the CPU usage
 * graph. You can compare before and after of your softirq and CPU usage graphs
 * to confirm that RPS is configured properly to your liking.
 *
 *
 *
 * XXX note on RFS
 *
 * for RPS system already maintaining hash table
 *
 * I thinks there is another hash table get maintained using same code base
 * based on IP flow so each flow can be processed by same CPU to improve data
 * locality .
 *
 *
 *
 * XXX here is problem 
 *
 * - we can load balance packet processing across CPUs by doing RSS
 * - we can pin point CPUs for core per queue using RPS and RFS
 * - but what is point ? I will never know which IP flow is going to which queue in advance 
 *   Only way to achive this by using aRFS 
 *
 *   looks like ntuple or aRFS can work without rules
 *
 *   
 **/



