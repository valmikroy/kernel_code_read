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


