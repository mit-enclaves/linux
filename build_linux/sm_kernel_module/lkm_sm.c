#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/fs.h>
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/err.h>

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "api/api_untrusted.h"

#include "test.h"

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; };
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct arg_stat_enclave*)

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Computer Structure Group CSAIL");
MODULE_DESCRIPTION("Security Monitor");


static struct device *security_monitor_dev;

void start_enclave(struct arg_start_enclave *arg)
{

  printk(KERN_INFO "Start routine start_enclave");
  dma_addr_t dma_addr;

  void* addr = dma_alloc_coherent(security_monitor_dev, 4*0x2000, &dma_addr, GFP_KERNEL);
  if (addr == 0) {
    printk(KERN_ALERT "Error dma allocation");
    return (int)addr;
  }
  uintptr_t region2;
  uintptr_t region3;
  if ( (unsigned long long) addr % 0x2000000 == 0) {
    region2 = (uintptr_t) dma_addr;
    region3 = (uintptr_t) dma_addr+0x2000000;
  } else {
    unsigned long long aligned_dma_addr = ((((unsigned long long) dma_addr)/0x2000000)+1)*0x2000000; 
    region2 = (uintptr_t) aligned_dma_addr;
    region3 = (uintptr_t) aligned_dma_addr+0x2000000;
  }

  printk(KERN_INFO "Address region1 is %x",region2);
  printk(KERN_INFO "Address region2 is %x",region3);
  uint64_t region2_id = addr_to_region_id((uintptr_t) region2);
  uint64_t region3_id = addr_to_region_id((uintptr_t) region3);
  arg->result = sm_region_block(region3_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_block FAILED with error code %d\n", arg->result);
    return; 
  }

  arg->result = sm_region_free(region3_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_free FAILED with error code %d\n ", arg->result);
    return;
  }

  arg->result = sm_region_metadata_create(region3_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_metadata_create FAILED with error code %d\n",arg->result);
    return; 
  }

  uint64_t region_metadata_start = sm_region_metadata_start();
  printk(KERN_INFO "Address metadata is %x",region_metadata_start);
  enclave_id_t enclave_id = ((uintptr_t) region3) + (PAGE_SIZE * region_metadata_start);
  uint64_t num_mailboxes = 1;
  uint64_t timer_limit = 10000;

  arg->result = sm_enclave_create(enclave_id, 0x0, REGION_MASK, num_mailboxes, timer_limit, true);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_create FAILED with error code %d\n", arg->result);
    return;
  }

  arg->result = sm_region_block(region2_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_block FAILED with error code %d\n", arg->result);
    return;
  }

  arg->result = sm_region_free(region2_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_free FAILED with error code %d\n", arg->result);
    return; 
  }

  arg->result = sm_region_assign(region2_id, enclave_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_assign FAILED with error code %d\n", arg->result);
    return; 
  }

  uintptr_t enclave_handler_address = (uintptr_t) region2;
  uintptr_t enclave_handler_stack_pointer = enclave_handler_address + HANDLER_LEN + STACK_SIZE;

  arg->result = sm_enclave_load_handler(enclave_id, enclave_handler_address);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_handler FAILED with error code %d\n", arg->result);
    return; 
  }

  uintptr_t page_table_address = enclave_handler_stack_pointer;

  arg->result = sm_enclave_load_page_table(enclave_id, page_table_address, 0, 3, NODE_ACL);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", arg->result);
    return; 
  }

  page_table_address += PAGE_SIZE;

  arg->result = sm_enclave_load_page_table(enclave_id, page_table_address, 0, 2, NODE_ACL);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", arg->result);
    return; 
  }

  page_table_address += PAGE_SIZE;

  arg->result = sm_enclave_load_page_table(enclave_id, page_table_address, 0, 1, NODE_ACL);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", arg->result);
    return; 
  }

  uintptr_t phys_addr = page_table_address + PAGE_SIZE;
  uintptr_t os_addr = (uintptr_t) arg->enclave_start;
  uintptr_t virtual_addr = 0;

  printk(KERN_INFO "Start loading program\n");

  int num_pages_enclave = (((uint64_t) arg->enclave_end) - ((uint64_t) arg->enclave_start)) / PAGE_SIZE;
  int page_count;
  for(page_count = 0; page_count < num_pages_enclave; page_count++) {

    arg->result = sm_enclave_load_page(enclave_id, phys_addr, virtual_addr, os_addr, LEAF_ACL);
    if(arg->result != MONITOR_OK) {
      printk(KERN_ALERT "sm_enclave_load_page FAILED with error code %d\n", arg->result);
      return; 
    }

    printk(KERN_INFO "Just loaded a page\n");
    phys_addr    += PAGE_SIZE;
    os_addr      += PAGE_SIZE;
    virtual_addr += PAGE_SIZE;

  }

  uint64_t size_enclave_metadata = sm_enclave_metadata_pages(num_mailboxes);

  thread_id_t thread_id = enclave_id + (size_enclave_metadata * PAGE_SIZE);

  arg->result = sm_thread_load(enclave_id, thread_id, 0x0, 0x1000, enclave_handler_address, enclave_handler_stack_pointer);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_thread_load FAILED with error code %d\n", arg->result);
    return; 
  }

  printk(KERN_INFO "Enclave init\n");
  arg->result = sm_enclave_init(enclave_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_init FAILED with error code %d\n", arg->result);
    return; 
  }

  printk(KERN_INFO "Enclave enter\n");
  arg->result = sm_enclave_enter(enclave_id, thread_id);
  printk(KERN_INFO "Enclaved finished executing with : %d\n", arg->result); 
  return;
}

static long sm_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static ssize_t sm_read(struct file * file, char * buf, size_t count, loff_t *ppos){
    printk(KERN_INFO "read dummy sm");
}
static struct file_operations fops =
  {
   .owner          = THIS_MODULE,
   .read           = sm_read,
   .write          = NULL,
   .open           = NULL,
   .unlocked_ioctl = sm_ioctl,
   .release        = NULL,
  };


static struct miscdevice security_monitor_misc = {
	.name = "security_monitor",
	.fops = &fops,
    .minor =  MISC_DYNAMIC_MINOR,
};

static long sm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        unsigned long bytes_from_user;
        unsigned long bytes_to_user;

        struct arg_start_enclave arg_struct;
         switch(cmd) {
                case IOCTL_START_ENCLAVE:
                        bytes_from_user = copy_from_user(&arg_struct ,(int32_t*) arg, sizeof(arg_struct));
                        if (bytes_from_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }

                        dma_addr_t dma_addr;
                        size_t size_enclave =  arg_struct.enclave_end - arg_struct.enclave_start;

                        printk(KERN_INFO "Allocate physical memory for binary image\n");
                        void* addr = dma_alloc_coherent(security_monitor_dev, size_enclave/0x1000, &dma_addr, GFP_KERNEL);
                        if (addr == 0) {
                          printk(KERN_ALERT "Error dma allocation");
                          return (int)addr;
                        }
                        printk(KERN_INFO "Copy image from user\n");
                        bytes_from_user = copy_from_user(addr, (char*) arg_struct.enclave_start, size_enclave);
                        if (bytes_from_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }
                        int iterateword;
                        for (iterateword = 0; iterateword < 20; iterateword++) {
                            printk(KERN_INFO "In kernel space: %x", *(((unsigned int*) addr)+ iterateword));
                        }
                        arg_struct.enclave_start = dma_addr;
                        arg_struct.enclave_end = dma_addr + size_enclave;
                        printk(KERN_INFO "Start enclave\n");
                        start_enclave(&arg_struct);
                        printk(KERN_INFO "Free physical memory for binary image\n");
                        dma_free_coherent(security_monitor_dev, size_enclave, addr, dma_addr);
                        bytes_to_user = copy_to_user((void*) arg, &arg_struct, sizeof(arg_struct));
                        if (bytes_to_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }
                        break;
        }
        return 0;
}


static int __init sm_mod_init(void)
{
  int region;
  int ret_val;
  printk(KERN_INFO "Kernel module try to do some enclave stuff!\n");

  for(region = 0; region < 64; region++) {
    int result = sm_region_owner(region);
    printk(KERN_INFO "Owner of region %d is %d\n", region, result);
  }

  ret_val = misc_register(&security_monitor_misc);
  if (unlikely(ret_val)) {
  	pr_err("failed to register security monitor misc device!\n");
  	return ret_val;
  }
  security_monitor_dev = security_monitor_misc.this_device;
  security_monitor_dev->coherent_dma_mask = ~0;
  _dev_info(security_monitor_dev, "registered.\n");

  return 0;
}

static void __exit sm_mod_cleanup(void)
{
  printk(KERN_INFO "Cleaning up module.\n");

  misc_deregister(&security_monitor_misc);}

module_init(sm_mod_init);
module_exit(sm_mod_cleanup);
