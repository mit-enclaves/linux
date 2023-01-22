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
#include <linux/cma.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>

#include "api/api_untrusted.h"

#include "test.h"

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; };
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct arg_stat_enclave*)

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Computer Structure Group CSAIL");
MODULE_DESCRIPTION("Security Monitor");


static struct device *security_monitor_dev;

static uintptr_t region1 = 0;
static uintptr_t region2 = 0;
void start_enclave(struct arg_start_enclave *arg)
{
  uint64_t region2_id, region1_id;
  enclave_id_t enclave_id;
  uintptr_t enclave_handler_address;
  uintptr_t page_table_address;
  uint64_t region_metadata_start, num_mailboxes;
  uintptr_t phys_addr, os_addr, virtual_addr;
  int num_pages_enclave, page_count;
  uintptr_t entry_stack, stack_phys_addr, enclave_stack, entry_pc;
  uint64_t size_enclave_metadata, timer_limit;
  thread_id_t thread_id;

  printk(KERN_INFO "Start routine start_enclave");
  if(region1 ==0 && region2 == 0) {
  dma_addr_t dma_addr;
  void* addr = dma_alloc_coherent(security_monitor_dev, 0x5000000, &dma_addr, GFP_KERNEL);
  if (dma_addr == 0) {
    printk(KERN_ALERT "Error allocation");
    return;
  }
  printk(KERN_INFO "dma addr is %llx",dma_addr);
  if ( (unsigned long long) addr % 0x2000000 == 0) {
    region1 = (uintptr_t) dma_addr;
    region2 = (uintptr_t) dma_addr+0x2000000;
  } else {
    unsigned long long aligned_dma_addr = ((((unsigned long long) dma_addr)/0x2000000)+1)*0x2000000; 
    region1 = (uintptr_t) aligned_dma_addr;
    region2 = (uintptr_t) aligned_dma_addr+0x2000000;
  }
  printk(KERN_INFO "Address region1 is %lx",region1);
  printk(KERN_INFO "Address region2 is %lx",region2);
  region2_id = addr_to_region_id((uintptr_t) region2);
  arg->result = sm_region_block(region2_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_block FAILED with error code %d\n", arg->result);
    return; 
  }

  arg->result = sm_region_free(region2_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_free FAILED with error code %d\n ", arg->result);
    return;
  }

  arg->result = sm_region_metadata_create(region2_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_metadata_create FAILED with error code %d\n",arg->result);
    return; 
  }
  }
  region1_id = addr_to_region_id((uintptr_t) region1);
  region_metadata_start = sm_region_metadata_start();
  printk(KERN_INFO "Address metadata is %llx",region_metadata_start);
  enclave_id = ((uintptr_t) region2) + (PAGE_SIZE * region_metadata_start);
  num_mailboxes = 1;

  arg->result = sm_enclave_create(enclave_id, 0x0, ~0xFFFFFF/*REGION_MASK*/, num_mailboxes, true);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_create FAILED with error code %d\n", arg->result);
    return;
  }

  arg->result = sm_region_block(region1_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_block FAILED with error code %d\n", arg->result);
    return;
  }

  arg->result = sm_region_free(region1_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_free FAILED with error code %d\n", arg->result);
    return; 
  }

  arg->result = sm_region_assign(region1_id, enclave_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_assign FAILED with error code %d\n", arg->result);
    return; 
  }

  enclave_handler_address = (uintptr_t) region1;
  page_table_address = enclave_handler_address + (STACK_SIZE * NUM_CORES) + HANDLER_LEN;

  arg->result = sm_enclave_load_handler(enclave_id, enclave_handler_address);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_handler FAILED with error code %d\n", arg->result);
    return; 
  }

  printk(KERN_INFO "Enclave Page Table Root is %lx",page_table_address);

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

  phys_addr = page_table_address + PAGE_SIZE;
  os_addr = (uintptr_t) arg->enclave_start;
  virtual_addr = 0;

  printk(KERN_INFO "Start loading program\n");

  num_pages_enclave = ((((uint64_t) arg->enclave_end) - ((uint64_t) arg->enclave_start)) / PAGE_SIZE);
  
  if(((((uint64_t) arg->enclave_end) - ((uint64_t) arg->enclave_start)) % PAGE_SIZE) != 0) {
    printk(KERN_ALERT "Enclave binary is not page aligned");
    return;
  }
  
  // Load page table entry for stack
  entry_stack = 0x200000; 
  stack_phys_addr = phys_addr;
  arg->result = sm_enclave_load_page_table(enclave_id, stack_phys_addr, entry_stack - PAGE_SIZE, 0, LEAF_ACL);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", arg->result);
    return; 
  }

  phys_addr += PAGE_SIZE;
  enclave_stack = virtual_addr;
  printk(KERN_INFO "Enclave Stack Pointer %lx\n", enclave_stack);
  
  entry_pc = virtual_addr;
  
  for(page_count = 0; page_count < num_pages_enclave; page_count++) {

    arg->result = sm_enclave_load_page(enclave_id, phys_addr, virtual_addr, os_addr, LEAF_ACL);
    if(arg->result != MONITOR_OK) {
      printk(KERN_ALERT "sm_enclave_load_page FAILED with error code %d\n", arg->result);
      return; 
    }

    printk(KERN_INFO "Just loaded page %x\n", page_count);
    phys_addr    += PAGE_SIZE;
    os_addr      += PAGE_SIZE;
    virtual_addr += PAGE_SIZE;

  }

  size_enclave_metadata = sm_enclave_metadata_pages(num_mailboxes);

  thread_id = enclave_id + (size_enclave_metadata * PAGE_SIZE);
  
  timer_limit = 40000000;

  arg->result = sm_thread_load(enclave_id, thread_id, entry_pc, entry_stack, timer_limit);
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

  arg->result = sm_thread_delete(thread_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_thread_delete FAILED with error code %d\n", arg->result);
    return;
  }

  printk(KERN_INFO "delete thread\n");
  arg->result = sm_enclave_delete(enclave_id);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_delete FAILED with error code %d\n", arg->result);
    return; 
  }

  printk(KERN_INFO "delete enclave\n");

  arg->result = sm_region_assign(region1_id, OWNER_UNTRUSTED);
  if(arg->result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_assign FAILED with error code %d\n", arg->result);
    return; 
  }
  printk(KERN_INFO "reassign region to untrusted \n");

  //dma_free_coherent(security_monitor_dev, 0x5000000,  addr, dma_addr);
  return;
}

static long sm_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static ssize_t sm_read(struct file * file, char * buf, size_t count, loff_t *ppos){
    printk(KERN_INFO "read dummy sm");
    return 0;
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
        //local_irq_disable();

        unsigned long bytes_from_user, bytes_to_user;
        dma_addr_t dma_addr;
        size_t size_enclave;
        void* addr;
        int iterateword;

        struct arg_start_enclave arg_struct;
         switch(cmd) {
                case IOCTL_START_ENCLAVE:
                        bytes_from_user = copy_from_user(&arg_struct ,(int32_t*) arg, sizeof(arg_struct));
                        if (bytes_from_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }

                        size_enclave =  arg_struct.enclave_end - arg_struct.enclave_start;

                        printk(KERN_INFO "Allocate physical memory for binary image\n");
                        addr = dma_alloc_coherent(security_monitor_dev, size_enclave, &dma_addr, GFP_KERNEL);
                        if (addr == 0) {
                          printk(KERN_ALERT "Error dma allocation");
                          return (long int)addr;
                        }
                        printk(KERN_INFO "Copy image from user\n");
                        bytes_from_user = copy_from_user(addr, (char*) arg_struct.enclave_start, size_enclave);
                        if (bytes_from_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }
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
        //local_irq_enable();
        printk(KERN_INFO "renable timer interrupts\n");
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
