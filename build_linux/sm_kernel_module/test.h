#ifndef SM_TEST_H
#define SM_TEST_H

#include "platform/parameters.h"

void test_entry (void)  __attribute__((noreturn));

// #define PAGE_SIZE (1<<PAGE_SHIFT) // Already defined by Linux
#define REGION_SIZE (1<<REGION_SHIFT)
#define REGION_MASK (~(REGION_SIZE-1))

static inline uint64_t addr_to_region_id (uintptr_t addr) {
  return ((addr-RAM_BASE) & REGION_MASK) >> REGION_SHIFT; // will return an illegally large number in case of an address outside RAM. CAUTION!
}

static inline void * region_id_to_addr (uint64_t region_id) {
  return (void *)(RAM_BASE + (region_id << REGION_SHIFT));
}

#endif // SM_TEST_H
