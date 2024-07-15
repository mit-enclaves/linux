#include "platform_lock.h"

uint64_t hartid;

void init_p_lock_global(int core_id) {
  hartid = core_id;
}

// Implementation of Peterson's lock for two cores.
void platform_p_lock_init(volatile platform_p_lock_t *lock) {
  lock->flag[0] = false;
  lock->flag[1] = false;
  lock->turn = 0;
  asm volatile("fence");
}

void platform_p_lock_acquire(volatile platform_p_lock_t *lock) {
  int other_hartid = (hartid + 1) % 2;
  lock->flag[hartid] = true;
  lock->turn = other_hartid;
  asm volatile("fence");
  while ((lock->flag[other_hartid] == true) && (lock->turn == other_hartid)) {};
}

void platform_p_lock_release(volatile platform_p_lock_t *lock) {
  lock->flag[hartid] = false;
  asm volatile("fence");
}
