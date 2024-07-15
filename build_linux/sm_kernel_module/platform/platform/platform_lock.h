#ifndef PLATFORM_LOCK_H
#define PLATFORM_LOCK_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
  uint64_t lock_flag;
  uint64_t _pad[7];
} platform_lock_t;

#define platform_lock_acquire(lock) ({ unsigned long __tmp; \
      asm volatile ("amoswap.w.aq %[result], %[value], (%[address]) \n": [result] "=r"(__tmp) : [value] "r"(1), [address] "r"(&((lock)->lock_flag))); \
      (__tmp == 0); })

#define platform_lock_release(lock) ({ \
      asm volatile ("amoswap.w.rl x0, x0, (%[address]) \n" :: [address] "r"(&((lock)->lock_flag))); })

static inline bool platform_lock_state(platform_lock_t *lock) {
  return ((lock->lock_flag) != 0);
}

// Peterson's lock for Secure Shared Memory:

typedef struct {
  volatile uint64_t flag[2];
  volatile uint64_t turn;
  uint64_t _pad[5];
} platform_p_lock_t;

void init_p_lock_global(int core_id);

// Implementation of Peterson's lock for two cores.
void platform_p_lock_init(volatile platform_p_lock_t *lock);
void platform_p_lock_acquire(volatile platform_p_lock_t *lock);
void platform_p_lock_release(volatile platform_p_lock_t *lock);

#endif // PLATFORM_LOCK_H
