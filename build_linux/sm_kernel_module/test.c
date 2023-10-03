#define _GNU_SOURCE
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include "api/api_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "msgq/msgq.h"
#include "crypto_enclave_api.h"
#include "test.h"

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; uintptr_t shared_memory; };
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct run_enclave*)

long int size_file(const char *file_name)
{
  // from https://www.includehelp.com/c-programs/find-size-of-file.aspx
  struct stat st;
  if(stat(file_name,&st)==0)
    return (st.st_size);
  else
    return -1;
}

// Function for the thread running the enclave
void* enclave_thread(void *arg) {
  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();  // Get current thread
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);

  if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
    printf("[Core 0] Pthread affinity falure\n");
  }
  
  int fd, ret = 0;
  fd = open("/dev/security_monitor", O_RDWR);
  printf("[Core 0] File descriptor fd(%d)\n", fd);
  if (fd < 0) {
    printf("[Core 0] File open error with errno %d\n", errno);
    return NULL;
  }

  FILE *ptr;
  ptr = fopen("/test/enclave.bin","rb");
  long int sizefile = size_file("/test/enclave.bin");
  printf("[Core 0] Size enclave.bin (%ld)\n", sizefile);
  char* enclave = memalign(1<<12,sizefile);
  size_t sizecopied;
  sizecopied = fread(enclave, sizefile, 1, ptr);
  fclose(ptr);

  //printf("Right now in shared memory: %s\n", (char *) shared_memory); 
  struct arg_start_enclave val;
  val.shared_memory = (long) SHARED_MEM_REG;
  val.enclave_start = (long)enclave;
  val.enclave_end = (long)(enclave + sizefile);

  printf("[Core 0] Asking the SM Kernel Module to launch the enclave.\n");
  fflush(stdout);
  ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);
  printf("[Core 0] SM Kernel Module returned with val (%d) errno (%d)\n", ret, errno);
  //perror("IOCTL error: ");
  close(fd);

  return NULL;
}

// Function for the thread interacting with the user
void* user_thread(void* arg) {
  
  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();  // Get current thread
  CPU_ZERO(&cpuset);
  CPU_SET(1, &cpuset);

  if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
    printf("[Core 1] Pthread affinity falure\n");
  }

  char command[256];
  char message[256];
  
  // Enqueue requests for enclave
  mem_pool_t *mem = (mem_pool_t *)MEM_POOL;

  // key_seed_t *seed = &mem->seed;
  uint64_t key_id = 0;

  printf("[Core 1] RPC Create SK\n");
  create_signing_key_pair(NULL, &key_id);

  msg_t *m; 
  queue_t *qresp = SHARED_RESP_QUEUE;

  int res;
  do {
    res = pop(qresp, (void **) &m);
  } while((res != 0) || m->f != F_CREATE_SIGN_K);

  printf("[Core 1] Enclave is ready!\n");
  
  printf("[Core 1] Requesting the enclave PK\n");
  public_key_t *pk = &mem->pk;
  get_public_signing_key(key_id, pk);

  printf("[Core 1] Requesting the enclave to sign \"Hello World!\"\n");
  strcpy(message, "Hello World!");
  int lenght = strlen(message);
  signature_t *s = &mem->s;
  sign(message, lenght, key_id, s);
      
  do {
    res = pop(qresp, (void **) &m);
    if((res == 0) && (m->f == F_SIGN)) {
      printf("[Core 1] Signature received from the enclave :\n");
      for (size_t i = 0; i < 64; i++) {
        printf("%02X",((signature_t *) m->args[3])->bytes[i]);
      }
      printf("\n");
    } else if((res == 0) && (m->f == F_HASH)) {
      printf("[Core 1] Hash received from the enclave :\n");
      for (size_t i = 0; i < 64; i++) {
        printf("%02X",((hash_t *) m->args[1])->bytes[i]);
      }
      printf("\n");
    } else if((res == 0) && (m->f == F_GET_SIGN_PK)) {
      printf("[Core 1] Public key from the enclave :\n");
      for (size_t i = 0; i < LENGTH_PK; i++) {
        printf("%02X",((signature_t *) m->args[1])->bytes[i]);
      }
      printf("\n");
    } else if((res == 0) && (m->f == F_EXIT)) {
      printf("[Core 1] Enclave exited correctly!\n");
      fflush(stdout);
      return NULL;
    }
  } while((res != 0) || m->f != F_SIGN);
  
  enclave_exit();
  
  do {
    res = pop(qresp, (void **) &m);
    if((res == 0) && (m->f == F_EXIT)) {
      printf("[Core 1] Enclave exited correctly!\n");
      fflush(stdout);
      return NULL;
    }
  } while((res != 0) || m->f != F_SIGN);
  
  fflush(stdout);
  return NULL;
}

int main()
{
  /* Allocate memory to share with the enclave. Need to find a proper place for that */
#define shared_size 0x10000
  void* shared_memory = mmap((void *)SHARED_MEM_REG, shared_size, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (shared_memory == MAP_FAILED) {
    perror("Shared memory not allocated in a correct place, last errno: ");
    exit(-1);
  }
  printf("Address for the shared memory with the enclave %p\n", shared_memory);
  memset(shared_memory, 0, shared_size);

  void* memory_pool_m = mmap((void *)MEM_POOL, shared_size, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (memory_pool_m == MAP_FAILED) {
    perror("Shared memory not allocated in a correct place, last errno: ");
    exit(-1);
  }
  printf("Address for the memory pool %p\n", memory_pool_m);
  memset(memory_pool_m, 0, shared_size);

#define EVBASE 0x20000000

  void* enclave_address_space = mmap((void *)EVBASE, REGION_SIZE, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (enclave_address_space == MAP_FAILED) {
    perror("Enclave virtual memory not reserved...\n");
    exit(-1);
  }

  pthread_t thread1, thread2;

  // Create threads
  if (pthread_create(&thread1, NULL, &enclave_thread, NULL)) {
    fprintf(stderr, "Error creating enclave thread\n");
    return 1;
  }

  if (pthread_create(&thread2, NULL, &user_thread, NULL)) {
    fprintf(stderr, "Error creating user thread\n");
    return 1;
  }

  // Wait for the threads to finish
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);

  return 0;
}
