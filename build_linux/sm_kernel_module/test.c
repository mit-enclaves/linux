#include <string.h>
#include <malloc.h>
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

// INPUTS
extern int len_a;
extern int len_elements[];
extern char *a[];

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

int main()
{
  int fd, ret = 0;
  struct arg_start_enclave val;
  fd = open("/dev/security_monitor", O_RDWR);
  printf("file descriptor fd(%d)\n", fd);
  if (fd < 0) {
    printf("File open error with errno %d\n", errno);
    return -errno;
  }

  FILE *ptr;
  ptr = fopen("/test/enclave.bin","rb");
  long int sizefile = size_file("/test/enclave.bin");
  printf("Size enclave.bin (%ld)\n", sizefile);
  char* enclave = memalign(1<<12,sizefile);
  size_t sizecopied;
  sizecopied = fread(enclave, sizefile, 1, ptr);
  printf("Size copied: %ld\n", sizecopied);
  int iterateword;
  for (iterateword = 0; iterateword < 20; iterateword++) {
    printf("In user space: %x\n", *(((unsigned int*) enclave)+ iterateword));
  }

  fclose(ptr);
  /* Allocate memory to share with the enclave. Need to find a proper place for that */
#define shared_size 0x1000
  void* shared_enclave = mmap((void *)SHARED_MEM_REG, shared_size, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (shared_enclave == MAP_FAILED) {
    perror("Shared memory not allocated in a correct place, last errno: ");
    exit(-1);
  }
  printf("Address for the shared memory with the enclave %p\n", shared_enclave);
 
#define EVBASE 0x20000000

  void* enclave_address_space = mmap((void *)EVBASE, REGION_SIZE, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (enclave_address_space == MAP_FAILED) {
    perror("Enclave virtual memory not reserved...\n");
    exit(-1);
  }
  
  // Enqueue requests for enclave
  // key_seed_t *seed = malloc(sizeof(key_seed_t));
  uint64_t key_id = 0;
  public_key_t *pk = malloc(sizeof(public_key_t));
  signature_t *s = malloc(sizeof(signature_t)); 

  printf("Creat SK\n");
  create_signing_key_pair(NULL, &key_id);
  printf("Creat PK\n");
  get_public_signing_key(key_id, pk);

  msg_t *m; 
  queue_t *qresp = SHARED_RESP_QUEUE;
  int res;

  // *** BEGINING BENCHMARK ***
  //riscv_perf_cntr_begin();

  //printf("Sign\n");
#define N 32
  for(int i = 0; i < N; i++) {
    sign(a[i%len_a], len_elements[i%len_a], key_id, s); 
  }   

  //printf("Verify SK\n");
  verify(s, a[N-1%len_a], len_elements[N-1%len_a], pk);

  //printf("Send Enclave Exit\n");
  enclave_exit();
  
  printf("Done sending RPC\n");

  //printf("Right now in shared memory: %s\n", (char *) shared_enclave); 
  val.shared_memory = (long) shared_enclave;
  val.enclave_start = (long)enclave;
  val.enclave_end = (long)(enclave + sizefile);
  printf("Sending ioctl CMD 2\n");
  fflush(stdout);
  ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);
  printf("ioctl ret val (%d) errno (%d)\n", ret, errno);
  if (ret == 0) {
    do {
      res = pop(qresp, (void **) &m);
      if((res == 0) && (m->f == F_VERIFY)) {
        printf("result %d\n", m->ret);
      }
    } while((res != 0) || (m->f != F_EXIT));
  }
  fflush(stdout);
  //perror("IOCTL error: ");
  close(fd);
  }
