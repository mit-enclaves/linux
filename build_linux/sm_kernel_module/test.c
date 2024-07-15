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
#include <pthread.h>

#include "msgq/msgq.h"
#include "crypto_enclave_api.h"
#include "test.h"

// INPUTS
extern int len_a;
extern int len_elements[];
extern char *a[];

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; uintptr_t shared_memory; };
struct arg_region_update { api_result_t result; };
struct arg_region_owner { api_result_t result; enclave_id_t enc_id;};
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct run_enclave*)
#define IOCTL_REGION_UPDATE _IOR(MAJOR_NUM, 0x2, struct arg_region_update*)
#define IOCTL_REGION_OWNER  _IOR(MAJOR_NUM, 0x3, struct arg_region_owner*)

long int size_file(const char *file_name)
{
  // from https://www.includehelp.com/c-programs/find-size-of-file.aspx
  struct stat st;
  if(stat(file_name,&st)==0)
    return (st.st_size);
  else
    return -1;
}

void print_byte_array(const unsigned char *array, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X", array[i]);
    }
    printf("\n");
}

void *update_region(void *arg) {
  int *fd_t = (int *)arg;
  struct arg_region_update val;
  struct arg_region_owner val_owner;
  val_owner.enc_id = 0x3d; 
  do { 
    ioctl(*fd_t, IOCTL_REGION_OWNER, &val_owner);
    ioctl(*fd_t, IOCTL_REGION_UPDATE, &val);
  } while (val_owner.result == 1);
  while(1) {
    val_owner.enc_id++;
  };
  return 0;
}

int main()
{
  int fd, ret = 0;
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
  printf("Get PK\n");
  get_public_signing_key(key_id, pk);

  print_byte_array(pk->bytes,LENGTH_PK);

  msg_t *m; 
  queue_t *qresp = SHARED_RESP_QUEUE;
  int res;

  // *** BEGINING BENCHMARK ***
  //riscv_perf_cntr_begin();

  printf("Sign random string ");
  print_byte_array(a[0], len_elements[0]);
#define N 1
  for(int i = 0; i < N; i++) {
    sign(a[i%len_a], len_elements[i%len_a], key_id, s); 
  }   

  //printf("Send Enclave Exit\n");
  enclave_exit();
  
  printf("Done sending RPC\n");

  pthread_t thread_id;
  // Create the second thread
  if (pthread_create(&thread_id, NULL, update_region, &fd) != 0) {
     fprintf(stderr, "Error creating thread\n");
     return 1;
  }
  
  //printf("Right now in shared memory: %s\n", (char *) shared_enclave); 
  struct arg_start_enclave val;
  val.shared_memory = (long) shared_enclave;
  val.enclave_start = (long)enclave;
  val.enclave_end = (long)(enclave + sizefile);
  //printf("Sending ioctl CMD 2\n");
  fflush(stdout);
  ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);
  //printf("ioctl ret val (%d) errno (%d)\n", ret, errno);
  if (ret == 0) {
    do {
      res = pop(qresp, (void **) &m);
      if((res == 0) && (m->f == F_SIGN)) {
        printf("Signature \n");
	print_byte_array(s->bytes, 64);
      }
    } while((res != 0) || (m->f != F_EXIT));
  }
  fflush(stdout);
  //perror("IOCTL error: ");
  close(fd);
  }
