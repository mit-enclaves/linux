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

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; };
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
  #define begin_shared 0xF000000
  #define shared_size 0x1000
  void* shared_enclave = mmap((void *)begin_shared, shared_size, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // 
  if (shared_enclave == MAP_FAILED) {
    perror("Shared memory not allocated in a correct place, last errno: ");
    exit(-1);
  }
  printf("Address for the shared enclave %p\n", shared_enclave);
  strcpy(shared_enclave, "A small test");
  val.enclave_start = (long)enclave;
  val.enclave_end = (long)(enclave + sizefile);
  printf("Sending ioctl CMD 2\n");
  fflush(stdout);
  ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);
  printf("ioctl ret val (%d) errno (%d)\n", ret, errno);
  if (ret == 0) {
    printf("Received from enclave: %s\n", (char *) shared_enclave); 
  }
  fflush(stdout);
  //perror("IOCTL error: ");
  close(fd);
}
