
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "api/api_types.h"
#include <stdint.h>
#include <stdbool.h>

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
  fd = open("/dev/security_monitor_dev", O_RDWR);
  FILE *ptr;
  ptr = fopen("/test/enclave.bin","rb");
  long int sizefile = size_file("/test/enclave.bin");
  printf("Size enclave.bin (%d)\n", sizefile);
  char* enclave = memalign(1<<12,sizefile);
  size_t sizecopied;
  sizecopied = fread(enclave, sizefile, 1, ptr); 
  printf("Size copied: %d", sizecopied);
  int iterateword;
  for (iterateword = 0; iterateword < 20; iterateword++) {
      printf("In user space: %x", *(((unsigned int*) enclave)+ iterateword));
  }
 
  fclose(ptr);
  printf("file descriptor fd(%d) %x\n", fd, (void*) enclave);
  if (fd < 0) {
     printf("File open error\n"); 
  }

  val.enclave_start = enclave;
  val.enclave_end = enclave + sizefile;
  printf("Sending ioctl CMD 2\n");
  ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);
  printf("ioctl ret val (%d) errno (%d)\n", ret, errno);
  perror("IOCTL error: ");
  close(fd);
}
