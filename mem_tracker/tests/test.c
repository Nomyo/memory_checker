#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
  void *addr = malloc(1420);
  void *addre = malloc(9999);
  free(addre);
  addre = realloc(NULL, 1000);
  addre = realloc(addre, 0);
  void *callocptr = calloc(10, 100);
  free(callocptr);
  free(addr);
  char *ptr = (char *)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  mprotect(ptr, 102, PROT_NONE);
  return 0;
}
