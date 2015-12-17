#define _GNU_SOURCE
#include <stdint.h>
#include <dlfcn.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>

void *malloc(size_t size)
{
  __asm__ __volatile__("mov $0xfffffffc01dc0ffe, %r10\n");
  __asm__ __volatile__("int3");  
  __asm__ __volatile__("mov $0x0, %r10\n");  

  static void *(*malloc_ptr)(size_t size);
  void *addr;
  if (!malloc_ptr) /* get address of malloc */
    malloc_ptr = (void *(*) (size_t))dlsym(RTLD_NEXT, "malloc");
  addr = malloc_ptr(size);

  __asm__ __volatile__("mov $0xfffffffc0ffec01d ,%r10\n");
  __asm__ __volatile__("int3");
  __asm__ __volatile__("mov $0x0, %r10\n");
  return addr;
}

void free(void *addr)
{
  __asm__ __volatile__("mov $0xc01db3afffffffff, %r10\n");
  __asm__ __volatile__("int3");
  __asm__ __volatile__("mov $0x0, %r10\n");

  static void (*free_ptr)(void *);
  if (!free_ptr) /* get address of free */
    free_ptr = (void (*) (void *))dlsym(RTLD_NEXT, "free");
  free_ptr(addr);
}

void *realloc(void *ptr, size_t size)
{
  __asm__ __volatile__("mov $0xffffffff5417b3af, %r10\n");
  __asm__ __volatile__("int3");  
  __asm__ __volatile__("mov $0x0, %r10\n");  

  static void *(*realloc_ptr)(void *ptr, size_t size);
  void *addr;
  if (!realloc_ptr) /* get address of malloc */
    realloc_ptr = (void *(*) (void *, size_t))dlsym(RTLD_NEXT, "realloc");
  addr = realloc_ptr(ptr, size);

  __asm__ __volatile__("mov $0x5417b3afffffffff, %r10\n");
  __asm__ __volatile__("int3");
  __asm__ __volatile__("mov $0x0, %r10\n");
  return addr;
}
