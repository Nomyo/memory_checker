#define _GNU_SOURCE
#include <stdint.h>
#include <dlfcn.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>

void *malloc(size_t size)
{
  static void *(*malloc_ptr)(size_t size);
  void *addr;
  if (!malloc_ptr) /* get address of malloc */
    malloc_ptr = (void *(*) (size_t))dlsym(RTLD_NEXT, "malloc");
  addr = malloc_ptr(size);
  __asm__ __volatile__("push %r12");
  __asm__ __volatile__("push %r11");
  __asm__ __volatile__("push %r10");
  __asm__ __volatile__("mov $0xfffffffc0ffec01d ,%r10\n");
  __asm__ __volatile__("mov %0, %%r11;" : : "r" (size));
  __asm__ __volatile__("mov %0, %%r12;" : : "r" (addr));
  __asm__ __volatile__("int3");
  __asm__ __volatile__("pop %r10");
  __asm__ __volatile__("pop %r11");
  __asm__ __volatile__("pop %r12");
  __asm__ __volatile__("mov $0x0, %r10\n");
  return addr;
}

void free(void *addr)
{
  __asm__ __volatile__("push %r10");
  __asm__ __volatile__("mov $0xc01db3afffffffff, %r10\n");
  __asm__ __volatile__("int3");
  __asm__ __volatile__("pop %r10");
  __asm__ __volatile__("mov $0x0, %r10\n");
  static void (*free_ptr)(void *);
  if (!free_ptr) /* get address of free */
    free_ptr = (void (*) (void *))dlsym(RTLD_NEXT, "free");
  free_ptr(addr);
}

void *realloc(void *ptr, size_t size)
{
  static void *(*realloc_ptr)(void *ptr, size_t size);
  void *addr;
  if (!realloc_ptr) /* get address of realloc */
    realloc_ptr = (void *(*) (void *, size_t))dlsym(RTLD_NEXT, "realloc");
  addr = realloc_ptr(ptr, size);
  __asm__ __volatile__("push %r12");
  __asm__ __volatile__("push %r11");
  __asm__ __volatile__("push %r10");
  __asm__ __volatile__("mov $0x5417b3afffffffff, %r10\n");
  __asm__ __volatile__("mov %0, %%r11;" : : "r" (size));
  __asm__ __volatile__("mov %0, %%r12;" : : "r" (ptr));
  __asm__ __volatile__("mov %0, %%r9;" : : "r" (addr));
  __asm__ __volatile__("int3");
  __asm__ __volatile__("pop %r10");
  __asm__ __volatile__("pop %r11");
  __asm__ __volatile__("pop %r12");
  __asm__ __volatile__("mov $0x0, %r10\n");
  return addr;
}

void *calloc(size_t nmemb, size_t size)
{
  static void *(*calloc_ptr)(size_t nmemb, size_t size);
  void *addr;
  if (!calloc_ptr) /* get address of calloc */
    calloc_ptr = (void *(*) (size_t, size_t))dlsym(RTLD_NEXT, "calloc");
  addr = calloc_ptr(nmemb, size);
  __asm__ __volatile__("push %r12");
  __asm__ __volatile__("push %r11");
  __asm__ __volatile__("push %r10");
  __asm__ __volatile__("mov $0xc01dc01dc01dc01d, %r10\n");
  __asm__ __volatile__("mov %0, %%r11;" : : "r" (size));
  __asm__ __volatile__("mov %0, %%r12;" : : "r" (nmemb));
  __asm__ __volatile__("mov %0, %%r9;" : : "r" (addr));
  __asm__ __volatile__("int3");
  __asm__ __volatile__("pop %r10");
  __asm__ __volatile__("pop %r11");
  __asm__ __volatile__("pop %r12");
  __asm__ __volatile__("mov $0x0, %r10\n");
  return addr;
}
