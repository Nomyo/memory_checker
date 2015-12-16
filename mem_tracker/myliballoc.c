#include <stdint.h>
#include <dlfcn.h>

void *malloc(size_t size)
{
  static void *(*malloc_ptr)(size_t size);
  void *addr;
 
  if (!malloc_ptr) /* get address of malloc */
    malloc_ptr = (void *(*) (size_t))dlsym(RTLD_NEXT, "malloc");
  
  addr = malloc_ptr(size);
  
  return addr;
}

void free(void *addr)
{
  static void (*free_ptr)(void *);
   
  if (!free_ptr) /* get address of free */
    free_ptr = (void (*) (void *))dlsym(RTLD_NEXT, "free");
  
 free_ptr(addr);
}
