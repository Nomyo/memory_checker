#ifndef ALLOC_OBJ_HH
# define ALLOC_OBJ_HH

struct S_mem
{
  uintptr_t addr;
  unsigned long len;
  long int prot;
};

#endif /* !ALLOC_OBJ_HH */
