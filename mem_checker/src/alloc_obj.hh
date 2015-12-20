#ifndef ALLOC_OBJ_HH
# define ALLOC_OBJ_HH

struct S_mem
{
  uintptr_t addr;    // start adress the memory block
  unsigned long len; // length of allocate memory
  long int prot;     // protection
};

#endif /* !ALLOC_OBJ_HH */
