#ifndef ALLOC_OBJ_HH
# define ALLOC_OBJ_HH

struct S_mem
{
  uintptr_t addr;
  unsigned long len;
  long int prot; /* for malloc, realloc or calloc this field
                    will be used to check if struct is set or not yet */
};

#endif /* !ALLOC_OBJ_HH */
