#include "track.hh"
#include "alloc_obj.hh"

void Tracker::wrap_mmap(struct user_regs_struct regs)
{
  struct S_mem s;
  s.addr = regs.rax;
  s.len = regs.rsi;
  s.prot = regs.rdx;
  if (-regs.rax == ENOMEM)
    return;
  else
  {
    ls_mem_.push_back(s);
    mem_alloc_ += s.len;
    un_protect(s, regs);
  }
}


void Tracker::wrap_munmap(struct user_regs_struct regs)
{
  unsigned long addr_b = regs.rdi;
  unsigned long len = regs.rsi;
  unsigned long addr_e = addr_b + len - 1;
  std::list<std::list<S_mem>::iterator> l_it;
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (addr_e >= i->addr + i->len && i->addr + i->len >= addr_b
        && addr_e >= i->addr && i->addr >= addr_b)
    {
      l_it.push_back(i);
      mem_alloc_ -= i->len;
    }
    else if (i->addr + i->len > addr_e && i->addr <= addr_e  && i->addr >= addr_b)
    {
      i->addr = addr_e;
      mem_alloc_ -= i->len;
      i->len = i->addr + i->len - addr_e;
      mem_alloc_ += i->len; 
        }
    else if (addr_e >= i->addr + i->len && i->addr + i->len >= addr_b && i->addr < addr_b)
    {
      mem_alloc_ -= i->len;
      i->len = i->addr + i->len - addr_b;
      mem_alloc_ += i->len; 
    }
    else if (i->addr + i->len > addr_e && i->addr < addr_e && addr_b > i->addr) /* split */
    {
      unsigned long tmp = i->len;
      mem_alloc_ -= i->len;
      i->len = addr_b - i->addr;
      struct S_mem s;
      s.addr = addr_e;
      s.len = i->addr + tmp - addr_e;
      mem_alloc_ -= s.len;
      s.prot = i->prot;
      mem_alloc_ += i->len + s.len;
      ls_mem_.push_back(s);
    }
  }
  for (auto& i : l_it) /* erase all maps that are unmap */
    ls_mem_.erase(i);
}

void Tracker::wrap_mprotect(struct user_regs_struct regs)
{
  unsigned long addr_b = regs.rdi;
  unsigned long len = regs.rsi;
  int prot = regs.rdx;
  unsigned long addr_e = addr_b + len - 1;
  if (-regs.rax == ENOMEM) /* if -ENOMEM mprotect failed */
    return;
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  { 
    if (addr_e >= i->addr + i->len && i->addr + i->len >= addr_b
        && addr_e >= i->addr && i->addr >= addr_b)
    {
      i->prot = prot;
    }
    else if (i->addr + i->len > addr_e && i->addr <= addr_e  && i->addr >= addr_b)
    {
      if (i->prot != prot) /* do not split */
      {
        struct S_mem s;
        s.addr = addr_e;
        s.len = i->len + i->addr - s.addr;
        s.prot = prot;
        ls_mem_.push_front(s);
        i->len = i->len - s.len;
      }
    }
    else if (addr_e >= i->addr + i->len && i->addr + i->len >= addr_b && i->addr < addr_b)
    {
      if (i->prot != prot) /* do not split */
      {
        struct S_mem s;
        s.addr = addr_b;
        s.len = i->len + i->addr - addr_b;
        s.prot = prot;
        ls_mem_.push_front(s);
        i->len = i->len - s.len;
      }
    }
    else if (i->addr + i->len > addr_e && i->addr < addr_e && addr_b > i->addr) /* split */
    {
      if(i->prot != prot)
      {
        int tmp = i->len;
        i->len = addr_b - i->addr;
        struct S_mem s2;
        s2.addr = addr_e;
        s2.len = i->addr + tmp;
        s2.prot = i->prot;
        struct S_mem s;
        s.addr = addr_b;
        s.len = addr_e - addr_b;
        s.prot = prot;
        ls_mem_.push_front(s);
        ls_mem_.push_front(s2);
      }
    }
  }
}

void Tracker::wrap_mremap(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (i->addr == regs.rdi && i->prot != -1)
    {
      if (regs.rsi == 0)
      {
        mem_alloc_ -= i->len;
        ls_mem_.erase(i);
        break;
      }
      mem_alloc_ -= i->len;
      i->len = regs.rdx;
      mem_alloc_ += i->len;
      i->addr = regs.rax;
      break;
    }
  }
}

void Tracker::print_ls_mem()
{
  for (auto &i : ls_mem_)
  {
    printf("MAP AT : 0x%lx with len 0x%lx, and prot = %ld\n",
           i.addr, i.len, i.prot);
  }
}

void Tracker::wrap_malloc_b(struct user_regs_struct regs)
{
  struct S_mem s;
  s.addr = regs.r12;
  s.len = regs.r11;
  s.prot = -1;
  ls_mem_.push_back(s);  
  nb_alloc_++;
}

void Tracker::wrap_realloc_b(struct user_regs_struct regs)
{
  if (regs.r12 == 0) /* ptr is NULL so act like malloc */
  {
    struct S_mem s;  /* right before libc malloc call so we do */ 
    s.addr = regs.r9;      /* not have the return address yet*/
    s.len = regs.r11;
    s.prot = -1;
    ls_mem_.push_back(s);
    nb_alloc_++;
  }
  else if (regs.r11 == 0) /* size is NULL act like free */
  {
    for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
    {
      if (i->addr == regs.r12)
      {
        ls_mem_.erase(i);
        return;
      }
    }    
  }
  else
  {
    for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
    {
      if (i->addr == regs.r12)
      {
        i->prot = -1; /* unset the struct in order to tell at the end of realloc */
        i->addr = regs.r9;
        i->len = regs.r11;
      }
    }
  }
}

void Tracker::wrap_calloc_b(struct user_regs_struct regs)
{
  struct S_mem s;
  s.addr = regs.r9;
  s.len = regs.r11 * regs.r12;
  s.prot = -1;
  ls_mem_.push_back(s);
  nb_alloc_++;
}

void Tracker::wrap_free(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (i->addr == regs.rdi)
    {
      ls_mem_.erase(i);
      nb_free_++;
      return;
    }
  }
  printf("\x1b[31m Invalid free at : 0x%llx\x1b[0m\n", regs.rdi);
}

int Tracker::check_reg(struct user_regs_struct regs)
{
  if (regs.r10 == 0xfffffffc0ffec01d) /* end of malloc */
  {
    wrap_malloc_b(regs);
    return 1;
  }
  else if (regs.r10 == 0xc01db3afffffffff) /* free call */
  {
    wrap_free(regs);
    return 1;
  }
  else if (regs.r10 == 0x5417b3afffffffff)
  {
    wrap_realloc_b(regs);
    return 1;
  }
  else if (regs.r10 == 0xc01dc01dc01dc01d)
  {
    wrap_calloc_b(regs);
    return 1;
  }
  return 0;
}

void Tracker::wrap_alloc_syscall(unsigned long sysnum,
                                 struct user_regs_struct regs)
{
  if (sysnum == __NR_mmap)
    wrap_mmap(regs);
  else if (sysnum == __NR_munmap)
    wrap_munmap(regs);
  else if (sysnum == __NR_mremap)
    wrap_mremap(regs);
  else if (sysnum == __NR_mprotect)
    wrap_mprotect(regs);
}
