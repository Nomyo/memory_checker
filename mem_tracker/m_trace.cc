#include "track.hh"
#include "alloc_obj.hh"

void Tracker::wrap_mmap(struct user_regs_struct regs)
{
  struct S_mem s;
  s.addr = regs.rax;
  s.len = regs.rsi;
  s.prot = regs.rdx;
  if (-regs.rax == ENOMEM)
  {
    printf("mmap { addr = 0x%llx, len = 0x%llx, prot = %lld } = - ENOMEM\n",
           regs.rdi, regs.rsi, regs.rdx);
  }
  else
  {
    printf("mmap { addr = 0x%llx, len = 0x%llx, prot = %lld }\n",
           regs.rax, regs.rsi, regs.rdx);
    ls_mem_.push_back(s);
  }
}

void Tracker::wrap_munmap(struct user_regs_struct regs)
{
  unsigned long addr_b = regs.rdi;
  unsigned long len = regs.rsi;
  unsigned long addr_e = addr_b - len;
  std::list<std::list<S_mem>::iterator> l_it;
  int acc = 0;
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (addr_b >= i->addr && i->addr >= addr_e
        && addr_b >= i->addr - i->len && i->addr - i->len <= addr_e) /* free mapping */
    {
      printf("munmap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
             regs.rdi, regs.rsi, i->prot);
      l_it.push_back(i);
      acc++;
    }
    else if (i->addr > addr_b && i->addr - i->len <= addr_b  && i->addr - i->len >= addr_e)
    {
      printf("munmap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
             regs.rdi, regs.rsi, i->prot);
      i->len = i->len - (addr_b - i->addr - i->len);
      acc++;
    }
    else if (addr_b >= i->addr && i->addr >= addr_e && i->addr - len < addr_e)
    {
      printf("munmap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
             regs.rdi, regs.rsi, i->prot);
      i->addr = addr_e;
      i->len = i->len - (addr_e - i->addr - i->len );
      acc++;
    }
    else if (i->addr > addr_b && i->addr - len < addr_b && addr_e > i->addr - len) /* split */
    {
      printf("munmap split { addr = 0x%lx, len = 0x%lx, prot = %ld } into\n",
             i->addr, i->len, i->prot);
      i->len = i->len - (addr_b - i->addr - i->len);
      struct S_mem s;
      s.addr = addr_e;
      s.len = i->len - (addr_e - i->addr - i->len );
      s.prot = i->prot;
      printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
             i->addr, i->len, i->prot);
      printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
             s.addr, s.len, s.prot);
      ls_mem_.push_back(s);
      acc++;
    }
  }
  for (auto& i : l_it) /* erase all maps that are unmap */
    ls_mem_.erase(i);
  if (acc == 0)
    printf("munmap { addr = 0x%llx, len = 0x%llx, prot = ? }\n",
           regs.rdi, regs.rsi);
}

void Tracker::wrap_mprotect(struct user_regs_struct regs)
{
  unsigned long addr_b = regs.rdi;
  unsigned long len = regs.rsi;
  int prot = regs.rdx;
  unsigned long addr_e = addr_b - len;
  int acc = 0;
  if (regs.rax) /* if -ENOMEM mprotect failed */
  {
    printf("mprotect { addr = 0x%llx, len = 0x%llx, prot = %d } = FAIL\n",
           regs.rdi, regs.rsi, prot);
    return;
  }
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (addr_b >= i->addr && i->addr >= addr_e
        && addr_b >= i->addr - i->len && i->addr - i->len <= addr_e)
    {
      printf("[pid %d] mprotect { addr = 0x%llx, len = 0x%llx, prot = %d }\n",
             pid_, regs.rdi, regs.rsi, prot);
      i->prot = prot;
      acc++;
    }
    else if (i->addr > addr_b && i->addr - i->len <= addr_b  && i->addr - i->len >= addr_e)
    {
      if (i->prot == prot) /* do not split */
      {
        printf("[pid %d] mprotect{ addr = 0x%llx, len = 0x%llx, prot = %d }\n",
               pid_, regs.rdi, regs.rsi, prot);
        acc++;
      }
      else
      {
        struct S_mem s;
        s.addr = addr_b;
        s.len = i->len - (i->addr - addr_b);
        s.prot = prot;
        ls_mem_.push_front(s);
        printf("[pid %d] mprotect{ addr = 0x%lx, len = 0x%lx, prot = %ld } into\n",
               pid_, i->addr, i->len, i->prot);
        i->len = i->len - (addr_b - i->addr - i->len);
        printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
               i->addr, i->len, i->prot);
        printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %d }\n",
               s.addr, s.len, prot);
        acc++;
      }
    }
    else if (addr_b >= i->addr && i->addr >= addr_e && i->addr - len < addr_e)
    {
      if (i->prot == prot) /* do not split */
      {
        printf("[pid %d] mprotect{ addr = 0x%llx, len = 0x%llx, prot = %d }\n",
               pid_, regs.rdi, regs.rsi, prot);
        acc++;
      }
      else
      {
        struct S_mem s;
        s.addr = i->addr;
        s.len = i->len - (addr_e - i->addr + i->len);
        s.prot = prot;
        ls_mem_.push_front(s);
        printf("[pid %d] mprotect{ addr = 0x%lx, len = 0x%lx, prot = %ld } into\n",
               pid_, i->addr, i->len, i->prot);
        i->addr = addr_e;
        printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %d }\n",
               s.addr, s.len, prot);
        i->len = i->len - (addr_b - i->addr - i->len);
        printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
               i->addr, i->len, i->prot);
        acc++;
      }
    }
    else if (i->addr > addr_b && i->addr - len < addr_b && addr_e > i->addr - len) /* split */
    {
      if (i->prot == prot) /* do not split */
      {
        printf("[pid %d] mprotect{ addr = 0x%llx, len = 0x%llx, prot = %d }\n",
               pid_, regs.rdi, regs.rsi, prot);
        acc++;
      }
      else
      {
        printf("[pid %d] mprotect split { addr = 0x%lx, len = 0x%lx, prot = %ld } into\n",
               pid_, i->addr, i->len, i->prot);
        int tmp = i->len;
        i->len = i->len - (addr_b - i->addr - i->len);
        printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
               i->addr, i->len, i->prot);
        struct S_mem s2;
        s2.addr = addr_e;
        s2.len = i->len - (addr_e - i->addr - i->len );
        s2.prot = i->prot;
        struct S_mem s;
        s.addr = addr_b;
        s.len = tmp - s2.len - i->len;
        s.prot = prot;
        printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
               s.addr, s.len, s.prot);
        printf("\t* { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
               s2.addr, s2.len, s2.prot);
        ls_mem_.push_front(s);
        ls_mem_.push_front(s2);
        acc++;
      }
    }
  }
  if (acc == 0)
    printf("mprotect { addr = 0x%llx, len = 0x%llx, prot = %d }\n",
           regs.rdi, regs.rsi, prot);
}


void Tracker::wrap_mremap(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (i->addr == regs.rdi)
    {
      if (regs.rsi == 0)
      {
        printf("mremap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
               regs.rax, regs.rdx, i->prot);
        ls_mem_.erase(i);
        break;
      }
      printf("mremap { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
             i->addr, i->len, i->prot);
      i->len = regs.rdx;
      i->addr = regs.rax;
      printf("\tto { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
             i->addr, i->len, i->prot);
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

void Tracker::wrap_brk(struct user_regs_struct regs)
{
  if (brk_ == 0)
    brk_ = (uintptr_t)regs.rax;
  else
  {
    if (brk_len_)
    {
      printf("brk { addr = 0x%lx, len = 0x%lx, prot = 0 }\n",
             brk_, brk_len_);
      brk_len_ = brk_len_ + regs.rdi - brk_; 
      printf("\tto { addr = 0x%lx, len = 0x%lx, prot = 0 }\n",
             brk_, brk_len_);
    }
    else
    {
      printf("brk { addr = 0x%lx, len = (nil), prot = 0 }\n",
             brk_);
      brk_len_ = brk_len_ + regs.rdi - brk_; 
      printf("\tto { addr = 0x%lx, len = 0x%lx, prot = 0 }\n",
             brk_, brk_len_);
    }
  }
}

void Tracker::wrap_malloc_b(struct user_regs_struct regs)
{
  struct S_mem s;
  s.addr = 0;
  s.len = regs.rdi;
  s.prot = -1; /* right before libc malloc call so we do 
                  not have the return address yet*/
  ls_mem_.push_back(s);  
}

void Tracker::wrap_malloc_e(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (i->prot == -1)
    {
      i->addr = regs.rax;
      i->prot = 0;
      printf("malloc { addr = 0x%lx, len = 0x%lx }\n"
             , i->addr, i->len);
      return;
    }
  }
}

void Tracker::wrap_realloc_b(struct user_regs_struct regs)
{
  if (regs.rdi == 0) /* ptr is NULL so act like malloc */
  {
    struct S_mem s;  /* right before libc malloc call so we do */ 
    s.addr = 0;      /* not have the return address yet*/
    s.len = regs.rsi;
    s.prot = -1;
    ls_mem_.push_back(s);  
  }
  else if (regs.rsi == 0) /* size is NULL act like free */
  {
    for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
    {
      if (i->addr == regs.rdi)
      {
        printf("realloc { addr = 0x%lx, len = 0x%llx }\n"
               , i->addr, regs.rsi);
        ls_mem_.erase(i);
        return;
      }
    }    
  }
  else
  {
    for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
    {
      if (i->addr == regs.rdi)
      {
        i->prot = -1; /* unset the struct in order to tell at the end of realloc */
        printf("realloc { addr = 0x%lx, len = 0x%lx }\n"
               , i->addr, i->len);
        i->len = regs.rsi;
      }
    }
  }
}

void Tracker::wrap_realloc_e(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (i->prot == -1) /* looking for unset structure */
    {
      if (i->addr == 0)
      {
        printf("realloc { addr = 0x%llx, len = 0x%lx }\n"
               , regs.rax, i->len);
        i->addr = regs.rax;
      }
      else
        printf("\tto { addr = 0x%llx, len = 0x%lx }\n"
               , regs.rax, i->len);
      
      if (i->addr == regs.rax)
        i->addr = regs.rax;
      i->prot = 0;
      return;
    }
  }
}

void Tracker::wrap_free(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (i->addr == regs.rdi)
    {
      printf("free { addr = 0x%lx, len = 0x%lx }\n"
             , i->addr, i->len);
      ls_mem_.erase(i);
      return;
    }
  }
}

int Tracker::check_reg(struct user_regs_struct regs)
{
  if (regs.r10 == 0xfffffffc01dc0ffe) /* malloc begins */
  {
    wrap_malloc_b(regs);
    return 1;
  }
  else if (regs.r10 == 0xfffffffc0ffec01d) /* end of malloc */
  {
    wrap_malloc_e(regs);
    return 1;
  }
  else if (regs.r10 == 0xc01db3afffffffff) /* free call */
  {
    wrap_free(regs);
    return 1;
  }
  else if (regs.r10 == 0xffffffff5417b3af) /* realloc begins */
  {
    wrap_realloc_b(regs);
    return 1;
  }
  else if (regs.r10 == 0x5417b3afffffffff) /* end of realloc */
  {
    wrap_realloc_e(regs);
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
  else if (sysnum == __NR_brk)
    wrap_brk(regs);
  else if (sysnum == __NR_mprotect)
    wrap_mprotect(regs);
}
