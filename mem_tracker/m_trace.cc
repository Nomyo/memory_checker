#include "track.hh"
#include "alloc_obj.hh"

void Tracker::wrap_mmap(struct user_regs_struct regs)
{
  struct S_mem s;
  s.addr = regs.rax;
  s.len = regs.rsi;
  s.prot = regs.rdx;
  ls_mem_.push_back(s);
  printf("[pid %d] mmap { addr = 0x%llx, len = 0x%llx, prot = %lld }\n",
         pid_, regs.rax, regs.rsi, regs.rdx);
}

void Tracker::wrap_munmap(struct user_regs_struct regs)
{
  unsigned long addr_b = regs.rdi;
  unsigned long len = regs.rsi;
  unsigned long addr_e = addr_b - len;
  std::list<std::list<S_mem>::iterator> l_it;
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (addr_b >= i->addr && i->addr >= addr_e
        && addr_b >= i->addr - i->len && i->addr - i->len <= addr_e) /* free mapping */
    {
      printf("[pid %d] munmap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
             pid_, regs.rdi, regs.rsi, i->prot);
      l_it.push_back(i);
    }
    else if (i->addr > addr_b && i->addr - i->len <= addr_b  && i->addr - i->len >= addr_e)
    {
      printf("[pid %d] munmap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
             pid_, regs.rdi, regs.rsi, i->prot);
      i->len = i->len - (addr_b - i->addr - i->len);
    }
    else if (addr_b >= i->addr && i->addr >= addr_e && i->addr - len < addr_e)
    {
      printf("[pid %d] munmap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
             pid_, regs.rdi, regs.rsi, i->prot);
      i->addr = addr_e;
      i->len = i->len - (addr_e - i->addr - i->len );
    }
    else if (i->addr > addr_b && i->addr - len < addr_b && addr_e > i->addr - len) /* split */
    {
      printf("[pid %d] munmap split { addr = 0x%lx, len = 0x%lx, prot = %ld } into\n",
             pid_, i->addr, i->len, i->prot);
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
    }
  }
  for (auto& i : l_it) /* erase all maps that are unmap */
    ls_mem_.erase(i);
}


void Tracker::wrap_mremap(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if (i->addr == regs.rdi)
    {
      if (regs.rsi == 0)
      {
        printf("[pid %d] mremap { addr = 0x%llx, len = 0x%llx, prot = %ld }\n",
               pid_, regs.rax, regs.rdx, i->prot);
        ls_mem_.erase(i);
        break;
      }
      printf("[pid %d] mremap { addr = 0x%lx, len = 0x%lx, prot = %ld }\n",
             pid_, i->addr, i->len, i->prot);
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
    printf("MAP AT :%lx with len 0x%lx, and prot = %ld\n", i.addr, i.len, i.prot);
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
      printf("[pid %d] brk { addr = 0x%lx, len = 0x%lx, prot = 0 }\n",
             pid_, brk_, brk_len_);
      brk_len_ = brk_len_ + regs.rdi - brk_; 
      printf("\tto { addr = 0x%lx, len = 0x%lx, prot = 0 }\n",
             brk_, brk_len_);
    }
    else
    {
      printf("[pid %d] brk { addr = 0x%lx, len = (nil), prot = 0 }\n",
              pid_, brk_);
      brk_len_ = brk_len_ + regs.rdi - brk_; 
      printf("\tto { addr = 0x%lx, len = 0x%lx, prot = 0 }\n",
             brk_, brk_len_);
    }
  }
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
}
