#include "track.hh"

void Tracker::un_protect(struct S_mem map, struct user_regs_struct regs)
{
  struct user_regs_struct tmp_regs = regs;
  int status;
  regs.rax = __NR_mprotect;
  regs.rdi = map.addr;
  regs.rsi = map.len;
  if ((map.prot & PROT_EXEC) == PROT_EXEC)
    return;
  else
    regs.rdx = PROT_NONE;
  unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, regs.rip); /* save old instruction */
  
  ptrace(PTRACE_POKEDATA, pid_, regs.rip, (ins & 0xffffffffffff0000) | 0x050f);
  ptrace(PTRACE_SETREGS, pid_, NULL, &regs);  /* poke syscall ins */
  ptrace(PTRACE_SINGLESTEP, pid_, 0, 0);
  waitpid(pid_, &status, 0);
  ptrace(PTRACE_SETREGS, pid_, NULL, &tmp_regs);
  ptrace(PTRACE_POKEDATA, pid_, tmp_regs.rip, ins); /* reset right instruction */
}

void Tracker::re_protect(struct S_mem map, struct user_regs_struct regs)
{
  struct user_regs_struct tmp_regs = regs;
  int status;
  regs.rax = __NR_mprotect;
  regs.rdi = map.addr;
  regs.rsi = map.len;
  regs.rdx = map.prot;
  unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, regs.rip); /* save old instruction */
  ptrace(PTRACE_SETREGS, pid_, NULL, &regs);  /* poke syscall ins */
  ptrace(PTRACE_POKEDATA, pid_, regs.rip, (ins & 0xffffffffffff0000) | 0x050f);
  ptrace(PTRACE_SINGLESTEP, pid_, 0, 0);
  waitpid(pid_, &status, 0);

  ptrace(PTRACE_SETREGS, pid_, NULL, &tmp_regs);
  ptrace(PTRACE_POKEDATA, pid_, tmp_regs.rip, ins); /* reset right instruction */
}

void Tracker::un_protect_all(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    un_protect(*i, regs);
  }
}

void Tracker::re_all_protect(struct user_regs_struct regs)
{
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    re_protect(*i, regs);
  }
}

void Tracker::get_current_inst(uintptr_t addr)
{
  csh handle;
  cs_insn *insn = NULL;
  size_t count;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
  {
    std::cerr << "Unable to open capstone" << std::endl;
    return;
  }
  char code[100];
  Tools::read_from_pid(pid_, 100, code, (void *)((uintptr_t)addr));
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
  count = cs_disasm(handle, (const uint8_t *)(code), sizeof (unsigned long), addr, 0, &insn);
  if (count)
    printf("0x%lx :\t%s\t%s\n", addr, insn[0].mnemonic,
           insn[0].op_str);
  
  cs_close(&handle);
}

void Tracker::show_leaks()
{
  
  printf("\n\n\x1b[31mMemory leaks\x1b[0m : %ld bytes not liberated at exit\n",
         mem_alloc_);
  for (auto &i : ls_mem_)
  {
    printf("\t=> \x1b[32maddress\x1b[0m = 0x%lx - \x1b[32mlen\x1b[0m 0x%lx\n",
           i.addr, i.len);
  }
  printf("\n HEAP SUMMARY:\n total heap usage : %ld allocs, %ld frees\n\n",
         nb_alloc_, nb_free_);
}

void Tracker::is_invalid(uintptr_t addr, struct user_regs_struct regs)
{
  int status;
  uintptr_t o_add = regs.rip;
  for (auto i = ls_mem_.begin(); i != ls_mem_.end(); ++i)
  {
    if ((i->addr >= addr && i->addr + i->len <= addr)
        || (i->addr <= addr && i->addr + i->len >= addr))
    {
      re_protect(*i, regs); /* reset protection */
      ptrace(PTRACE_SINGLESTEP, pid_, 0, 0);
      waitpid(pid_, &status, 0);
      ptrace(PTRACE_GETREGS, pid_, NULL, &regs); /* get update register after singlestep */
      un_protect(*i, regs);
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
      {
        printf("\nInvalid memory access at address : 0x%lx\n", addr);
        get_current_inst(o_add);
        /* kill instead of exit in order to let the father free the memory */ 
        kill(pid_, SIGKILL);

      }
      return;
    }
  }
  printf("\n\x1b[33mInvalid memory access at address\x1b[0m : 0x%lx\n", addr);
  get_current_inst(o_add);
  kill(pid_, SIGKILL);
}
