#include "track.hh"

void Tracker::un_protect(struct S_mem map, struct user_regs_struct regs)
{
  struct user_regs_struct tmp_regs = regs;
  int status;
  regs.rax = __NR_mprotect;
  regs.rdi = map.addr;
  regs.rsi = map.len;
  if ((map.prot & PROT_EXEC) == PROT_EXEC)
    regs.rdx = PROT_EXEC;
  else
    regs.rdx = PROT_NONE;
  unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, regs.rip); /* save old instruction */

  ptrace(PTRACE_SETREGS, pid_, NULL, &regs);
  ptrace(PTRACE_POKEDATA, pid_, regs.rip, (ins & 0xffffffffffff0000) | 0x050f); /* poke syscall ins */

  ptrace(PTRACE_SINGLESTEP, pid_, 0, 0);
  waitpid(pid_, &status, 0);

  ptrace(PTRACE_SETREGS, pid_, NULL, &tmp_regs);
  ptrace(PTRACE_POKEDATA, pid_, tmp_regs.rip, ins); /* reset right instruction */
}
