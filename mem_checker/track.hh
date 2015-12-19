#ifndef BREAK_HH
# define BREAK_HH

#include <map>
#include <unistd.h>
#include <sys/ptrace.h>
#include <iostream>
#include <elf.h>
#include <link.h>
#include "tools.hh"
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <capstone/capstone.h>
#include "syscall_p.hh"
#include <sys/wait.h>
#include "alloc_obj.hh"
#include <list>
#include <asm/unistd.h>

class Tracker
{
public:
  using pair_name_map = std::pair<std::string, std::map<uintptr_t, unsigned long>>;
  Tracker();
  Tracker(pid_t pid, int state, char *name);
  ~Tracker();
  
  void print_breaks();
  int get_state();
  void set_state(int state);
  void set_pid(pid_t pid);
  pid_t get_pid();
  void print_lib_name(struct link_map *l_map);

  /* functions that handle load objects and breakpoints */
  void update_break(ElfW(Addr) l_addr, ElfW(Off) off,
                    ElfW(Xword) size, char *l_name);
  void get_shdr(ElfW(Ehdr) *elf_addr, ElfW(Addr) l_addr, char *name);
  void load_lo(struct link_map *l_map);
  void update(struct link_map *l_map);
  int treat_break(struct link_map *l_map, uintptr_t addr,
                  struct user_regs_struct regs);
  void add_break(uintptr_t addr, std::string l_name);
  int rem_break(uintptr_t addr, char *l_name, struct user_regs_struct regs);
  void rem_loadobj(struct link_map *l_map);
  void init_break();

  void wrap_alloc_syscall(unsigned long sysnum, struct user_regs_struct regs);
  int check_reg(struct user_regs_struct regs);
  
  /* wrapper that analyse pid_ registers, print and fill ls_mem_ struct */
  void wrap_mmap(struct user_regs_struct regs);
  void wrap_mprotect(struct user_regs_struct regs);
  void wrap_munmap(struct user_regs_struct regs);
  void wrap_mremap(struct user_regs_struct regs);
  void wrap_brk(struct user_regs_struct regs);
  void wrap_free(struct user_regs_struct regs);
  void wrap_malloc_b(struct user_regs_struct regs);
  void wrap_realloc_b(struct user_regs_struct regs);
  void wrap_calloc_b(struct user_regs_struct regs);

  /* funciton in order to check memory */
  void un_protect(struct S_mem map, struct user_regs_struct regs);
  
  void print_ls_mem();

private:
  std::map<std::string, std::map<uintptr_t, unsigned long>> mbreak_;
  pid_t pid_;
  int p_state_;
  char *binary_;
  std::list<S_mem> ls_mem_;
  uintptr_t brk_ = 0;
  unsigned long brk_len_ = 0;
};

#endif /* !BREAK_HH */
