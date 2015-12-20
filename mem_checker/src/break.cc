#include "track.hh"

Tracker::Tracker()
  : mbreak_()
{}

Tracker::Tracker(pid_t pid, int state, char *name)
  : mbreak_()
  , pid_(pid)
  , p_state_(state)
  , binary_(name)
  , ls_mem_()
{}

void Tracker::set_pid(pid_t pid)
{
  pid_ = pid;
}

pid_t Tracker::get_pid()
{
  return pid_;
}

Tracker::~Tracker() = default;

void Tracker::set_state(int state)
{
  p_state_ = state;
}

int Tracker::get_state()
{
  return p_state_;
}


// update_break disas the memory area, look for syscall instruction
// and add the address into breakpoint map with the associated name

void Tracker::update_break(ElfW(Addr) l_addr, ElfW(Off) off,
                         ElfW(Xword) size, char *l_name)
{
  csh handle;
  cs_insn *insn = NULL;
  size_t count = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
  {
    std::cerr << "Unable to open capstone" << std::endl;
    return;
  }
  char *code = (char *)malloc(sizeof (char) * size);
  Tools::read_from_pid(pid_, size, code, (void *)((uintptr_t)l_addr + (uintptr_t)off));
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
  count = cs_disasm(handle, (const uint8_t *)(code), size - 1, l_addr + off, 0, &insn);
  if (count > 0)
  {
    size_t j;
    for (j = 0; j < count; j++)
    {
      if (strcmp(insn[j].mnemonic, "syscall") == 0)
        add_break((uintptr_t)insn[j].address, std::string(l_name));
    }
    cs_free(insn, count);
  }
  else
    std::cerr << "Couldn't disassemble instruction" << std::endl;
  free(code);
  cs_close(&handle);
}





// get_shdr from the ELF header and call the update break function

void Tracker::get_shdr(ElfW(Ehdr) *ehdr, ElfW(Addr) l_addr, char *l_name)
{
  int shnum = ehdr->e_shnum; /* get number of section */
  if (ehdr->e_shstrndx == SHN_UNDEF)
  {
    std::cerr << "No section header string table index found" << std::endl;
    return;
  }
  ElfW(Shdr) *shdr_ad;
  shdr_ad = (ElfW(Shdr) *)((uintptr_t)ehdr + (uintptr_t)ehdr->e_shoff +
                           ((uintptr_t)ehdr->e_shstrndx * (uintptr_t)ehdr->e_shentsize));
  for (int i = 0; i < shnum; i++)  /* iterate on each shdr */
  {
    shdr_ad = (ElfW(Shdr) *)((char *)ehdr +
                             (uintptr_t)ehdr->e_shoff + (i * (uintptr_t)ehdr->e_shentsize));
    if ((shdr_ad->sh_flags & SHF_EXECINSTR) == 4)
      update_break(l_addr, shdr_ad->sh_offset, shdr_ad->sh_size, l_name);
  }
}




// init_break is called at the beginning of the program
// and register breakpoint in the file which name is im binary_

void Tracker::init_break()
{
  ElfW(Ehdr) *elf;
  ElfW(Addr) addr = 0x400000;
  int file = open(binary_, O_RDONLY);
  if (file == -1)
  {
    std::cerr << "Couldn't open " << binary_ << " file" << std::endl;
    exit(2); // Nothing allocated so exit here won't leads to leak
  }
  struct stat s;
  if (fstat(file, &s) == -1)
  {
    std::cerr << "Couldn't open " << binary_ << " file" << std::endl;
    exit(2);
  }
  elf = (ElfW(Ehdr) *)mmap(0, s.st_size, PROT_READ, MAP_SHARED, file, 0);
  get_shdr(elf, addr, binary_);
  munmap(elf, s.st_size);
}





// load_lo will temporary map load object in order to get the ELF header
// and then call get_shdr

void Tracker::load_lo(struct link_map *l_map)
{
  char name[512];
  ElfW(Ehdr) *elf;
  l_map = Tools::get_load_obj_next(pid_, l_map); // Bypass first l_map
  while (l_map)
  {
    Tools::get_load_obj_name(pid_, l_map, name);
    struct link_map m;
    Tools::read_from_pid(pid_, sizeof (struct link_map), &m, l_map);
    if (strcmp("", name) == 0 || strncmp("linux-vdso.so", name, 13) == 0)
    {
      l_map = Tools::get_load_obj_next(pid_, l_map);
      continue;
    }
    else
    {
      int file = open(name, O_RDONLY);
      if (file == -1)
      {
        std::cerr << "Couldn't open " << name << " file" << std::endl;
        break;
      }
      struct stat s;
      if (fstat(file, &s) == -1)
      {
        std::cerr << "Couldn't open " << name << " file" << std::endl;
        break;
      }
      elf = (ElfW(Ehdr) *)mmap(0, s.st_size, PROT_READ, MAP_SHARED, file, 0);
      get_shdr(elf, m.l_addr, name);
      munmap(elf, s.st_size);
    }
    l_map = Tools::get_load_obj_next(pid_, l_map);
  }
}





// Update function is called when r_debug state is consistent so
// we look at the previous state ADD or DELETE to do the right call

void Tracker::update(struct link_map *l_map)
{
  if (p_state_ == r_debug::RT_ADD)
    load_lo(l_map);
  else if (p_state_ == r_debug::RT_DELETE)
    rem_loadobj(l_map);
}




// add breakpoint in the map corresponding to l_name

void Tracker::add_break(uintptr_t addr, std::string l_name)
{
  if (mbreak_.find(l_name) == mbreak_.end()) /* unpatch loaded objects*/
  {
    mbreak_.insert(pair_name_map(l_name, std::map<uintptr_t, unsigned long>{}));
    unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, addr);

    // save old instruction and store a breakpoint isntruction
    mbreak_[l_name].insert(std::pair<uintptr_t, unsigned long>(addr, ins));
    ptrace(PTRACE_POKEDATA, pid_, addr, (ins & 0xffffffffffffff00) | 0xcc);
  }
  else
  {
    if (mbreak_[l_name].find(addr) != mbreak_[l_name].end())
      return;
    else
    {
      mbreak_.insert(pair_name_map(l_name, std::map<uintptr_t, unsigned long>{}));
      unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, addr);
      mbreak_[l_name].insert(std::pair<uintptr_t, unsigned long>(addr, ins));
      ptrace(PTRACE_POKEDATA, pid_, addr, (ins & 0xffffffffffffff00) | 0xcc);
    }
  }
}





// Delete in map structure the map corresponding to
// a deleted load object

void Tracker::rem_loadobj(struct link_map *l_map)
{
  struct link_map *head = l_map;
  char name[512];
  for (auto const &i : mbreak_)
  {
    l_map = Tools::get_load_obj_next(pid_, l_map);
    while (l_map)
    {
      Tools::get_load_obj_name(pid_, l_map, name);
      if (i.first.compare(name) == 0)
        break;
      l_map = Tools::get_load_obj_next(pid_, l_map);
    }
    if (!l_map && i.first.compare(binary_) != 0)
    {
      mbreak_.erase(i.first);
      break;
    }
    else
      l_map = head;
  }
}




// function called when SIGTRAP is caught and rip - 1 is not equal
// to r_brk

int Tracker::treat_break(struct link_map *l_map, uintptr_t addr,
                       struct user_regs_struct regs)
{
  char name[512];
  l_map = Tools::get_load_obj_next(pid_, l_map); // Bypass first l_map
  while (l_map)
  {
    Tools::get_load_obj_name(pid_, l_map, name);
    if (rem_break(addr, name, regs) == 1)
    return 1;
    l_map = Tools::get_load_obj_next(pid_, l_map);
  }
  return 0;
}


// function that from a breakpoint and regs, process the syscall and
// a wrapper is called if necessary

int Tracker::rem_break(uintptr_t addr, char *l_name, struct user_regs_struct regs)
{
  for (auto const &i : mbreak_)
  {
    if (i.first.compare(l_name) == 0
        && (i.second.find(addr) != i.second.end()))
    {
      for (auto const &j : i.second)
      {
        if (j.first == addr)
        {
          int status;
          unsigned long ins = j.second;
          ptrace(PTRACE_POKEDATA, pid_, addr, ins); /* syscall instr set */
          regs.rip--;
          ptrace(PTRACE_SETREGS, pid_, NULL, &regs);
          re_all_protect(regs); /* remove all protection */
          ptrace(PTRACE_SINGLESTEP, pid_, 0, 0); /* exec syscall */
          waitpid(pid_, &status, 0);
          ptrace(PTRACE_GETREGS, pid_, NULL, &regs);
          un_protect_all(regs); /* reset all protection */
          if (WIFEXITED(status))
          {
            show_leaks();
            return 1;
          }
          else
          {
            /* wrapper mmap and associated func */
            if (regs.orig_rax == __NR_mmap || regs.orig_rax == __NR_mremap
                || regs.orig_rax == __NR_munmap
                || regs.orig_rax == __NR_mprotect)
              wrap_alloc_syscall(regs.orig_rax, regs);
          }
          ptrace(PTRACE_POKEDATA, pid_, addr,
                 (ins & 0xffffffffffffff00) | 0xcc);
        }
      }
    }
  }
  return 0;
}



void Tracker::print_lib_name(struct link_map *l_map)
{
  char name[512];
  l_map = Tools::get_load_obj_next(pid_, l_map);
  while (l_map)
  {
    Tools::get_load_obj_name(pid_, l_map, name);
    printf("Lib name :%s \n", name);
    l_map = Tools::get_load_obj_next(pid_, l_map);
  }
}


void Tracker::print_breaks()
{
  for (auto const &i : mbreak_)
  {
    std::cout << "In :" << i.first << std::endl;
    for (auto const &j : i.second)
      printf("\t 0x%lx with %ld\n", (unsigned long)j.first, j.second);
  }
}
