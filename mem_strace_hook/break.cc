#include "break.hh"

Break::Break()
  : mbreak_()
{}

Break::Break(pid_t pid, int state)
  : mbreak_()
  , pid_(pid)
  , p_state_(state)
{}

void Break::set_pid(pid_t pid)
{
  pid_ = pid;
}

pid_t Break::get_pid()
{
  return pid_;
}

Break::~Break() = default;

void Break::set_state(int state)
{
  p_state_ = state;
}

int Break::get_state()
{
  return p_state_;
}

////////////////////////// TEST ///////////////////////////////

void Break::update_break(ElfW(Addr) l_addr, ElfW(Off) off,
                         ElfW(Xword) size, char *l_name)
{
  csh handle;
  cs_insn *insn;
  size_t count;
  l_name = l_name;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
      std::cerr << "Unable to open capstone" << std::endl;
      return;
    }
  char *code = (char *)malloc(sizeof (char) * size);
  Tools::read_from_pid(pid_, size, code, (void *)((uintptr_t)l_addr + (uintptr_t)off));
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
  count = cs_disasm(handle,(const uint8_t *)(code), size - 1, l_addr + off, 0, &insn);
  if (count > 0)
    {
      size_t j;
      for (j = 0; j < count; j++)
        {
          printf("0x%lx:     \t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                 insn[j].op_str);
        }
      cs_free(insn, count);
    }
  else
    std::cerr << "Couldn't disassemble instruction" << std::endl;
  free(code);
  cs_close(&handle);
}

void Break::get_shdr(ElfW(Ehdr) *ehdr, ElfW(Addr) l_addr)
{
  l_addr = l_addr;
  const char * shstrtab;
  int shnum = ehdr->e_shnum; /* get number of section */
  if (ehdr->e_shstrndx == SHN_UNDEF)
    {
      std::cerr << "No section header string table index found" << std::endl;
      return;
    }
  ElfW(Shdr) *shdr_ad;
  shdr_ad = (ElfW(Shdr) *)((uintptr_t)ehdr + (uintptr_t)ehdr->e_shoff +
                           ((uintptr_t)ehdr->e_shstrndx * (uintptr_t)ehdr->e_shentsize));
  shstrtab = (char *)ehdr + (uintptr_t)shdr_ad->sh_offset;
  for (int i = 0; i < shnum; i++)  /* iterate on each shdr */
    {
      shdr_ad = (ElfW(Shdr) *)((char *)ehdr +
                               (uintptr_t)ehdr->e_shoff + (i * (uintptr_t)ehdr->e_shentsize));
      std::cout << &shstrtab[shdr_ad->sh_name] << std::endl;
      if (shdr_ad->sh_flags == SHF_EXECINSTR)
        {
          /* add breakpoints from l_addr + sh_offset,
             with process_readv/writev and l_name  sh_size */
        }
      printf("SHDR 0x%lx \n", (unsigned long)shdr_ad->sh_offset);
      printf("SHDR SIZE = %lx \n", (unsigned long)shdr_ad->sh_size);
    }
}

void Break::load_lo(struct link_map *l_map)
{
  char name[512];
  ElfW(Ehdr) *elf;
  //  l_map = Tools::get_load_obj_next(pid_, l_map); // Bypass first l_map
  while (l_map)
    {
      Tools::get_load_obj_name(pid_, l_map, name);
      if (strcmp("", name) == 0)
        {
          l_map = Tools::get_load_obj_next(pid_, l_map);
          continue;
        }
      printf("\nIN Lib name :%s ", name);
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
      elf = (ElfW(Ehdr) *)mmap(0, s.st_size, PROT_READ, MAP_SHARED, file, 0); /* mapp the lib*/
      struct link_map m;
      Tools::read_from_pid(pid_, sizeof (struct link_map), &m, l_map);
      printf("L_ADDR = 0x%lx\n ",  m.l_addr);
      get_shdr(elf, m.l_addr);
      munmap(elf, s.st_size);
      l_map = Tools::get_load_obj_next(pid_, l_map);
    }
}

////////////////////////////////////////////////////////////////

void Break::update(struct link_map *l_map)
{
  l_map = l_map;
  if (p_state_ == r_debug::RT_ADD)
    load_lo(l_map);
  else if (p_state_ == r_debug::RT_DELETE)
    rem_loadobj(l_map);
}

void Break::add_break(void *addr, char *l_name)
{
  if (mbreak_.find(l_name) == mbreak_.end()) /* unpatch loaded objects*/
    {
      mbreak_.insert(pair_name_map(l_name, std::map<void *, unsigned long>{}));
      unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, addr); /* get instruction */
      mbreak_[l_name].insert(std::pair<void *, unsigned long>(addr, ins)); /* store old ins */
      ptrace(PTRACE_POKEDATA, addr, (ins & 0xffffffffffffff00) | 0xcc); /* insert break point*/
    }
  else
    {
      if (mbreak_[l_name].find(addr) != mbreak_[l_name].end())
        return;
      else
        {
          mbreak_.insert(pair_name_map(l_name, std::map<void *, unsigned long>{}));
          unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, addr);
          mbreak_[l_name].insert(std::pair<void *, unsigned long>(addr, ins));
          ptrace(PTRACE_POKEDATA, addr, (ins & 0xffffffffffffff00) | 0xcc);
        }
    }
}

void Break::rem_loadobj(struct link_map *l_map)
{
  struct link_map *head = l_map;
  char name[512];
  for (auto const &i : mbreak_)
    {
      while (l_map)
        {
          Tools::get_load_obj_name(pid_, l_map, name);
          if (strcmp(name, i.first) == 0)
            break;
          Tools::get_load_obj_next(pid_, l_map);
        }
      if (!l_map)
        {
          mbreak_.erase(i.first);
          break;
        }
      else
        l_map = head;
    }
}

void Break::rem_break(void *addr, char *l_name)
{
  if (mbreak_[l_name].find(addr) != mbreak_[l_name].end())
    return;
  unsigned ins = mbreak_[l_name][addr];
  mbreak_[l_name].erase(addr);
  ptrace(PTRACE_POKEDATA, addr, ins); /* replace rip ? */
}

void Break::print_lib_name(struct link_map *l_map)
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

void Break::print_breaks()
{
  for (auto const &i : mbreak_)
    {
      std::cout << "In :" << i.first << std::endl;
      for (auto const &j : i.second)
        printf("\t 0x%lx with %ld\n", (unsigned long)j.first, j.second);
    }
}
