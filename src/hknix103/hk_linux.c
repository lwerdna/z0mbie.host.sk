/*
  HOOKLIB os-dependend functions
  version 1.03/linux
*/

/* main functions -- used by hooklib.c */
/* returns: 0 or NULL on error */

int hl_attach(pid_t pid);
int hl_detach(pid_t pid);
int hl_read(pid_t pid, void* dst, void* src, unsigned long size);
int hl_write(pid_t pid, void* dst, void* src, unsigned long size);
void* hl_malloc(pid_t pid, unsigned long size);
int hl_free(pid_t pid, void* ptr);

/* additional functions */
int waitstop(int pid, int hang);
unsigned long find_module_base(pid_t pid, char* module);

#define mmap_code_size          28       /* must be 4-aligned                */
#define mmap_patch_len_at       9
char* mmap_code =
  "\x6A\x00"                    /* push 0        ; offset                    */
  "\x6A\xFF"                    /* push -1       ; fd = -1                   */
  "\x6A\x22"                    /* push 22h      ; MAP_PRIVATE|MAP_ANONYMOUS */
  "\x6A\x03"                    /* push 3        ; PROT_READ|PROT_WRITE      */
  "\x68\xFF\xFF\xFF\xFF"        /* push <LENGTH> ; len                       */
     /*  ^^  ^^  ^^  ^^                                                      */
  "\x6A\x00"                    /* push 0        ; addr = 0                  */
  "\x8B\xDC"                    /* mov ebx, esp  ; struct mmap_arg_struct *  */
  "\xB8\x5A\x00\x00\x00"        /* mov eax, 90   ; eax = mmap#               */
  "\xCD\x80"                    /* int 80h       ; syscall                   */
  "\xCC"                        /* int 3         ; return from PTRACE_CONT   */
  "\x90\x90\x90";               /* ...           ; padding                   */

int waitstop(int pid, int hang)
{
  int status;
  waitpid(pid, &status, hang ? WUNTRACED : WNOHANG);
  return (WIFSTOPPED(status) ? 1 : 0);
}

unsigned char* find_module_by_mask(pid_t pid, char* mask)
{
  FILE *f;
  static char buf[1024], check[1024], s[64];

  snprintf(s, sizeof(s)-1, "/proc/%d/maps", pid);

  f = fopen(s,"r");
  if (!f)
  {
    hk_DebugLog3("find_m_b_m:ERROR:fopen('%s') error %s\n", s, errstr());
    return 0;
  }

  buf[0] = 0;
  while (!feof(f))
  {
    if (!fgets(buf, sizeof(buf)-1, f)) break;
//08048000-080a0000 r-xp 00000000 03:02 10606474   /usr/local/apache/bin/httpd
//080a9000-080c0000 rwxp 00000000 00:00 0
    sscanf(buf, "%*x-%*x %*s %*x %s %*d %s", check, check, check, check, check, check);  // x1
    if (strlen(check) >= strlen(mask))
    if (strcmp(check+strlen(check)-strlen(mask), mask)==0)
    {
      strcpy(buf, check);
      break;
    }
    buf[0] = 0;
  }

  fclose(f);

  return buf[0] == 0 ? NULL : buf;

} /* find_module_by_mask */

/* if (module == NULL), return 1st non-empty block */

unsigned long find_module_base(pid_t pid, char* module)
{
  FILE *f;
  unsigned long addr;
  static char buf[1024], check[1024], s[64];

  snprintf(s, sizeof(s)-1, "/proc/%d/maps", pid);

  f = fopen(s,"r");
  if (!f)
  {
    hk_DebugLog3("find_m_b:ERROR:fopen('%s') error %s\n", s, errstr());
    return 0;
  }

  addr = 0;

  while (!feof(f))
  {
    if (!fgets(buf, sizeof(buf)-1, f)) break;
//08048000-080a0000 r-xp 00000000 03:02 10606474   /usr/local/apache/bin/httpd
//080a9000-080c0000 rwxp 00000000 00:00 0
    sscanf(buf, "%lx-%*x %*s %*x %s %*d %s", &addr, check, check, check, check, check);  // x1
    if (module == NULL)
    {
      if (strcmp(check, "00:00")==0) addr = 0;
    }
    else
    {
      if (strcmp(check, module )!=0) addr = 0;
    }
    if (addr) break;
  }

  fclose(f);

  return addr;

} /* find_module_base */

int hl_attach(pid_t pid)
{
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0)
  {
    hk_DebugLog3("hl_attach:ERROR:PTRACE_ATTACH(pid=%d) error %s\n", pid, errstr());
    return 0;
  }

  waitstop(pid, 1);

  return 1;
} /* hl_attach */

int hl_detach(pid_t pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) != 0)
  {
    hk_DebugLog2("hl_detach:ERROR:PTRACE_DETACH error %s\n", errstr());
    return 0;
  }

  waitstop(pid, 1);   // ???

  return 1;
} /* hl_detach */

int hl_read(pid_t pid, void* dst, void* src, unsigned long size)
{
  unsigned long i, j, d;

  hk_DebugLog5("hl_read:pid=%d,addr=src=0x%08X,data=dst=0x%08X,len=%d\n", pid, src, dst, size);

  for(i = 0; i < size; )
  {
    d = ptrace(PTRACE_PEEKTEXT,
               pid,
               (unsigned long)src + i,
               NULL);

    if (errno)
    {
      hk_DebugLog2("hl_read:ERROR:PTRACE_PEEKTEXT error %s\n", errstr());
      return 0;
    }

    j = 0;
    while((i < size) && (j < 4))
    {
      *(unsigned char*)((unsigned long)dst + i) = d & 0xFF;
      d >>= 8;
      i++;
      j++;
    }
  }

  return 1;

} /* hl_read */

int hl_write(pid_t pid, void* dst, void* src, unsigned long size)
{
  unsigned long i,j,d,b;

  hk_DebugLog5("hl_write:pid=%d,addr=dst=0x%08X,data=src=0x%08X,len=%d\n", pid, dst, src, size);

  for(i = 0; i < size; i += 4)
  {
    d = 0;
    for(j = 0; j < 4; j++)
    {
      if (i + j < size)
      {
        b = *(unsigned char*)((unsigned long)src + i + j);
      }
      else
      {
        if (!hl_read(pid, (void*)&b, (void*)((unsigned long)dst+i+j), 1))
        {
          hk_DebugLog1("hl_write:ERROR:hl_read error\n");
          return 0;
        }
      }
      d |= b << (j << 3);
    }

    if (ptrace(PTRACE_POKETEXT,
               pid,
               (unsigned long)dst + i,
               d) != 0)
    {
      hk_DebugLog2("hl_write:ERROR:PTRACE_POKETEXT error %s\n", errstr());
      return 0;
    }
  }

  return 1;

} /* hl_write */

void* hl_malloc(pid_t pid, unsigned long size)
{
  struct user_regs_struct reg, reg_0;
  char temp[mmap_code_size], code[mmap_code_size];
  void* res;

  hk_DebugLog3("hl_malloc:pid=%d,size=%d\n", pid, size);

  res = NULL;

  memset((void*)&reg_0, 0, sizeof(struct user_regs_struct));

  if (ptrace(PTRACE_GETREGS, pid, NULL, (void*)&reg_0) != 0)
  {
    hk_DebugLog2("hl_malloc:ERROR: PTRACE_GETREGS error %s\n", errstr());
    goto quit;
  }

  memcpy((void*)&reg, (void*)&reg_0, sizeof(struct user_regs_struct));

  reg.eip = ((unsigned long)find_module_base(pid, NULL)) + 4;

  if (ptrace(PTRACE_SETREGS, pid, NULL, (void*)&reg) != 0)
  {
    hk_DebugLog2("hl_malloc:ERROR: PTRACE_SETREGS error %s\n", errstr());
    goto quit;
  }

  memcpy(code, mmap_code, mmap_code_size);

  *(unsigned long*)&code[mmap_patch_len_at] = size;

  if (hl_read(pid, temp, (void*)reg.eip, mmap_code_size) == 0)
  {
    hk_DebugLog2("hl_malloc:hl_read error\n", errstr());
    goto quit;
  }

  if (hl_write(pid, (void*)reg.eip, code, mmap_code_size) == 0)
  {
    hk_DebugLog2("hl_malloc:hl_write error\n", errstr());
    goto quit;
  }

  if (ptrace(PTRACE_CONT, pid, 0, 0) != 0)
  {
    hk_DebugLog2("hl_malloc:ERROR: PTRACE_CONT error %s\n", errstr());
    goto quit;
  }

  while (!waitstop(pid, 0)) sleep(1);

  memset((void*)&reg, 0, sizeof(struct user_regs_struct));

  if (ptrace(PTRACE_GETREGS, pid, NULL, (void*)&reg) != 0)
  {
    hk_DebugLog2("hl_malloc:ERROR: PTRACE_GETREGS error %s\n", errstr());
    goto quit;
  }

  if (hl_write(pid, (void*)reg.eip, temp, mmap_code_size) == 0)
  {
    hk_DebugLog2("hl_malloc:hl_write error\n", errstr());
    goto quit;
  }

  res = (void*)reg.eax;

  if (ptrace(PTRACE_SETREGS, pid, NULL, (void*)&reg_0) != 0)
  {
    hk_DebugLog2("ERROR: hl_malloc:PTRACE_SETREGS error %s\n", errstr());
    res = NULL;
  }

quit:

  hk_DebugLog2("hl_malloc:return,ptr=0x%08X\n", res);

  return res;

} /* hl_malloc */

int hl_free(pid_t pid, void* ptr)
{
  /* todo */

  hk_DebugLog1("hl_free:todo\n");

  return 1;
} /* hl_free */

/* EOF */
