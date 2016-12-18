/*
  process memory contents dumper
*/

#include "precomp.h"
#pragma hdrstop

char* errstr()
{
  int code = errno;
  static char result[512];
  snprintf(result, sizeof(result), "%d=='%s'", code, strerror(code));
  return result;
} /* errstr */

#include "xde.c"
#include "hooklib.c"

int main(int argc, char* argv[])
{
  pid_t pid;
  unsigned long off, len;
  int ip, l;
  struct xde_instr diza;
  unsigned char* m;

  if (argc != 4)
  {
    printf("syntax: %s <pid> <offs> <len>\n", argv[0]);
    exit(1);
  }

  pid = atoi(argv[1]);
  assert(sscanf(argv[2], "%X", &off));
  assert(sscanf(argv[3], "%X", &len));

  printf("# pid = %d, off = 0x%08X, len = 0x%08X = %d\n", pid, off, len, len);

  m = (unsigned char*) malloc( len+16 );
  memset(m, 0x90, len+16 );

  if (hl_read(pid, (void*)m, (void*)off, len) == 0)
  {
    printf("ERROR: hl_read() error\n");
    exit(1);
  }

  ip = 0;
  while(len)
  {
    l = xde_disasm((unsigned char*)(m+ip), &diza);
    if (l > len) l = len;

    printf("%08X: ", off+ip);

    if (l == 0)
    {
      printf("***ERROR***\n");
      break;
    }

    len -= l;

    while(l--)
      printf(" %02X", m[ip++]);

    if (diza.flag & C_REL)
    {
      if (diza.datasize == 1) printf("  # --> %08X", (signed)(off+ip)+diza.data_c[0]);
      if (diza.datasize == 2) printf("  # --> %08X", (signed)(off+ip)+diza.data_s[0]);
      if (diza.datasize == 4) printf("  # --> %08X", (signed)(off+ip)+diza.data_l[0]);
    }

    printf("\n");

  }

  free(m);

  exit(0);
  return 0;
} // main

/* EOF */
