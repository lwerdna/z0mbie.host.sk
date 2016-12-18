/*
  process memory injector
*/

#include "precomp.h"
#pragma hdrstop

char* errstr()
{
  int code = errno;
  static char result[512];
  snprintf(result, sizeof(result), "%d=='%s'", code, strerror(code));
  return result;
} // errstr

#include "xde.c"
#include "hooklib.c"

int main(int argc, char* argv[])
{
  pid_t pid;
  unsigned long off, len;
  int i;
  struct xde_instr diza;
  unsigned char* m;

  if (argc < 4)
  {
    printf("syntax: %s <pid> <offs> <hex-byte(s)>\n", argv[0]);
    exit(1);
  }

  pid = atoi(argv[1]);
  assert(sscanf(argv[2], "%X", &off));

  len = argc - 3;
  assert(len);

  printf("pid = %d, off = 0x%08X, len = 0x%08X = %d\n", pid, off, len, len);

  m = (unsigned char*) malloc( (size_t)(len+16) );
  assert(m);
  memset(m, 0, len+16);

  for(i = 0; i<len; i++)
  {
    //printf("i=%d len=%d argv[4+i]=%s\n", i,len,argv[3+i]);
    assert(sscanf(argv[3+i], "%X", &m[i]));
  }

  printf("injecting...\n");

  if (hl_write(pid, (void*)m, (void*)off, len) == 0)
  {
    printf("ERROR: hl_write() error\n");
    exit(1);
  }

  free(m);

  printf("OK\n");

  exit(0);
  return 0;
} // main

/* EOF */
