/*
  HOOKLIB -- API Splicing Library -- FREEWARE
  version 1.03/linux
*/

#include "hooklib.h"         /* constants && options                         */
#include "hk_linux.c"        /* linux-specific memory io                     */
#include "xde.h"             /* Extended Disassembler Engine                 */

void* InstallHook(void* Target,
                  void* Hook,
                  unsigned long flags,          /* HF_xxx */
                  unsigned long nArgs,
                  void* stubAddr,
                  unsigned long stubSize,
                  pid_t pid )
{
  unsigned char stub[MAX_STUB_SIZE];            /* hook stub, temp */
  unsigned char opcode[MAX_PROLOG_SIZE];        /* opcode, temp */
  void *p, *ip;
  unsigned long i, j, tmp_len, jmp_to, *orig_len, *orig_ptr,
  *orig_ptr_2, stub_len, stub_maxlen;
  struct xde_instr op;

  /*printf("Target=%08X Hook=%08X flags=%08X nArgs=%d stubAddr=%08X hProcess=%08X\n",
    Target, Hook, flags, nArgs, stubAddr, hProcess);*/

  hk_DebugLog7("inst:Target=0x%08X,Hook=0x%08X,flags=0x%08X,nArgs=%d,stubAddr=0x%08X,pid=%d\n",
    Target, Hook, flags, nArgs, stubAddr, pid);

  /* allocate memory for hook stub data, if it is not specified */
  if ((flags & HF_NOMALLOC) == 0)
  {
    stub_maxlen = MAX_STUB_SIZE;
    stubAddr = hl_malloc(pid, stub_maxlen);
    if (stubAddr == NULL)
    {
      hk_DebugLog1("inst:ERROR:hl_malloc() error\n");
      return NULL;
    }
  }
  else
  {
    stub_maxlen = stubSize;
  }

  /* lets build hook stub data (temp) */

  p = stub;

  /* build hook sign (size == SIGN_SIZE), used by UninstallHook() */

  if ((flags & HF_DISABLE_UNHOOK) == 0)
  {
    HL_PUT_BYTE(0xEB);             /* +00 jmp over sign_data              */
    HL_PUT_BYTE(SIGN_SIZE-2);
    HL_PUT_DWORD(HOOK_ID);         /* +02 hook id                         */
    HL_PUT_DWORD(flags);           /* +06 flags                           */
    HL_PUT_DWORD(Target);          /* +0A dst = ptr to hooked subroutine  */
    orig_ptr = (unsigned long*)p;  /*     to fix later:                   */
    HL_PUT_DWORD(0);               /* +0E src = ptr to original bytes     */
    orig_len = (unsigned long*)p;  /*     to fix later:                   */
    HL_PUT_DWORD(0);               /* +12 size = length of original bytes */
  }
  else
  {
    orig_len = &tmp_len;
    tmp_len = 0;
  }

  /* repush arguments */

  if (flags & HF_REPUSH_ARGS)
  {
    if (flags & HF_VAARG)
    {
      /* push ptr to ... (va_arg = variable argument list) */
      HL_PUT_BYTE(0x54)    /* push esp */

      HL_PUT_BYTE(0x81)    /* add dword [esp], dword 4+nArgs*4 */
      HL_PUT_BYTE(0x04)
      HL_PUT_BYTE(0x24)
      HL_PUT_DWORD( 4+nArgs*4 )
    }
    /* for each argument */
    for(i=0; i<nArgs; i++)
    {
      /* push dword ptr [esp+j] */
      /* ...                    */
      /* call subroutine        */
      j = 4 * nArgs + (flags & HF_VAARG ? 4 : 0);
      if (j < 0x80)
      {
        /* short form */
        HL_PUT_BYTE(0xFF)      /* push dword [esp + byte j] */
        HL_PUT_BYTE(0x74)
        HL_PUT_BYTE(0x24)
        HL_PUT_BYTE(j)
      }
      else
      {
        /* long form */
        HL_PUT_BYTE(0xFF);     /* push dword [esp + dword j] */
        HL_PUT_BYTE(0xB4);
        HL_PUT_BYTE(0x24);
        HL_PUT_DWORD(j);
      }
    }
  } /* HF_REPUSH_ARGS */

  if (flags & HF_OWN_CALL)
  {
    HL_PUT_BYTE(0x68);                     /* push offset orig_bytes */
    orig_ptr_2 = (unsigned long*)p;        /* to fix later */
    HL_PUT_DWORD(0);
  }

  if (flags & HF_REGISTERS)
  {
    HL_PUT_BYTE(0x60);                     /* pushad */
  }

  /* call Hook() */
  HL_PUT_BYTE( (flags & HF_RETTOCALLER) ? 0xE9 : 0xE8);
  HL_PUT_DWORD( (unsigned long)Hook -
                  ( (unsigned long)stubAddr +
                    (unsigned long)p -
                    (unsigned long)stub + 4 ) );

  if (flags & HF_REGISTERS)
  {
    HL_PUT_BYTE(0x61);                     /* popad */
  }

  if ((flags & HF_RETTOCALLER)==0)
  {

    /* if arguments were repushed, fix stack */
    if (flags & HF_REPUSH_ARGS)
    {
      /* j == used stack size */
      j = nArgs * 4 + (flags & HF_VAARG ? 4 : 0);
      /* if HF_OWN_CALL, pushed ptr to orig_bytes */
      if (flags & HF_OWN_CALL) j += 4;
      if (j < 0x80)
      {
        /* short form */
        HL_PUT_WORD(0xC483);       /* add esp, byte nArgs */
        HL_PUT_BYTE(j);
      }
      else
      {
        /* long form */
        HL_PUT_WORD(0xC481);       /* add esp, dword nArgs */
        HL_PUT_DWORD(j);
      }
    }

    if (flags & HF_OWN_CALL)
    {
      if ((flags & HF_REPUSH_ARGS) == 0)
      {
        /* if HF_OWN_CALL, pushed ptr to orig_bytes */
        HL_PUT_WORD(0xC483);       /* add esp, 4 */
        HL_PUT_BYTE(4);
      }
      if ((nArgs == 0) || (flags & HF_TARGET_IS_CDECL))
      {
        HL_PUT_BYTE(0xC3);
      }
      else
      {
        HL_PUT_BYTE(0xC2);
        HL_PUT_WORD(nArgs * 4);
      }
      /* fix orig_ptr_2, i.e. ptr to were original bytes are located, */
      /* hook() will call this ptr to invoke target subroutine      */
      *orig_ptr_2 = (unsigned long)stubAddr +
                    (unsigned long)p -
                    (unsigned long)stub;
    } /* HF_OWN_CALL */

  } /* !HF_RETTOCALLER */

  /* fix orig_ptr, i.e. ptr to were original bytes are located (for unhook) */
  if ((flags & HF_DISABLE_UNHOOK) == 0)
    *orig_ptr = (unsigned long)stubAddr +
                (unsigned long)p -
                (unsigned long)stub;

  /* read some bytes into opcode[] */
  if (hl_read(pid, opcode, Target, MAX_PROLOG_SIZE) == 0)
  {
    if ((flags & HF_NOMALLOC) == 0)
      if (!hl_free(pid, stubAddr))
        hk_DebugLog1("inst:ERROR:hl_free() error\n");
    hk_DebugLog1("inst:ERROR:hl_read() error\n");
    return NULL;
  }

  /* some instructions from the hooking subroutine are copied into hook stub */
  /* to be executed there,coz we need JMPTOHOOK_LEN bytes to insert jmp hook */
  /* so lets do some disassembly */
  ip = Target;            /* ip        = ptr to current opcode               */
  *orig_len = 0;          /* *orig_len = sumary len of original instructions */
  while(*orig_len < JMPTOHOOK_LEN)
  {
    /* parse opcode, get length & some info */
    if (xde_disasm(opcode, &op) == 0)
    {
      if ((flags & HF_NOMALLOC) == 0)
        if (!hl_free(pid, stubAddr))
          hk_DebugLog1("inst:ERROR:hl_free() error\n");
      hk_DebugLog1("inst:ERROR:dis error\n");
      return NULL;
    }

    if (opcode[0] == 0xE9) /* multiple hooks or whatever */
    {
      /* where it points to? */
      jmp_to = (unsigned long)ip + 5 + (*(unsigned long*)&opcode[1]);
      /* copy manually, do address fix since location is changed */
      HL_PUT_BYTE( 0xE9);
      HL_PUT_DWORD( (unsigned long)jmp_to -
                       ( (unsigned long)stubAddr +
                         (unsigned long)p -
                         (unsigned long)stub + 4 ) );
      /* original bytes are now changed, so unhook will fail, */
      /* so we will save bytes later into another location */
      if ((flags & HF_DISABLE_UNHOOK) == 0)
        *orig_ptr = 0;
    }
    else
    if (op.flag & (C_REL|C_STOP))
    {
      /* i hope you will not encounter RET- or Jxx- like opcodes in the   */
      /* subroutine prolog, but if so, should fix Jxx as shown above and  */
      /* probably fail on RET...                                          */
      if ((flags & HF_NOMALLOC) == 0)
        if (!hl_free(pid, stubAddr))
          hk_DebugLog1("inst:ERROR:hl_free() error\n");
      hk_DebugLog1("inst:ERROR:Jxx||RET\n");
      return NULL;
    }
    else
    {
      /* all other opcodes are copied normally,              */
      /* however it can fail if such opcode has some xref... */
      HL_RANGE_CHECK(op.len);
      memcpy(p, opcode, op.len);
      (unsigned char*)p += op.len;
    }

    *orig_len += op.len;

    /* go to next instruction */
    (unsigned char*)ip += op.len;
    memcpy(opcode, ((unsigned char*)opcode)+op.len, MAX_PROLOG_SIZE-op.len);
  }

  /* now store jmp to target+*orig_len, i.e. return to hooked subroutine */
  HL_PUT_BYTE( 0xE9);
  HL_PUT_DWORD( (unsigned long)Target + *orig_len -
                   ( (unsigned long)stubAddr +
                     (unsigned long)p -
                     (unsigned long)stub + 4 ) );

  /* if original bytes were changed, should save 'em once again, for unhook */
  if ((flags & HF_DISABLE_UNHOOK) == 0)
  if (*orig_ptr == 0)
  {
    if (hl_read(pid, p, Target, *orig_len) == 0)
    {
      if ((flags & HF_NOMALLOC) == 0)
        if (!hl_free(pid, stubAddr))
          hk_DebugLog1("inst:ERROR:hl_free() error\n");
      hk_DebugLog1("inst:ERROR:hl_read() error\n");
      return NULL;
    }
    *orig_ptr = (unsigned long)stubAddr +
                (unsigned long)p -
                (unsigned long)stub;
    (unsigned long*)p += *orig_len;
  }

  /* calculate total hook stub length */
  stub_len = (unsigned long)p - (unsigned long)stub;

  /* write hook stub into allocated or given memory */
  if (hl_write(pid, stubAddr, stub, stub_len) == 0)
  {
    if ((flags & HF_NOMALLOC) == 0)
      if (!hl_free(pid, stubAddr))
        hk_DebugLog1("inst:ERROR:hl_free() error\n");
    hk_DebugLog1("inst:ERROR:hl_write() error\n");
    return NULL;
  }

  /* now modify target subroutine */

  /* 1st, build jmp to hook stub */
  p = stub;

  /* HL_PUT_BYTE(0xCC);   to enable it, set JMPTOHOOK_LEN to 6 */

  HL_PUT_BYTE( 0xE9);                    /* jmp hook_stub */
  HL_PUT_DWORD( (unsigned long)stubAddr -
               ( (unsigned long)Target +
                 (unsigned long)p + 4 -
                 (unsigned long)stub ) );
  for(i=JMPTOHOOK_LEN; i<*orig_len; i++)            /* align with NOP's */
  {
    HL_PUT_BYTE(0x90);
  }

  /* 2nd, patch hooked subroutine. */
  /* this can fail on multiple cpu's, if execution is not blocked */
  /* i dont know if it is so... */
  if (hl_write(pid, Target, stub, *orig_len) == 0)
  {
    if ((flags & HF_NOMALLOC) == 0)
      if (!hl_free(pid, stubAddr))
        hk_DebugLog1("inst:ERROR:hl_free() error\n");
    hk_DebugLog1("inst:ERROR:hl_write() error\n");
    return NULL;
  }

  hk_DebugLog2("inst:stubAddr = 0x%08X\n", stubAddr);

  /* now it is hooked. return ptr to hook stub */
  return stubAddr;

} /* InstallHook */

//int UninstallHook(void* hookHandle, pid_t pid)
//{
//  unsigned char sign[SIGN_SIZE];
//  void *p, *src, *dst;
//  unsigned long flags, len;
//
//  hk_DebugLog3("uninst:hookHandle=0x%08X,pid=%d\n", hookHandle, pid);
//
//  /* read hook signature */
//  if (hl_read(pid, sign, hookHandle, SIGN_SIZE) == 0)
//  {
//    hk_DebugLog1("uninst:ERROR:hl_read() error\n");
//    return 0;
//  }
//
//  p = sign;
//
//  /* check hook id */
//  if ( (GET_BYTE(p)  != 0xEB       ) ||
//       (GET_BYTE(p)  != SIGN_SIZE-2) ||
//       (GET_DWORD(p) != HOOK_ID    ) )
//  {
//    hk_DebugLog1("uninst:ERROR:no HOOK_ID signature\n");
//    return 0;
//  }
//
//  /* get hook parameters */
//  flags   = GET_DWORD(p);
//  dst     = (void*)GET_DWORD(p);
//  src     = (void*)GET_DWORD(p);
//  len     = *(unsigned long*)p;
//
//  /* unhook */
//  /* assert(len <= SIGN_SIZE); */
//  if (!hl_read (pid, sign, src, len))
//  {
//    hk_DebugLog1("uninst:ERROR:hl_read() error\n");
//    return 0;
//  }
//
//  if (!hl_write(pid, dst, sign, len))
//  {
//    hk_DebugLog1("uninst:ERROR:hl_write() error\n");
//    return 0;
//  }
//
//  /* free hook stub, if it were allocated */
//  if ((flags & HF_NOMALLOC)==0)
//    if (!hl_free(pid, hookHandle))
//      hk_DebugLog1("uninst:ERROR:hl_free() error\n");
//
//  /* now unhooked */
//  return 1;
//
//} /* UninstallHook */
