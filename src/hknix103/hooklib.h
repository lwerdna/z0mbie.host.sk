/*
  HOOKLIB -- API Splicing Library -- FREEWARE
  version 1.03/linux
*/

#ifndef __HOOKLIB_H__
#define __HOOKLIB_H__

#define HOOKLIB_DEBUG              /* for some debug printf                  */

/* InstallHook() flags */
#define HF_REPUSH_ARGS          1  /* if used, specify nArgs                 */
#define HF_VAARG                2  /* last arg = ..., used if HF_REPUSH_ARGS */
#define HF_DISABLE_UNHOOK       4  /* if used, UninstallHook() is not avail. */
#define HF_NOMALLOC             8  /* if specified, stubAddr is used         */
#define HF_RETTOCALLER          16 /* dont call original subroutine          */
#define HF_OWN_CALL             32 /* call target from hook, uses nArgs      */
#define HF_TARGET_IS_CDECL      64 /* used if HF_OWNCALL, we hook cdecl sub  */
#define HF_REGISTERS            128/* use registers as arguments             */

#define SIGN_SIZE               0x16        /* hook signature size (if used) */
#define HOOK_ID                 0x484F4F4B  /* hook signature id   (if used) */
#define MAX_STUB_SIZE           1024        /* max size of hook stub,        */
                                            /* used if stubAddr == NULL      */
#define MAX_PROLOG_SIZE         128         /* max prolog size we analyze    */
#define JMPTOHOOK_LEN           5           /* size of jmp-to-hook code      */

/* returns: hook handle (==ptr to hook stub) or NULL if error */

void* InstallHook(void* Target,             /* subroutine to hook            */
                  void* Hook,               /* hook handler                  */
                  unsigned long flags,      /* flags, HF_xxx                 */
                  unsigned long nArgs,      /* used if HF_REPUSH_ARGS        */
                  void* stubAddr,           /* if NULL, do malloc/free       */
                  unsigned long stubSize,   /* unused if stubAddr is defined */
                  pid_t pid );              /* process handle                */

/* returns: 1 if ok, 0 if error */

int UninstallHook(void* hookHandle,         /* returned by InstallHook()     */
                  pid_t pid );              /* process handle                */

#define GET_BYTE(p)     *((unsigned char*)p)++
#define GET_DWORD(p)    *((unsigned long*)p)++
/*
  фактически, это могло бы работать и на gcc тоже, если бы поганое быдло,
  которое писало йобаное гцц своими кривыми руками, не кодило бы все через жопу
#define PUT_BYTE(p, v)  *((unsigned char *)p)++ = (unsigned char )v
#define PUT_WORD(p, v)  *((unsigned short*)p)++ = (unsigned short)v
#define PUT_DWORD(p, v) *((unsigned long *)p)++ = (unsigned long )v
*/
#define PUT_BYTE(p, v)  { *(unsigned char *)(p) = (unsigned char )(v); *(unsigned long*)&p += 1; }
#define PUT_WORD(p, v)  { *(unsigned short*)(p) = (unsigned short)(v); *(unsigned long*)&p += 2; }
#define PUT_DWORD(p, v) { *(unsigned long *)(p) = (unsigned long )(v); *(unsigned long*)&p += 4; }

#define HL_RANGE_CHECK(x)                                                    \
        if ((unsigned long)p + (x) - (unsigned long)stub >= stub_maxlen)     \
        {                                                                    \
          if ((flags & HF_NOMALLOC) == 0)                                    \
            if (!hl_free(pid, stubAddr))                                     \
              hk_DebugLog1("inst:ERROR:hl_free() error\n");           \
          hk_DebugLog1("inst:ERROR:not enough place in the stub\n"); \
          return 0;                                                          \
        }

#define HL_PUT_BYTE(v)  { HL_RANGE_CHECK(1); PUT_BYTE(p, v); }
#define HL_PUT_WORD(v)  { HL_RANGE_CHECK(2); PUT_WORD(p, v); }
#define HL_PUT_DWORD(v) { HL_RANGE_CHECK(4); PUT_DWORD(p, v); }

#define ALIGN4K_L(x)    (((unsigned long)(x)) & (~4095))
#define ALIGN4K_H(x)    (((unsigned long)(x) + 4095) & (~4095))

#ifdef HOOKLIB_DEBUG
#define hk_DebugLog1(a)             printf(a)
#define hk_DebugLog2(a,b)           printf(a,b)
#define hk_DebugLog3(a,b,c)         printf(a,b,c)
#define hk_DebugLog4(a,b,c,d)       printf(a,b,c,d)
#define hk_DebugLog5(a,b,c,d,e)     printf(a,b,c,d,e)
#define hk_DebugLog6(a,b,c,d,e,f)   printf(a,b,c,d,e,f)
#define hk_DebugLog7(a,b,c,d,e,f,g) printf(a,b,c,d,e,f,g)
#else
#define hk_DebugLog1(a)
#define hk_DebugLog2(a,b)
#define hk_DebugLog3(a,b,c)
#define hk_DebugLog4(a,b,c,d)
#define hk_DebugLog5(a,b,c,d,e)
#define hk_DebugLog6(a,b,c,d,e,f)
#define hk_DebugLog7(a,b,c,d,e,f,g)
#endif

#endif /* __HOOKLIB_H__ */
