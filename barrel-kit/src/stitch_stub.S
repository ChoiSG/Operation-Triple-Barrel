.intel_syntax noprefix
.section .text

stitch_blob:
    .long stitch_worker - stitch_blob
    .long stitch_fixup - stitch_blob
    .long stitch_blob_end - stitch_blob
    .long 0x48435453

stitch_worker:
    mov [rcx + 88], rbx
    mov [rcx + 96], rsi
    mov rbx, rcx
    push rbp
    mov rbp, rsp

stitch_wait:
    mov rsp, rbp
    sub rsp, 0x20
    mov rcx, [rbx + 8]
    mov edx, 0xffffffff
    xor r8d, r8d
    call qword ptr [rbx + 32]
    add rsp, 0x20

    cmp dword ptr [rbx + 56], 0
    jne stitch_stop
    mov r11, [rbx + 40]
    test r11, r11
    jz stitch_wait

    mov rsp, rbp
    mov rax, [rbx + 72]
    sub rax, 8
    sub rsp, rax

    lea r10, [r11 + 16]
    mov eax, dword ptr [r11 + 12]
    dec rax
    mov rcx, rax
    sub rcx, 4

stitch_stack_args:
    cmp rax, 4
    jl stitch_args_done
    mov r8, [r10 + rax*8]
    mov [rsp + rcx*8 + 0x20], r8
    dec rax
    dec rcx
    jmp stitch_stack_args

stitch_args_done:
    lea rax, [r11]
    movsxd rdx, dword ptr [rbx + 80]
    sub rax, rdx

    movsx rdx, byte ptr [rbx + 84]
    lea rsi, [rbx + 104]
    sub rsi, rdx

    mov rcx, [r10]
    mov rdx, [r10 + 8]
    mov r8,  [r10 + 16]
    mov r9,  [r10 + 24]
    jmp qword ptr [rbx + 64]

stitch_fixup:
    mov [rbx + 48], rax
    mov rsp, rbp

    sub rsp, 0x20
    call qword ptr [rbx + 144]
    add rsp, 0x20
    mov [rbx + 152], eax

    mov rsi, [rbx + 96]
    mov qword ptr [rbx + 40], 0

    sub rsp, 0x20
    mov rcx, [rbx + 16]
    call qword ptr [rbx + 24]
    add rsp, 0x20
    jmp stitch_wait

stitch_stop:
    mov rsp, rbp
    pop rbp
    mov rsi, [rbx + 96]
    mov r10, [rbx + 88]
    xor eax, eax
    mov rbx, r10
    ret

stitch_blob_end:
    nop
