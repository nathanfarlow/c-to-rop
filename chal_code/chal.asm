global rop

section .data

rop_data: resb 1024 * 64
rop_chain: resb 1024 * 1024 * 4

section .text

rop:
    lea rax, [rop_chain]
    mov rsp, rax
    ret

    syscall
    ret

    ; Comparison gadgets
    cmp rax, rbx
    ret

    cmp rcx, rbx
    ret

    xor rax, rax
    ret

    sub rax, rbx
    ret

    ; ; mov gadgets
    xchg rax, rbx
    ret

    xchg rax, rcx
    ret

    xchg rbx, rcx
    ret

    mov rax, rsp
    ret

    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    pop rax
    ret

    ;need set rax -> rbx

    xchg rax, rsi
    ret

    mov rcx, rax
    ret

    mov rbx, rcx
    ret

    mov rax, [rbx]
    ret

    mov rbx, [rax]
    ret

    mov rcx, [rax]
    ret

    mov [rax], rcx
    ret

    mov [rax], rbx
    ret

    mov [rbx], rax
    ret

    ; sete + setl gadgets
    sete al
    ret

    cmove rax, rbx
    ret

    setl al
    ret

    cmovl rax, rbx
    ret

    ; Add reg to mem gadget
    add [rbx], rax
    ret

    ; Add mem to reg gadget
    add rax, [rbx]
    ret

    ; Add reg to reg gadget
    add rax, rbx
    ret

    ; xor gadgets
    xor rax, rbx
    ret

    xor eax, ebx
    ret

    ; Register setting gadgets
    pop rax
    ret

    pop rbx
    ret

    pop rcx
    ret

    pop rdx
    ret

    pop rbp
    ret

    pop rsp
    ret

    pop rsi
    ret

    pop rdi
    ret

    pop r8
    ret

    pop r9
    ret

    pop r10
    ret

    pop r11
    ret

    pop r12
    ret

    pop r13
    ret

    pop r14
    ret

    pop r15
    ret

    ; for some reason angrop doesn't pick up this gadget?
    pop r15
    ret
