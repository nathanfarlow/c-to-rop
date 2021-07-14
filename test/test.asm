
global _start

section .text

_start:

    ; syscall gadget
    mov rax, 60
    xor rdi, rdi
    syscall

    ; Comparison gadgets
    cmp rax, rbx
    ret

    sub rax, rbx
    ret

    ; mov gadgets
    xchg rax, rbx
    ret

    mov rax, [rbx]
    ret

    mov [rax], rbx
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

    sets al
    ret
    
    cmovs rax, rbx
    ret

    setb al
    ret

    cmovb rax, rbx
    ret

    setc al
    ret

    cmovc rax, rbx
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
