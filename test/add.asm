
global _start

section .text

_start:

    mov rax, 60
    xor rdi, rdi
    syscall

    ; Add reg to mem gadget
    add [rbx], rax
    ret

    ; Add mem to reg gadget
    add rax, [rbx]
    ret

    ; Add reg to reg gadget
    add rax, rbx
    ret
