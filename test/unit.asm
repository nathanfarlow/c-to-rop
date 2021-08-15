
global _start

section .text

_start:

    mov rax, [rbx]
    ret

    mov rax, [rbx]
    mov rax, [rbx]
    ret

    mov rax, [rbx]
    ret

    mov [rax], rbx
    ret

    mov [rbx], rax
    ret

    xor rax, rax
    ret

    xor rax, rax
    ret
    
    xor rax, rax
    ret

    xor rax, rax
    ret

    xor rax, rax
    ret

    xor rax, rax
    ret
    