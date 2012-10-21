.code64
.section .data
.section .text
.global hook_sys_block
.type hook_sys_block,@function

hook_sys_block:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    call judgm_syscall_check
    test %eax,%eax
    
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax

    jnz block
    
    push %rdx
    mov $8,%rdx
    mul %rdx
    pop %rdx
    add judgm_syscall_ori_table,%rax
    jmp *(%rax)
block:
    call judgm_syscall_block
    mov $-1,%rax
    ret
