.extern kprobes_test_ok
.global kprobes_test_fns
.global kprobes_test_probe_points
.global kprobes_test_fn_count

    .section .text
kprobes_test1:
    addi sp, sp, -10
    sd ra, 0(sp)
    li a0, 1
    call kprobes_test_ok
    ld ra, 0(sp)
    addi sp, sp, 10
    ret

kprobes_test2:
    c.addi16sp sp, -32
    sd ra, 0(sp)
    li a0, 2
    call kprobes_test_ok
    ld ra, 0(sp)
    c.addi16sp sp, 32
    ret

kprobes_test3:
    li t0, 0xdeadbeef
    addi sp, sp, -8
    sd ra, 0(sp)
    li a0, 3
    call kprobes_test_ok
    ld ra, 0(sp)
    addi sp, sp, 8
    ret

kprobes_test4:
    j 1f
    nop
    nop
    .word 0 # invalid
1:
    addi sp, sp, -8
    sd ra, 0(sp)
    li a0, 4
    call kprobes_test_ok
    ld ra, 0(sp)
    addi sp, sp, 8
    ret

kprobes_test5:
    mv t1, t0
kprobes_test5_entry:
    beq t1, t0, 2f
    nop
    nop
    .word 0 # invalid
2:
    addi sp, sp, -8
    sd ra, 0(sp)
    li a0, 5
    call kprobes_test_ok
    ld ra, 0(sp)
    addi sp, sp, 8
    ret    

    .section .rodata
kprobes_test_fns:
    .quad kprobes_test1
    .quad kprobes_test2
    .quad kprobes_test3
    .quad kprobes_test4
    .quad kprobes_test5

kprobes_test_probe_points:
    .quad kprobes_test1
    .quad kprobes_test2
    .quad kprobes_test3
    .quad kprobes_test4
    .quad kprobes_test5_entry

kprobes_test_fn_count:
    .word 5
