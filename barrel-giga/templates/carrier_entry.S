/* Shared x64 Windows ABI entry shim for the MinGW carrier backend. */

    .text
    .globl AlignRSP
    .def AlignRSP; .scl 2; .type 32; .endef
AlignRSP:
    pushq %rbp
    movq %rsp, %rbp
    andq $-16, %rsp
    subq $32, %rsp
    call sg_entry
    movq %rbp, %rsp
    popq %rbp
    ret
