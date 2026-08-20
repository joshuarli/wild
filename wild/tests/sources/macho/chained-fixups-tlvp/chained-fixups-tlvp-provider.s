// The two dynamic-library definitions are deliberately explicit: each exported name denotes a
// distinct Mach-O thread-variable descriptor and one initialized TLS word.
.section __DATA,__thread_data,thread_local_regular
.p2align 2
_chained_tlvp_first$tlv$init:
    .long 19
_chained_tlvp_second$tlv$init:
    .long 23

.section __DATA,__thread_vars,thread_local_variables
.p2align 3
.globl _chained_tlvp_first
_chained_tlvp_first:
    .quad __tlv_bootstrap
    .quad 0
    .quad _chained_tlvp_first$tlv$init

.globl _chained_tlvp_second
_chained_tlvp_second:
    .quad __tlv_bootstrap
    .quad 0
    .quad _chained_tlvp_second$tlv$init
