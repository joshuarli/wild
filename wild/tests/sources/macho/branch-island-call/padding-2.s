.section __TEXT,__text,regular,pure_instructions
.p2align 2

// Keep each input atom smaller than ld64's branch-island cluster boundary while their combined
// distance forces the caller's direct BL out of range.
.space 67108864
