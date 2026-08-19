.section __TEXT,__text,regular,pure_instructions
.p2align 2

// Together with `padding-1.s`, this exceeds the direct branch range. Splitting it is deliberate:
// ld64 only guarantees island placement around input atoms below its branch-island cluster size.
.space 67108864
