// `MH_SUBSECTIONS_VIA_SYMBOLS` requires atom-level, not section-level, garbage collection. This
// object contains exactly 10,000 externally visible text atoms but the executable reaches only
// one. The named first and last atoms prove that the scale workload remains semantic GC rather
// than a whole-section retention shortcut.
.subsections_via_symbols
.section __TEXT,__text,regular,pure_instructions

.globl _wild_dead_strip_stress_first
_wild_dead_strip_stress_first:
  mov w0, #1
  ret

.macro dead_atom
.p2align 2
.globl _wild_dead_strip_stress_dead_\@
_wild_dead_strip_stress_dead_\@:
  mov w0, #1
  ret
.endm

.rept 9997
dead_atom
.endr

.p2align 2
.globl _wild_dead_strip_stress_live
_wild_dead_strip_stress_live:
  mov w0, #42
  ret

.p2align 2
.globl _wild_dead_strip_stress_last
_wild_dead_strip_stress_last:
  mov w0, #1
  ret
