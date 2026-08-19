Yes. This version is substantially more suitable for an unattended agent. I added the repository-specific architecture, the existing testing machinery, explicit anti-shortcut rules, a progress ledger, regression constraints for Wild’s Linux support, and stronger empirical gates. Wild already has a dedicated AArch64 Mach-O CI job, its design is deliberately phase-oriented, and its current Mach-O adapter/backend still contain concrete TODOs in argument semantics, section classification, relocation/relaxation, and chained fixups. ([GitHub][1])

# Finish Wild's macOS linker and prove production Rust toolchain compatibility

You are taking ownership of the macOS/Mach-O port of the Wild linker and driving it to production-quality completion.

Work against the **current upstream state** of `wild-linker/wild`. Do not assume that issue numbers, TODOs, source layout, or implementation status in this prompt are still exact when you begin. Inspect the repository and current upstream issues first, reconcile them against this charter, then execute.

The primary goal is:

> Make Wild a genuinely usable high-speed replacement for Apple's system linker for ordinary Rust development on Apple Silicon macOS, with correctness established empirically against Apple's linker and through substantial real Rust workloads.

The primary target is:

```text
aarch64-apple-darwin
```

Once that target is genuinely production-ready, extend the same architecture and qualification methodology to:

```text
x86_64-apple-darwin
```

before claiming broad macOS support.

Do **not** define success as:

* linking Hello World;
* passing only Wild's existing Mach-O tests;
* closing the remaining children of issue #757;
* supporting only executables;
* making a handful of Rust crates compile;
* accepting arguments while silently ignoring their semantics.

Issue #757 is currently only a partial representation of the remaining work. At the time this charter was prepared it reported 13/21 subissues complete. ([GitHub][2])

The actual finish line is a linker that can handle realistic Cargo/Rust workflows including executables, test binaries, proc macros, dylibs/cdylibs, Apple frameworks and SDK stubs, native C/C++ dependencies, dead stripping, TLS, unwinding, DWARF/dSYM workflows, large programs, code signing, rpaths, archive semantics, and current rustc's Darwin linker command line.

---

## Operating mode

Treat this as a long-running principal-engineering project.

Do not wait for the user to break the work into individual GitHub issues.

Do not ask for permission between phases unless you encounter a genuinely external blocker that cannot be solved in the repository or local environment.

Maintain a persistent engineering ledger in the repository, for example:

```text
docs/macho-rust-status.md
```

It should contain:

* current baseline;
* current upstream commit;
* macOS/Xcode/SDK versions;
* Rust stable/nightly versions;
* known working features;
* known failures;
* current phase;
* minimal reproducer for every unresolved correctness bug;
* relevant Apple `ld` behavior;
* Wild behavior;
* tests added;
* performance measurements once applicable;
* deferred/non-goal items;
* next work item.

Update it continuously.

A fresh engineer or coding agent should be able to resume the project from this document without reconstructing the entire investigation.

Commit in coherent, reviewable units.

Prefer the cycle:

```text
minimal failing fixture
→ understand Apple behavior
→ implement generic semantic
→ differential test
→ integration test
→ full relevant regression suite
→ commit
```

Do not accumulate a huge untested rewrite.

---

# 1. Preserve Wild's existing architecture

Before editing, read at minimum:

```text
README.md
CONTRIBUTING.md
DESIGN.md
libwild/MachO.md

libwild/src/platform.rs
libwild/src/output_kind.rs
libwild/src/args/
libwild/src/args/macho.rs
libwild/src/macho.rs
libwild/src/macho_aarch64.rs
libwild/src/macho_writer.rs
libwild/src/macho_stub_library.rs

libwild/src/input_data.rs
libwild/src/string_merging.rs
libwild/src/symbol_db.rs
libwild/src/resolution.rs
libwild/src/layout.rs
libwild/src/export_list.rs

wild/tests/
linker-diff/
.github/workflows/
```

Wild's high-level architecture intentionally proceeds through argument parsing, input loading, string merging, symbol discovery/resolution, graph/layout work, and final writing; its integration suite already compiles C/C++/Rust/assembly programs and compares Wild against reference linkers. Preserve that model rather than building a second Mach-O-specific linker pipeline beside it. ([GitHub][3])

Understand the generic abstractions before deciding that Mach-O needs a new one.

In particular, reuse or extend existing generic machinery where semantically appropriate for:

* archive extraction;
* symbol resolution;
* GC/liveness;
* output kinds;
* string merging;
* export lists;
* GOT-like resources;
* thunks/relaxation;
* layout;
* parallel processing;
* validation;
* test fixtures.

However, do **not** force ELF concepts onto Mach-O merely because generic traits currently expose ELF-oriented hooks.

For every `todo!()`, placeholder implementation, or suspicious generic hook reached by the Mach-O backend, classify it as one of:

1. real Mach-O functionality that must be implemented;
2. functionality with a legitimate Mach-O no-op/constant implementation;
3. functionality that should be refactored out of a supposedly generic interface;
4. functionality unreachable for valid Mach-O inputs.

Do not cargo-cult an ELF implementation into category 2 or 3.

---

# 2. Protect existing Wild functionality

macOS support must not destabilize the existing linker.

Before substantial work, record the repository's baseline tests and current failures.

Throughout the project:

* run the project's prescribed formatting/lint/test checks;
* run Mach-O tests on macOS;
* periodically run the ordinary Linux/ELF suite where the environment permits;
* keep generic changes format-independent;
* avoid performance regressions in existing hot paths without justification.

The current CI already contains a dedicated macOS AArch64 Mach-O job using the `macho` feature. Extend it rather than constructing an unrelated testing universe. ([GitHub][1])

A macOS implementation that breaks Wild's existing Linux strengths is not complete.

---

# 3. Establish a hard baseline before implementing features

First, on a real Apple Silicon macOS machine:

1. build current Wild;
2. run every existing Mach-O test;
3. record failures/skips;
4. inventory all Mach-O-related TODOs, panics, assertions, unsupported errors, ignored flags, and feature gates;
5. inventory all open `mach-o` GitHub issues;
6. inspect recent Mach-O PRs and commits so work is not duplicated;
7. capture the current Apple linker, clang, SDK, Xcode command-line tools, Rust stable and Rust nightly versions.

Search at minimum:

```text
TODO
todo!
unimplemented!
panic!
unreachable!
assert!
ignored
unsupported
MachO
macho
```

Do not mechanically "eliminate all TODOs." Many generic hooks may not be meaningful on Mach-O.

Instead produce a categorized audit.

The existing source is visibly incomplete in areas such as:

* `-dead_strip`/GC wiring;
* output-kind handling;
* dynamic-symbol decisions;
* stripping;
* section allocation/classification;
* TLS classification;
* merge-string classification;
* common-symbol handling;
* architecture relaxation;
* architecture identifiers/generic hooks;
* additional AArch64 relocations.

For example, current Mach-O argument code still hard-codes section GC off and executable output on, while the AArch64 backend supports only a limited relocation set and marks returned relocations non-thunkable. ([GitHub][4])

Treat these as evidence of incomplete areas, not as an exhaustive checklist.

---

# 4. Build the conformance laboratory first

Do this before attempting to "finish the linker."

The implementation strategy must be **differential conformance**.

Apple's system linker is the primary behavioral oracle for macOS.

Current `ld64.lld` is a valuable secondary implementation/reference.

For every independently testable Mach-O semantic, arrange:

```text
controlled source/input
        │
        ├─ compile to identical .o/.a inputs
        │
        ├─ Apple ld ───→ reference output
        │
        ├─ ld64.lld ───→ secondary output
        │
        └─ Wild ───────→ candidate output
```

Then compare both structural and behavioral invariants.

Do not require byte-identical binaries where multiple valid encodings exist.

Useful structural tooling includes:

```text
otool -l
otool -L
nm
llvm-nm
llvm-objdump --macho
llvm-objdump --syms
llvm-objdump --reloc
llvm-objdump --unwind-info
dwarfdump
dsymutil
codesign
size
```

Useful behavioral checks include:

```text
execute binary
capture exit status
capture stdout/stderr
dlopen
dlsym
panic/unwind
C++ exception propagation
multithreaded TLS
lldb batch-mode commands
```

Extend Wild's existing integration-test philosophy and `linker-diff`.

`linker-diff` is currently centered on ELF/reference-linker comparison, while Wild's own design explicitly treats differential linking plus execution as its main testing approach. Extend that concept cleanly to Mach-O rather than creating a throwaway script collection. ([GitHub][5])

For each failure, retain enough information to reproduce it:

```text
argv
cwd
environment subset
SDK path/version
input objects
archives
export lists
Apple output
Wild output
inspection output
runtime result
```

Create minimization helpers where useful.

The agent should be able to turn a failure from a huge Cargo build into a small permanent linker fixture.

---

# 5. Capture the real rustc→Darwin linker ABI

Do not guess which ld64 options Rust needs.

Create a transparent linker recorder/delegator.

When rustc invokes the linker, record:

* executable invoked;
* exact argv;
* working directory;
* relevant environment;
* sysroot/SDK;
* target;
* crate type if inferable;
* output path;
* input classes.

Then delegate to Apple's working linker so the Cargo build succeeds.

Normalize ephemeral paths and save representative command lines as fixtures.

Generate the corpus from current stable Rust and current nightly Rust.

Exercise:

```text
bin
lib where applicable
test
example
bench where useful
proc-macro
dylib
cdylib
staticlib

debug
release

panic=abort
panic=unwind

debuginfo=0
debuginfo=1
debuginfo=2

split debuginfo modes supported on Darwin

strip modes

codegen-units=1
multiple codegen units

LTO=off
ThinLTO
fat LTO

-C rpath

Rust thread_local!

build.rs compiling C
build.rs compiling C++

static native archive
whole-archive native dependency

framework link
framework search path

dynamic native dependency

export-limited cdylib
```

Also inspect current `rustc_codegen_ssa` linker behavior directly.

Current rustc emits Darwin-specific behaviors including `-dead_strip`, `-force_load`, `-F`/`-framework`, `-dylib`, `-install_name`, and `-exported_symbols_list`. ([GitHub][6])

The recorded corpus is authoritative for the current compatibility target.

Add every semantically meaningful observed option to a matrix:

```text
option
who emits it
input form
meaning
Wild support
fixture
Cargo test
```

Unknown semantic options must not be silently discarded.

---

# 6. Establish the supported Rust invocation path

Wild already recommends driving the linker through Clang on supported platforms, using mechanisms such as `--ld-path=wild` or `-fuse-ld=wild`. Preserve this general integration model if it works correctly on Darwin instead of patching rustc. ([GitHub][7])

Determine empirically the cleanest macOS Cargo configuration.

The final user experience should be approximately equivalent to setting a target-specific Cargo linker configuration and then running ordinary:

```text
cargo build
cargo test
cargo run
```

Do not require a custom Rust compiler.

Do not patch application source.

Do not allow tests to accidentally fall back to Apple's linker.

Create an invocation audit mechanism so each qualification run can prove which final links were performed by Wild.

A fallback during qualification is a test failure.

---

# 7. Make Darwin argument semantics complete for the Rust contract

Refactor `args/macho.rs` so Mach-O output behavior is modeled rather than hard-coded.

Represent at least the semantically relevant distinction between:

```text
executable
dylib
```

and any additional output kind demonstrated to be necessary.

Implement the complete observed Rust command-line contract.

Likely required semantics include:

```text
-arch
-platform_version
-syslibroot

-L
-l

-F
-framework

-dead_strip
-dead_strip_dylibs

-force_load

-dylib
-install_name

-exported_symbols_list

-rpath

-e
-o

strip/debug-related options
```

But the recorder, not this list, is authoritative.

Distinguish:

* compiler-driver arguments;
* arguments forwarded to ld64;
* direct-linker arguments.

Do not accidentally implement a Clang flag as though it were an ld64 flag.

Preserve useful diagnostics.

If a valid current Rust workflow requires an unsupported semantic, fail explicitly until it is implemented.

---

# 8. Implement Apple SDK and framework lookup correctly

macOS linking is SDK-driven.

Correctly support the current SDK search model required by Clang/rustc:

```text
-syslibroot
-L
-F
-l
-framework
.tbd libraries
framework directories
SDK-relative lookup
```

Use Wild's existing `macho_stub_library.rs` support rather than replacing it.

Audit its current limitations.

For example, the existing reexport handling documents a limited/flat reexport topology; determine whether real SDK libraries exercised by the qualification corpus exceed that model and generalize it if necessary. ([GitHub][8])

Test at least several genuine system frameworks from Rust/C, including something equivalent to:

```rust
#[link(name = "Security", kind = "framework")]
```

Also test:

* ordinary libSystem imports;
* direct `.tbd` lookup;
* framework lookup through explicit `-F`;
* reexported symbols;
* weak exports/imports where encountered;
* two-level namespace / library ordinal behavior.

Never bake paths from one Xcode installation into tests.

Discover SDKs with platform tooling.

---

# 9. Finish Mach-O section and symbol semantics before piling features on top

Audit `macho.rs` carefully.

Current code still contains placeholders around section allocation, TLS, merge strings, common symbols and related classifications. ([GitHub][9])

Implement correct Mach-O semantics for properties used by the generic pipeline, including where relevant:

```text
allocated vs non-allocated
writable
executable
TLS
zerofill
debug
mergeable strings
retain/no-dead-strip
symbol kind
weakness
common/tentative symbol
visibility
function/TLS classification
undefined enforcement
```

Do not continue treating all sections as allocated.

That is especially important for debug sections.

Create focused fixtures for each classification rule.

Do not rely purely on section names where flags/types provide authoritative semantics, except where Mach-O itself conventionally requires name-based interpretation.

---

# 10. Systematically complete ARM64 Mach-O relocations

Do not implement relocation support reactively one crate at a time.

Generate a relocation corpus from:

* Rust;
* C;
* C++;
* hand-written AArch64 assembly.

Inventory all relocation kinds emitted by current compilers and encountered in real libraries.

For each relocation class document:

```text
raw Mach-O relocation type
external/local
PC-relative?
width
addend semantics
paired relocation behavior
GOT requirement
stub requirement
TLV requirement
final expression
range
alignment
overflow behavior
relaxation opportunity
thunkability
```

Current Wild only recognizes a limited subset of AArch64 relocation types and otherwise reports an unknown relocation. Its generic relocation records are currently returned with `thunkable: false`. ([GitHub][10])

Implement every relocation required by the corpus.

Add targeted fixture coverage for each.

Explicitly investigate paired/addend relocation forms rather than assuming every relocation is independent.

Bad or overflowing relocations must yield deterministic linker errors, not truncation.

---

# 11. Implement ARM64 branch islands/thunks

This is a production-scale requirement even if no existing #757 subissue covers it.

`ARM64_RELOC_BRANCH26` has finite reach.

Small programs can therefore appear correct while sufficiently large programs fail.

Integrate Mach-O AArch64 with Wild's existing thunk/relaxation concepts where possible.

The effective algorithm must handle layout feedback:

```text
initial layout
→ inspect branch ranges
→ allocate necessary islands/thunks
→ relayout
→ re-evaluate
→ converge
```

Do not merely reserve a giant unconditional trampoline region.

Preserve locality and Wild's performance goals.

Create a deterministic synthetic binary that forces a direct branch outside ARM64 branch range.

The test must fail without branch islands and pass with them.

Test both calls and jumps as applicable.

Also test multiple islands and a layout in which inserting one island changes other range decisions.

---

# 12. Generalize chained fixups completely

Do not interpret issue #2076 narrowly.

The current writer still explicitly assumes one chained-fixup page and contains an assertion limiting the import/fixup population accordingly. ([GitHub][11])

Model chained fixups as a real multi-page, multi-segment structure.

Correctly handle, as required by produced outputs:

```text
segment starts
page starts
chain termination
next deltas
bind
rebase
library ordinal
symbol table
addend
pointer format
multiple pages
multiple relevant segments
```

Pay attention to the distinction between:

* imports;
* GOT entries;
* writable data pointers;
* rebases;
* binds.

Stress with:

```text
thousands/tens of thousands of imports
multiple fixup pages
fixups in separate output regions
mixed binds/rebases where supported
```

Validate through dyld runtime behavior plus structural inspection.

---

# 13. Make dylib output a first-class subsystem

Do not implement #2161 as "change MH_EXECUTE to MH_DYLIB."

Rust requires real dylib semantics. Current rustc explicitly selects Darwin `-dylib` mode and may emit an `@rpath/...` install name. ([GitHub][12])

Implement output-kind-sensitive Mach-O construction, including as required:

```text
MH_DYLIB
LC_ID_DYLIB

install name
current version
compatibility version

exports trie
imports
dependency load commands

two-level namespace ordinals

rpaths

code signature

export filtering

weak definitions/imports
reexports
```

Executable-only commands such as `LC_MAIN` must not leak into dylibs.

Tests:

1. C dylib linked by Wild, consumed by a program.
2. Rust `cdylib`, consumed from C.
3. Rust `dylib`, consumed from Rust.
4. `dlopen` + `dlsym`.
5. dylib with dependency dylib.
6. dylib using `@rpath`.
7. restricted exports.
8. weak symbols if required.
9. genuine proc-macro Cargo workspace.

Validate with:

```text
otool -l
otool -L
nm
runtime loader
```

Proc macros are a mandatory qualification gate because they exercise dynamic loading during compilation.

---

# 14. Implement export filtering correctly

Current Rust on Darwin writes newline-separated symbol names and supplies them using:

```text
-exported_symbols_list
```

for applicable crate types. ([GitHub][6])

Wire this into Wild's existing generic export-list infrastructure if possible.

Test:

* allowed symbol exported;
* non-listed public-looking symbol absent;
* data exports;
* Rust cdylib exports;
* interaction with dead stripping;
* interaction with weak symbols.

Do not merely parse and ignore the file.

---

# 15. Implement `MH_SUBSECTIONS_VIA_SYMBOLS` and real `-dead_strip`

This is critical for Rust.

Wild's Mach-O notes themselves call out `MH_SUBSECTIONS_VIA_SYMBOLS` as the mechanism that allows symbol-granular section GC despite Mach-O's section-name limitations. ([GitHub][13])

Current rustc deliberately passes `-dead_strip` on Darwin for executables and dynamic libraries. ([GitHub][6])

The GC model therefore cannot permanently remain:

```text
one input Mach-O section = one liveness unit
```

when an object opts into subsections-via-symbols.

Develop the correct atom/subsection model based on symbol boundaries.

Handle edge cases:

* aliases;
* several symbols at one address;
* zero-sized symbols;
* local/global symbols;
* leading bytes;
* trailing bytes;
* no-symbol spans;
* relocation targets into the middle of atoms;
* objects without `MH_SUBSECTIONS_VIA_SYMBOLS`;
* weak/coalesced definitions.

Then integrate these atoms with Wild's existing liveness traversal rather than building separate GC.

Correctly root things such as:

* entry point;
* explicit exports;
* no-dead-strip/retain semantics;
* initialization machinery;
* live unwind records;
* TLS structures;
* dynamically required symbols;
* appropriate synthetic linker data.

Implement `-force_load` archive behavior correctly alongside lazy archive extraction.

Stress test:

```text
10,000 generated functions
small reachable subset
data referenced by only dead functions
archive members with mixtures of live/dead atoms
```

Compare:

* retained symbols;
* runtime result;
* output size;
* important section sizes

against Apple ld.

Exact byte-for-byte equivalence is unnecessary.

Semantic liveness equivalence is required.

---

# 16. Implement Mach-O TLS end to end

Issue #2071 is not merely section recognition.

Current Wild documentation identifies Mach-O TLS structures such as `__thread_vars`, `__thread_bss`, and `__tlv_bootstrap`. ([GitHub][14])

Implement the complete chain:

```text
input section classification
symbol classification
TLS relocations
layout
TLV descriptors
dynamic symbol/import handling
chained fixups where needed
runtime initialization
GC/liveness
```

Exercise at minimum:

```rust
thread_local! {
    static X: ...;
}
```

plus native:

```text
C/C++ TLS
initialized TLS
zero-filled TLS
multiple TLS variables
many threads
TLS accessed through dylib
dead TLS
```

Each thread must observe independent storage.

Do not stop when the binary launches.

---

# 17. Implement compact unwind as a synthesized output structure

Issue #2066 requires real final-binary unwind generation, not merely carrying `__compact_unwind` through to the output. ([GitHub][15])

Study:

* Wild's `MachO.md`;
* Apple output generated from controlled fixtures;
* current LLVM lld Mach-O implementation as a secondary reference.

Correctly transform compiler input compact-unwind records into final:

```text
__TEXT,__unwind_info
```

after sufficient symbol resolution, GC and layout information is available.

Handle:

```text
function addresses
function lengths
encoding
personality
LSDA
sorting
common encodings
first-level index
second-level pages
compressed/regular pages as required
DWARF fallback
dead functions
```

Do not retain unwind records for discarded functions.

Behavioral qualification:

```text
Rust panic=unwind
catch_unwind
deep Rust call stack
C++ throw/catch
C++ destructor cleanup
Rust → C++ → Rust stack
backtrace
```

Structural qualification:

```text
llvm-objdump --unwind-info
```

Unwinding correctness is part of runtime correctness.

---

# 18. Implement DWARF correctly for the macOS toolchain

Issue #2068 notes that Wild currently misses debug-info relocations. ([GitHub][16])

This must be treated as a macOS development requirement.

Correct:

* debug-section classification;
* non-alloc handling;
* relocations inside DWARF;
* post-GC address rewriting;
* debug string references;
* interaction with merging;
* interaction with stripped code.

The acceptance target is not merely "`dwarfdump` doesn't crash."

Require:

```text
Wild link
→ dsymutil
→ dwarfdump verification
→ LLDB
```

Test current Rust-supported combinations of:

```text
-C debuginfo=0
-C debuginfo=1
-C debuginfo=2

split-debuginfo modes

strip modes
```

In LLDB batch mode verify:

* breakpoint by source/function;
* expected source file/line;
* sane Rust function names;
* sane backtrace;
* simple local/argument inspection where available.

A normal debug Cargo build must feel normal.

---

# 19. Implement string merging without corrupting relocations

Finish issue #2070 and any surrounding machinery using Wild's generic string-merging architecture where possible.

Support eligible Mach-O string sections such as:

```text
__TEXT,__cstring
```

and applicable debug strings.

Maintain an explicit mapping such as:

```text
(input section, old offset)
        ↓
canonical merged representation
        ↓
(output section, new offset)
```

All relocations into merged material must be rewritten through this mapping.

Test strings distributed across multiple object files:

```text
"hello"
"hello"
"ello"
"hello world"
```

Cover:

* exact duplicates;
* suffix sharing if implemented;
* symbols/relocations pointing inside merged strings;
* dead strings;
* debug strings.

Matching Apple's exact packing heuristic is optional.

Correct pointer/reference semantics are mandatory.

---

# 20. Finish ABI-level symbol semantics

Audit and implement the smaller pieces that real mixed-language programs rely on.

Include at minimum, where required:

```text
___dso_handle
common/tentative symbols
weak definitions
weak references
private extern visibility
absolute symbols
aliases
C/C++ initialization
C/C++ teardown
```

Issue #2379 specifically tracks synthetic `___dso_handle`; do not treat that isolated symbol as the entire C++ ABI problem.

Create C/C++ interoperability tests demonstrating:

* global constructor runs before `main`;
* destructor/atexit behavior where expected;
* weak resolution behaves like Apple ld;
* tentative/common definitions resolve correctly;
* Rust can call a native library using these facilities.

Use minimal differential fixtures.

---

# 21. Harden `.tbd` and dynamic-library semantics

Do not assume that successfully resolving `_printf` means TBD support is finished.

Exercise current Apple SDK stubs for:

```text
ordinary exports
weak exports
reexports
nested dependencies
different framework/library paths
library ordinals
```

Generalize `macho_stub_library.rs` as required by real SDK fixtures.

Do not invent a complete TAPI implementation if the macOS Rust compatibility contract does not require it, but do not retain an incorrect shortcut once a normal SDK dependency disproves it.

---

# 22. Harden ad-hoc code signing and iterative relinking

Apple Silicon executable validity must survive normal developer rebuild loops.

Wild already emits `LC_CODE_SIGNATURE` machinery; the Mach-O notes explain that executable code signatures are part of final-file layout and page hashing. ([GitHub][11])

Construct adversarial tests:

```text
link target/debug/foo
verify signature
run

modify program
link same pathname
verify signature
run

grow binary substantially
link same pathname
verify signature
run

shrink binary
link same pathname
verify signature
run

repeat
```

Use:

```text
codesign --verify
```

plus actual execution.

Ensure the implementation does not suffer from:

* stale signature data;
* stale file tail data;
* wrong page count;
* wrong file-size hashing boundary;
* output mappings left from previous contents;
* signature calculated before final layout stabilizes.

---

# 23. Test load-command correctness as an explicit layer

For each output kind, define and test the expected load-command contract.

Relevant commands may include:

```text
LC_SEGMENT_64
LC_DYLD_CHAINED_FIXUPS
LC_DYLD_EXPORTS_TRIE
LC_SYMTAB
LC_DYSYMTAB
LC_LOAD_DYLINKER
LC_UUID
LC_BUILD_VERSION
LC_SOURCE_VERSION
LC_MAIN
LC_LOAD_DYLIB
LC_ID_DYLIB
LC_RPATH
LC_FUNCTION_STARTS
LC_DATA_IN_CODE
LC_CODE_SIGNATURE
```

The exact set may differ by output/features.

Do not blindly clone Apple's complete command list.

Instead ensure every command Wild emits is valid and every omitted command is genuinely optional for the supported contract.

Validate:

* offsets;
* alignments;
* VM/file sizes;
* section placement;
* segment permissions;
* command sizes;
* SDK/minimum OS versions;
* dylib identities;
* dylib dependencies.

---

# 24. Exercise malformed inputs and diagnostics

A production linker must fail safely.

Add negative tests for:

* malformed Mach-O object;
* invalid relocation;
* impossible relocation range;
* missing dylib;
* missing framework;
* malformed TBD;
* duplicate/conflicting definitions;
* undefined symbol;
* invalid exported-symbol-list file;
* invalid argument combination;
* unsupported architecture.

A bad input must not yield:

```text
panic
assertion failure
memory corruption
silently malformed output
```

Diagnostics need not byte-match Apple ld but should identify the actionable problem.

---

# 25. Build the Rust synthetic qualification matrix

Once individual facilities are implemented, create a dedicated Rust-on-macOS compatibility suite.

Test at least:

## Crate/output type

```text
binary
test harness
example
proc-macro
dylib
cdylib
staticlib
```

## Optimization

```text
debug
release
-O variants where useful
codegen-units=1
many codegen units
```

## Panic

```text
abort
unwind
```

## LTO

```text
off
thin
fat
```

Do not make `linker-plugin-lto` block the initial milestone unless current normal Rust/macOS workflows require it. Treat linker-plugin LTO as a separate compatibility feature because it requires the native linker to participate in LLVM bitcode/plugin semantics.

## Debug

```text
debuginfo 0/1/2
dSYM generation
LLDB
strip
```

## Runtime/linker facilities

```text
TLS
rpath
dlopen
framework
native C
native C++
static archive
force-load archive
weak symbol
constructor
panic unwind
C++ exception
restricted exports
```

## Scale

```text
large object count
large archive
large symbol count
large import/fixup count
huge dead-strip workload
>direct ARM64 branch range
large DWARF
```

Record proof that Wild handled every expected final link.

---

# 26. Build a real-world Cargo corpus

Synthetic tests are necessary but insufficient.

Create an escalating corpus of current, healthy Rust projects.

Include representative examples of:

* derive/proc-macro heavy code;
* async runtime;
* regex/codegen-heavy libraries;
* substantial CLI applications;
* networking;
* native C dependencies;
* native C++ dependencies;
* macOS frameworks;
* dynamic loading where available.

Possible candidates include projects/crates in the general class of:

```text
serde + serde_derive
regex
ripgrep
clap derive
rayon
tokio
reqwest
ring or another native dependency
git2 or another native-library consumer
```

Do not rigidly preserve this exact list if contemporary versions make a better corpus available.

For each:

```text
cargo clean
cargo build
cargo test
```

as applicable.

Run both stable and nightly periodically.

Capture failures and minimize linker-specific ones into permanent Wild tests.

Do not patch third-party crate source to accommodate Wild unless the crate itself is objectively incorrect.

---

# 27. Test incremental Cargo workflows even though Wild itself is not incremental

Wild's future incremental linker work is explicitly **out of scope**.

However, ordinary incremental Rust compilation is not.

Exercise repeated workflows:

```text
cargo build
edit one Rust source
cargo build

edit build.rs dependency
cargo build

edit proc-macro consumer
cargo build

change dylib-producing crate
cargo build
```

This catches same-path output replacement, dynamic-loading, signature, stale-file and dependency issues.

Do not confuse "Cargo incremental compilation works with Wild" with "Wild implements incremental linking."

---

# 28. Self-host Wild on macOS

Once the broad Cargo corpus is green:

Build Wild itself using Wild for its final macOS links.

Prove the linker selection rather than relying on configuration.

Then run Wild's own complete relevant test suite under the resulting build.

Self-hosting is an important confidence gate but is not the final one.

---

# 29. Bootstrap Rust with Wild

The strongest Apple-Silicon qualification gate is Rust itself.

Obtain the current Rust compiler source tree.

Configure its macOS host linker path so applicable `aarch64-apple-darwin` host links use Wild.

Do not change Rust semantics or add Wild-specific source hacks.

Attempt progressively:

```text
bootstrap prerequisites
stage1 compiler
compiler shared artifacts
rustc_driver
major tools
```

The exact bootstrap stages may vary with current Rust.

Use the current Rust build system rather than assumptions in this prompt.

Run relevant contemporary Rust link/run-make tests for Darwin.

This workload is valuable because it stresses:

* huge Rust dependency graphs;
* proc macros;
* dynamic libraries;
* export control;
* native libraries;
* large binaries;
* debug information;
* unwind metadata;
* archive extraction;
* many symbols.

Every linker failure discovered here should be minimized into a permanent Wild regression fixture whenever practical.

The agreed Apple-Silicon production milestone should not be declared complete before a substantial Rust compiler bootstrap using Wild succeeds.

---

# 30. Benchmark only after correctness

The purpose of this project is ultimately link speed, but correctness comes first.

Do not distort architecture to optimize a workload that is still failing conformance tests.

Use the linker invocation recorder to replay identical real links against:

```text
Apple ld
Wild
ld64.lld
```

Measure:

```text
wall time
user CPU
system CPU
peak RSS
output size
```

Use multiple warm repetitions.

At minimum benchmark:

```text
tiny Rust binary
medium Rust project
proc-macro-heavy workspace
native-dependency workspace
large Rust application
Wild itself
large rustc/rustc_driver artifact
```

Distinguish:

```text
link-only time
```

from:

```text
full cargo build time
```

because compilation can hide linker improvements.

Wild's own Mach-O notes already contain examples where Apple's linker beats lld on substantial native workloads, so speed superiority must be measured rather than presumed. ([GitHub][13])

If Wild is slower on an important workload:

1. profile;
2. identify the actual linker phase;
3. optimize without weakening correctness;
4. preserve benchmark results before/after.

Do not implement incremental linking as part of this project.

---

# 31. Apple Silicon is the first production milestone

Do not dilute the first milestone by simultaneously implementing every Darwin architecture.

Finish:

```text
aarch64-apple-darwin
```

to production quality first.

That means **all** important generic abstractions should be designed so another Mach-O architecture can plug in cleanly, but implementation effort should remain concentrated.

Only then add:

```text
x86_64-apple-darwin
```

Implement its actual relocation/stub/thunk semantics rather than copying ARM64 code.

Run the same:

* differential fixtures;
* Cargo matrix;
* dylib tests;
* debug tests;
* runtime tests;
* stress tests.

Universal/fat Mach-O output does not need to block platform completion.

Producing two valid thin binaries and combining them externally with `lipo` is sufficient unless a real Rust/toolchain workflow proves otherwise.

---

# 32. Explicitly exclude other Apple platforms

Do not allow the project to expand into:

```text
iOS
iOS simulator
watchOS
tvOS
visionOS
Mac Catalyst
```

unless a generic refactor necessary for macOS naturally helps them.

They require additional platform/deployment/SDK rules and are separate projects.

This charter is for macOS.

---

# 33. Things you must not do

Do not:

* special-case crate names;
* special-case rustc-generated filenames;
* special-case a particular SDK version without format justification;
* silently ignore meaningful ld64 flags;
* blindly copy lld behavior when Apple ld differs;
* treat lld as more authoritative than the actual macOS runtime/toolchain;
* treat "loads successfully" as proof of unwind/debug correctness;
* implement dylib support as only a Mach-O header switch;
* disable dead stripping to make tests pass;
* disable unwind data to make links pass;
* disable debug info to make links pass;
* invoke `codesign` externally as a permanent substitute for correct linker output unless the project's explicitly supported mode calls for it;
* fall back to Apple ld silently;
* patch Rust to accommodate Wild;
* rewrite Wild's generic architecture unnecessarily;
* duplicate generic ELF functionality in Mach-O-specific code if a clean abstraction can serve both;
* refactor large unrelated areas while trying to land one semantic;
* sacrifice existing Linux support;
* declare success based only on issue tracker completion.

---

# 34. Prefer empirical answers to linker folklore

Whenever Mach-O behavior is uncertain:

create the smallest possible input and ask Apple's linker.

For example:

```text
one weak definition
one weak reference
one dead subsection
one compact-unwind personality
one reexport
one chained-fixup page boundary
one common symbol
one unusual relocation
```

Then inspect the resulting Mach-O.

This is preferable to guessing from blog posts or implementing whatever seems analogous to ELF.

Use:

1. Apple's produced output and runtime behavior;
2. Apple headers/documentation where available;
3. LLVM lld source;
4. the `object` crate;
5. high-quality format references;

in roughly that order of authority for compatibility questions.

---

# 35. Upstream-quality implementation standards

New code should look like it belongs in Wild.

Prefer:

* typed representations over magic integers;
* checked arithmetic for file offsets/VM addresses;
* explicit endian writes;
* deterministic output;
* bounds checking;
* narrowly scoped `unsafe`;
* comments explaining non-obvious Mach-O invariants;
* tests for overflow and boundary conditions.

Do not merely translate lld C++ classes line-for-line.

Adapt semantics to Wild's architecture.

Avoid making serial phases expensive. Wild's design places strong emphasis on parallel processing, so watch for accidentally introducing global locks or giant sequential maps into hot paths. ([GitHub][3])

Correctness comes first, but architectural decisions should not foreclose Wild's speed advantage.

---

# 36. CI expectations

Evolve the existing Mach-O macOS CI into multiple confidence levels where runtime budget permits.

At minimum:

## Per-PR fast suite

```text
Mach-O unit/integration fixtures
argument parsing
relocations
basic executables
basic dylib
dead_strip
TLS
unwind
DWARF smoke
code signing
```

## Larger macOS qualification

Potentially scheduled/manual if too expensive:

```text
real Cargo corpus
stress tests
stable + nightly
large branch/fixup tests
LLDB/dsymutil
self-host Wild
```

## Very expensive qualification

Potentially manual/nightly:

```text
Rust bootstrap
large performance suite
x86_64 cross/host validation
```

Do not make normal pull requests require hours unnecessarily.

But all expensive qualification commands must be documented and reproducible.

---

# 37. Maintain a compatibility matrix

Keep a machine-readable or Markdown matrix resembling:

| Facility       | Minimal fixture | Apple differential | Rust integration | Stress test | Status |
| -------------- | --------------- | ------------------ | ---------------- | ----------- | ------ |
| executable     | ...             | pass               | pass             | n/a         | green  |
| dylib          | ...             | pass               | pass             | ...         | green  |
| framework      | ...             | pass               | pass             | n/a         | green  |
| dead strip     | ...             | pass               | pass             | pass        | green  |
| TLS            | ...             | pass               | pass             | pass        | green  |
| compact unwind | ...             | pass               | pass             | pass        | green  |
| DWARF          | ...             | pass               | pass             | pass        | green  |
| chained fixups | ...             | pass               | pass             | pass        | green  |
| branch islands | ...             | pass               | pass             | pass        | green  |

Never replace failures with vague prose such as "mostly works."

Record exact unsupported semantics.

---

# 38. Apple-Silicon definition of done

Do not declare `aarch64-apple-darwin` production-ready until all of the following are true.

* [ ] Existing Wild Mach-O tests pass.
* [ ] Existing non-Mach-O functionality remains healthy.
* [ ] All current stable/nightly Darwin linker arguments exercised by the qualification corpus are either correctly implemented or intentionally diagnosed as unsupported outside the declared scope.
* [ ] Qualification contains no silent fallback to Apple ld.
* [ ] Normal Rust debug executables build and run.
* [ ] Normal Rust release executables build and run.
* [ ] Rust tests link and run.
* [ ] Proc macros build and load.
* [ ] `cdylib` works.
* [ ] Rust `dylib` works to the extent supported by current rustc.
* [ ] `staticlib` workflows remain usable.
* [ ] SDK `.tbd` libraries work.
* [ ] Apple frameworks work.
* [ ] `-force_load` works.
* [ ] `-exported_symbols_list` works.
* [ ] `-rpath` / install-name workflows work.
* [ ] `MH_SUBSECTIONS_VIA_SYMBOLS` is modeled correctly.
* [ ] `-dead_strip` is semantically correct.
* [ ] Rust TLS works.
* [ ] Native C/C++ TLS works for the supported corpus.
* [ ] Multi-page chained fixups work.
* [ ] Large import/fixup stress passes.
* [ ] All current required AArch64 relocations are implemented.
* [ ] Out-of-range ARM64 branches succeed via correct islands/thunks.
* [ ] Compact unwind is generated correctly.
* [ ] `panic=unwind` works.
* [ ] mixed Rust/C++ unwinding works.
* [ ] DWARF relocations are correct.
* [ ] `dsymutil` succeeds.
* [ ] LLDB source-level debugging works.
* [ ] string merging preserves references.
* [ ] weak/common/ABI edge tests pass.
* [ ] repeated same-path rebuilds produce valid signatures and runnable binaries.
* [ ] malformed inputs fail diagnostically rather than panicking.
* [ ] substantial real Cargo corpus passes.
* [ ] Wild builds Wild.
* [ ] substantial Rust compiler bootstrap uses Wild successfully.
* [ ] performance is measured against Apple ld and lld.
* [ ] status/compatibility documentation is current.
* [ ] CI permanently covers the critical semantics.

Only then call the Apple-Silicon macOS implementation production-ready.

---

# 39. General macOS definition of done

After ARM64 reaches the previous milestone:

* [ ] implement x86_64 Mach-O architecture semantics;
* [ ] run the same differential framework;
* [ ] run the same Rust synthetic matrix;
* [ ] run representative Cargo workloads;
* [ ] verify debug/unwind/dylib/GC/TLS behavior;
* [ ] verify architecture-specific branch/relocation boundaries;
* [ ] demonstrate thin ARM64 and x86_64 outputs can participate in normal `lipo` workflows.

Only after both architectures are green should documentation advertise Wild as broadly supporting macOS.

---

# 40. Final deliverables

The finished project should contain:

1. **Production Mach-O implementation**

   * Apple Silicon first;
   * x86_64 afterward.

2. **Darwin differential conformance harness**

   * Apple ld;
   * optional lld comparison;
   * structural/runtime checking.

3. **Rust linker-invocation recorder/replayer**

   * reusable for future Rust releases.

4. **Focused Mach-O regression fixtures**

   * one semantic per fixture where practical.

5. **Rust synthetic integration suite**

6. **Real-world Cargo qualification suite**

7. **Mach-O stress suite**

   * branch range;
   * chained fixups;
   * symbol/archive scale;
   * dead strip;
   * DWARF.

8. **Debugger/unwind tests**

9. **Self-hosting test**

10. **Rust bootstrap qualification**

11. **Performance benchmark/replay tooling**

12. **CI coverage**

13. **Current compatibility/status documentation**

14. **User-facing Cargo/macOS documentation**
    explaining the supported way to select Wild as the linker.

---

# 41. Final report

When the work is complete, produce a concise but evidence-heavy report containing:

```text
Upstream/base commit

Architectures supported

macOS/SDK/Xcode versions tested

Rust versions tested

Mach-O facilities implemented

Remaining deliberate limitations

Existing #757 issues resolved or superseded

Rust synthetic matrix results

Real Cargo corpus results

Wild self-host result

Rust bootstrap result

Apple ld differential result

lld differential result where used

Performance:
  workload
  Apple ld
  ld64.lld
  Wild
  speedup/slowdown
  RSS

Known risks

Exact commands to reproduce qualification

Recommended follow-up work
```

Do not report "complete" if qualification gates remain red.

If something outside the declared scope remains unsupported, state it precisely.

---

# Execution priority

Unless current repository state demonstrates that a dependency ordering has changed, work approximately in this order:

```text
1. inspect / baseline / status ledger
2. Mach-O differential harness
3. Rust linker recorder + command corpus
4. Darwin argument/output-kind correctness
5. section/symbol classification
6. SDK/framework semantics
7. ARM64 relocation completion
8. chained-fixup generalization
9. ARM64 branch islands
10. dylib output
11. rpath/install-name/export filtering
12. subsections-via-symbols + dead_strip
13. TLS
14. ABI/common/weak/native initialization edges
15. compact unwind
16. DWARF + dsymutil/LLDB
17. string merging and remaining format cleanup
18. code-signing/relink torture
19. synthetic Rust matrix
20. real Cargo corpus
21. Wild self-host
22. Rust bootstrap
23. correctness cleanup
24. performance profiling/optimization
25. x86_64 Mach-O
26. final documentation/qualification
```

Independent items may proceed in parallel if doing so does not obscure causality.

If a later workload exposes a missing foundational semantic, stop treating it as an application bug:

```text
reproduce
→ minimize
→ add linker fixture
→ fix linker
→ resume workload
```

---

# North star

The objective is not:

> "Wild can emit Mach-O."

It is:

> **On macOS, a Rust developer can select Wild in Cargo, continue using the ordinary Rust/Apple toolchain, and trust the result—executables, tests, proc macros, native dependencies, dylibs, TLS, panics, debug builds and large projects included—while receiving a measurably faster linker where Wild's architecture can deliver one.**

Build the conformance machinery necessary to make that claim defensible, then keep working until the evidence supports it.

[1]: https://github.com/wild-linker/wild/blob/main/.github/workflows/ci.yml "wild/.github/workflows/ci.yml at main · wild-linker/wild · GitHub"
[2]: https://github.com/wild-linker/wild/issues/757 "MachO support · Issue #757 · wild-linker/wild · GitHub"
[3]: https://github.com/wild-linker/wild/blob/main/DESIGN.md "wild/DESIGN.md at main · wild-linker/wild · GitHub"
[4]: https://github.com/wild-linker/wild/blob/main/libwild/src/args/macho.rs "wild/libwild/src/args/macho.rs at main · wild-linker/wild · GitHub"
[5]: https://github.com/wild-linker/wild/tree/main/linker-diff "wild/linker-diff at main · wild-linker/wild · GitHub"
[6]: https://github.com/rust-lang/rust/blob/master/compiler/rustc_codegen_ssa/src/back/linker.rs "rust/compiler/rustc_codegen_ssa/src/back/linker.rs at main · rust-lang/rust · GitHub"
[7]: https://github.com/wild-linker/wild "GitHub - wild-linker/wild: A very fast linker for Linux · GitHub"
[8]: https://github.com/wild-linker/wild/blob/main/libwild/src/macho_stub_library.rs "wild/libwild/src/macho_stub_library.rs at main · wild-linker/wild · GitHub"
[9]: https://github.com/wild-linker/wild/blob/main/libwild/src/macho.rs "wild/libwild/src/macho.rs at main · wild-linker/wild · GitHub"
[10]: https://github.com/wild-linker/wild/blob/main/libwild/src/macho_aarch64.rs "wild/libwild/src/macho_aarch64.rs at main · wild-linker/wild · GitHub"
[11]: https://github.com/wild-linker/wild/blob/main/libwild/src/macho_writer.rs "wild/libwild/src/macho_writer.rs at main · wild-linker/wild · GitHub"
[12]: https://github.com/wild-linker/wild/issues/2161?utm_source=chatgpt.com "Mach-O: Support emitting dylibs · Issue #2161 · wild-linker/wild"
[13]: https://github.com/wild-linker/wild/blob/main/libwild/MachO.md "wild/libwild/MachO.md at main · wild-linker/wild · GitHub"
[14]: https://github.com/wild-linker/wild/issues/2071?utm_source=chatgpt.com "Mach-O: TLS support · Issue #2071 · wild-linker/wild"
[15]: https://github.com/wild-linker/wild/issues/2066?utm_source=chatgpt.com "Mach-O: add support for `__compact_unwind` · Issue #2066"
[16]: https://github.com/wild-linker/wild/issues/2068?utm_source=chatgpt.com "Mach-O: support DWARF debugging format · Issue #2068"
