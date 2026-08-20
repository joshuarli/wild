use crate::FileSystem;
use crate::OutputKind;
use crate::alignment;
use crate::alignment::Alignment;
use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::args::macho::MachOArgs;
use crate::bail;
use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::file_writer::copy_section_data;
use crate::grouping::SequencedInput;
use crate::input_data::FileId;
use crate::layout;
use crate::layout::HandlerData as _;
use crate::layout::Layout;
use crate::layout::OutputRecordLayout;
use crate::layout::Resolution;
use crate::layout::StubLibraryLayoutState;
use crate::layout::SymbolCopyInfo;
use crate::layout::SymbolResolutions;
use crate::layout_rules::SectionKind;
use crate::layout_rules::SectionRule;
use crate::macho::output_section_id::CHAINED_FIXUP_TABLE;
use crate::macho::output_section_id::CODE_SIGNATURE;
use crate::macho::output_section_id::EXPORTS_TRIE;
use crate::macho::output_section_id::LOAD_COMMANDS;
use crate::macho::output_section_id::STRTAB;
use crate::macho::output_section_id::SYMTAB_GLOBAL;
use crate::macho_writer;
use crate::output_section_id::FILE_HEADER;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrderBuilder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionIdentity;
use crate::output_section_id::SectionName;
use crate::output_section_id::SectionOutputInfo;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id::PartId;
use crate::platform;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::platform::SectionHeader as _;
use crate::platform::Symbol as _;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::resolution;
use crate::symbol_db::SymbolId;
use crate::symbol_db::Visibility;
use crate::timing_phase;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use anyhow::Context;
use itertools::Itertools;
use object::Endianness;
use object::SymbolIndex;
use object::macho;
use object::macho::N_ABS;
use object::macho::N_EXT;
use object::macho::N_INDR;
use object::macho::N_PEXT;
use object::macho::N_SECT;
use object::macho::N_UNDF;
use object::macho::N_WEAK_DEF;
use object::macho::N_WEAK_REF;
use object::macho::S_ATTR_DEBUG;
use object::macho::S_ATTR_EXT_RELOC;
use object::macho::S_ATTR_LIVE_SUPPORT;
use object::macho::S_ATTR_LOC_RELOC;
use object::macho::S_ATTR_NO_DEAD_STRIP;
use object::macho::S_ATTR_NO_TOC;
use object::macho::S_ATTR_PURE_INSTRUCTIONS;
use object::macho::S_ATTR_SOME_INSTRUCTIONS;
use object::macho::S_CSTRING_LITERALS;
use object::macho::S_GB_ZEROFILL;
use object::macho::S_THREAD_LOCAL_REGULAR;
use object::macho::S_THREAD_LOCAL_VARIABLES;
use object::macho::S_THREAD_LOCAL_ZEROFILL;
use object::macho::S_ZEROFILL;
use object::macho::SECTION_ATTRIBUTES;
use object::macho::SEG_LINKEDIT;
use object::macho::Section64;
pub use object::macho::SectionFlags;
use object::read::macho::MachHeader;
use object::read::macho::Nlist;
use object::read::macho::Section;
use object::read::macho::Segment;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::num::NonZeroU8;
use std::num::NonZeroU64;
use std::ops::Range;
use std::slice::Iter;
use std::sync::atomic::Ordering;

use gimli::Reader as _;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct MachO;

pub(crate) fn link_for_arch<'data, F: FileSystem>(
    linker: &'data crate::Linker<F>,
    args: &'data MachOArgs,
) -> Result<crate::LinkerOutput<'data>> {
    if !(cfg!(feature = "macho") || args.common().experimental_platforms) {
        crate::bail!(
            "Mach-O support is still experimental. Rebuild with `--features macho` to enable it."
        );
    }

    linker.link_for_arch::<MachO, crate::macho_aarch64::MachOAArch64>(args)
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum SinglePartSectionId {
    Strtab = crate::output_section_id::NUM_COMMON_SINGLE_PART_SECTIONS,
    Got,
    /// Runtime-bound pointers to TLV descriptors imported from dynamic libraries. Although a
    /// TLVP instruction pair has the same ADRP/LDR shape as a GOT load, its target is a
    /// descriptor selected by dyld for each image, not a normal symbol address.
    Tlvp,
    PltGot,
    /// Selector-reference slots synthesized for Clang's modern ARM64 Objective-C message
    /// dispatch ABI. dyld rebases each slot and libobjc canonicalises it during image setup.
    ObjcSelectorReferences,
    /// `-const_selrefs` uses the same selector ABI, but preserves the post-fixup read-only
    /// contract by placing the slots in `__DATA_CONST` rather than writable `__DATA`.
    ObjcConstSelectorReferences,
    /// Linker-synthesized ARM64 stubs for undefined `_objc_msgSend$selector` references.
    /// They load the selector reference into x1 before branching through `_objc_msgSend`'s GOT.
    ObjcMessageStubs,
    SymtabGlobal,
    LinkEditSegment,
    LoadCommands,
    CodeSignature,
    ChainedFixupTable,
    ExportsTrie,
    /// The selected DWARF CIE/FDE records used by ARM64 compact-unwind DWARF rows. Input
    /// `__eh_frame` is object metadata; the writer rebuilds its backward CIE references after
    /// GC and concatenation, then emits this final `__TEXT,__eh_frame` section.
    EhFrame,
    /// The final, page-indexed compact unwind table. Input `__compact_unwind` records are linker
    /// metadata and are translated into this `__TEXT,__unwind_info` section after GC has assigned
    /// every surviving function its final address.
    UnwindInfo,

    // Must be last.
    Count,
}

pub(crate) mod part_id {
    use super::SinglePartSectionId;
    use crate::part_id::PartId;

    pub(crate) const STRTAB: PartId = SinglePartSectionId::Strtab.part_id();
    pub(crate) const GOT: PartId = SinglePartSectionId::Got.part_id();
    pub(crate) const TLVP: PartId = SinglePartSectionId::Tlvp.part_id();
    pub(crate) const PLT_GOT: PartId = SinglePartSectionId::PltGot.part_id();
    pub(crate) const OBJC_SELECTOR_REFERENCES: PartId =
        SinglePartSectionId::ObjcSelectorReferences.part_id();
    pub(crate) const OBJC_CONST_SELECTOR_REFERENCES: PartId =
        SinglePartSectionId::ObjcConstSelectorReferences.part_id();
    pub(crate) const OBJC_MESSAGE_STUBS: PartId = SinglePartSectionId::ObjcMessageStubs.part_id();
    pub(crate) const SYMTAB_GLOBAL: PartId = SinglePartSectionId::SymtabGlobal.part_id();
    pub(crate) const LOAD_COMMANDS: PartId = SinglePartSectionId::LoadCommands.part_id();
    pub(crate) const CODE_SIGNATURE: PartId = SinglePartSectionId::CodeSignature.part_id();
    pub(crate) const CHAINED_FIXUP_TABLE: PartId = SinglePartSectionId::ChainedFixupTable.part_id();
    pub(crate) const EXPORTS_TRIE: PartId = SinglePartSectionId::ExportsTrie.part_id();
    pub(crate) const EH_FRAME: PartId = SinglePartSectionId::EhFrame.part_id();
    pub(crate) const UNWIND_INFO: PartId = SinglePartSectionId::UnwindInfo.part_id();
}

pub(crate) mod output_section_id {
    use super::MachO;
    use super::SinglePartSectionId;
    use crate::output_section_id::OutputSectionId;

    pub(crate) const STRTAB: OutputSectionId = SinglePartSectionId::Strtab.output_section_id();
    pub(crate) const GOT: OutputSectionId = SinglePartSectionId::Got.output_section_id();
    pub(crate) const TLVP: OutputSectionId = SinglePartSectionId::Tlvp.output_section_id();
    pub(crate) const PLT_GOT: OutputSectionId = SinglePartSectionId::PltGot.output_section_id();
    pub(crate) const OBJC_SELECTOR_REFERENCES: OutputSectionId =
        SinglePartSectionId::ObjcSelectorReferences.output_section_id();
    pub(crate) const OBJC_CONST_SELECTOR_REFERENCES: OutputSectionId =
        SinglePartSectionId::ObjcConstSelectorReferences.output_section_id();
    pub(crate) const OBJC_MESSAGE_STUBS: OutputSectionId =
        SinglePartSectionId::ObjcMessageStubs.output_section_id();
    pub(crate) const SYMTAB_GLOBAL: OutputSectionId =
        SinglePartSectionId::SymtabGlobal.output_section_id();
    pub(crate) const LINK_EDIT_SEGMENT: OutputSectionId =
        SinglePartSectionId::LinkEditSegment.output_section_id();
    pub(crate) const LOAD_COMMANDS: OutputSectionId =
        SinglePartSectionId::LoadCommands.output_section_id();
    pub(crate) const CODE_SIGNATURE: OutputSectionId =
        SinglePartSectionId::CodeSignature.output_section_id();
    pub(crate) const CHAINED_FIXUP_TABLE: OutputSectionId =
        SinglePartSectionId::ChainedFixupTable.output_section_id();
    pub(crate) const EXPORTS_TRIE: OutputSectionId =
        SinglePartSectionId::ExportsTrie.output_section_id();
    pub(crate) const EH_FRAME: OutputSectionId = SinglePartSectionId::EhFrame.output_section_id();
    pub(crate) const UNWIND_INFO: OutputSectionId =
        SinglePartSectionId::UnwindInfo.output_section_id();

    /// The primary ARM64 code section. Keeping it as a regular section gives range-extension
    /// thunks an addressable 4-byte-aligned part that can be placed immediately after the object
    /// which owns each island. `__stubs` is deliberately not used: it is reserved for dyld
    /// symbol stubs and can be more than a branch range away from ordinary input code.
    pub(crate) const TEXT: OutputSectionId =
        crate::output_section_id::regular_section_base::<MachO>();
    /// Tentative C/C++ definitions have no input section. ld64 materializes their selected
    /// definition in this zero-fill section instead of treating N_UNDF as an unresolved reference.
    pub(crate) const COMMON: OutputSectionId = TEXT.offset(1);
}

const LE: Endianness = Endianness::Little;

/// Mach-O uses a zero page for all 32bit addresses and thus we begin the memory
/// offsets right after that (1GiB).
pub(crate) const MACHO_START_MEM_ADDRESS: u64 = 0x1_0000_0000;

/// The command alignment is 8B for 64-bit platforms.
pub(crate) const MACHO_COMMAND_ALIGNMENT: usize = 8;

/// A path to the default dynamic linker.
pub(crate) const DYLINKER_PATH: &[u8] = b"/usr/lib/dyld";

// TODO: Getting the number of active segments in epilogue depends on determine_header_size
// which is called later for the prologue. We potentially over-allocate a couple of bytes.
pub(crate) const MAX_SEGMENT_COUNT: usize = 6;
/// `dyld_chained_starts_in_image` is 8-byte aligned after the 28-byte header. The object crate's
/// packed `ChainedStartsInSegment` omits C's flexible `page_start[1]`, so its 22-byte fixed
/// prefix must be followed explicitly by the first two-byte page entry on the wire.
pub(crate) const CHAINED_STARTS_IN_IMAGE_OFFSET: usize =
    size_of::<ChainedFixupsHeader>().next_multiple_of(size_of::<u64>());
pub(crate) const CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE: usize =
    size_of::<ChainedStartsInSegment>();
pub(crate) const CHAINED_FIXUP_TABLE_BASE_SIZE: u64 = (CHAINED_STARTS_IN_IMAGE_OFFSET
    + size_of::<u32>() * (MAX_SEGMENT_COUNT + /* leading segment count */ 1)
    + CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE
    + size_of::<u16>())
    as u64;
pub(crate) const CHAINED_FIXUP_IMPORT_SIZE: u64 = size_of::<u32>() as u64;
pub(crate) const CHAINED_FIXUP_PAGE_START_SIZE: u64 = size_of::<u16>() as u64;
pub(crate) const GOT_ENTRY_SIZE: u64 = 8;
pub(crate) const PLT_ENTRY_SIZE: u64 = 12;
/// Apple emits a six-instruction-and-padding selector dispatch stub for every modern Objective-C
/// selector symbol. Keep this separate from a normal 12-byte dyld symbol stub: it must first
/// materialize the selector into x1.
pub(crate) const OBJC_MESSAGE_STUB_SIZE: u64 = 32;
pub(crate) const OBJC_SELECTOR_REFERENCE_SIZE: u64 = 8;

/// Returns the selector suffix of Clang's ARM64 modern-message-dispatch undefined symbol.
///
/// `_objc_msgSend$selector` is not a dynamic-library symbol. ld64 binds `_objc_msgSend` and
/// emits a local veneer which sets x1 to a selector reference. Empty suffixes are intentionally
/// not accepted: they are neither emitted by Clang nor a meaningful Objective-C selector.
pub(crate) fn objc_message_selector(name: &[u8]) -> Option<&[u8]> {
    name.strip_prefix(b"_objc_msgSend$").filter(|selector| !selector.is_empty())
}

/// Returns the synthetic selector-reference storage selected by the Mach-O command-line ABI.
/// The two variants deliberately have separate section IDs: a built-in output section's segment
/// and flags are fixed before layout, while `-const_selrefs` changes both of those properties.
pub(crate) fn objc_selector_references_part_id(args: &MachOArgs) -> crate::part_id::PartId {
    if args.const_selrefs {
        part_id::OBJC_CONST_SELECTOR_REFERENCES
    } else {
        part_id::OBJC_SELECTOR_REFERENCES
    }
}

pub(crate) fn objc_selector_references_output_section_id(
    args: &MachOArgs,
) -> crate::output_section_id::OutputSectionId {
    if args.const_selrefs {
        output_section_id::OBJC_CONST_SELECTOR_REFERENCES
    } else {
        output_section_id::OBJC_SELECTOR_REFERENCES
    }
}

/// `compact_unwind_entry` records in `__LD,__compact_unwind` are fixed-width. They are only an
/// object-file representation: final Mach-O images contain the indexed `__unwind_info` encoding
/// synthesized by `macho_writer`.
pub(crate) const COMPACT_UNWIND_ENTRY_SIZE: usize = 32;

/// The regular second-level unwind page is the conservative encoding: unlike compressed pages it
/// has no 24-bit function-offset or 8-bit encoding-index limitation. A page stays within the
/// format's 4 KiB page bound at this entry count.
pub(crate) const COMPACT_UNWIND_REGULAR_PAGE_MAX_ENTRIES: usize = (4096 - 8) / 8;

/// An upper bound for the final `__unwind_info` serialization of `entry_count` input compact
/// unwind records. The writer filters dead-stripped functions after addresses are known, so this
/// allocation deliberately uses the input count and leaves any tail zero-filled.
pub(crate) fn compact_unwind_info_capacity(entry_count: usize) -> usize {
    if entry_count == 0 {
        return 0;
    }

    let page_count = entry_count.div_ceil(COMPACT_UNWIND_REGULAR_PAGE_MAX_ENTRIES);
    // Header, up to three personalities, one top-level index per page plus its sentinel, one
    // worst-case LSDA descriptor per entry, and the regular second-level page contents.
    28 + 3 * 4 + (page_count + 1) * 12 + entry_count * 8 + page_count * 8 + entry_count * 8
}

/// Allocate enough room for every input record plus the sole output terminator. The final writer
/// only retains CIEs that have a live FDE, so the actual serialization can be smaller, but it
/// never needs more bytes than the complete input sections and one four-byte terminator. The
/// synthetic section has 8-byte pointer alignment, so its reserved part must end on that boundary
/// even though the terminator itself is four bytes.
pub(crate) fn eh_frame_capacity(input_size: usize) -> Result<usize> {
    let size = input_size
        .checked_add(size_of::<u32>())
        .context("Mach-O __eh_frame input is too large")?;
    Ok(size
        .checked_add(7)
        .context("Mach-O __eh_frame alignment overflows")?
        & !7)
}

type SectionHeader = Section64<crate::macho::Endianness>;
type SectionTable<'data> = &'data [Section64<crate::macho::Endianness>];
type SymbolTable<'data> = object::read::macho::SymbolTable<'data, macho::MachHeader64<Endianness>>;
type RawSymtabEntry = object::macho::Nlist64<Endianness>;
type Relocation = object::macho::Relocation<Endianness>;

/// The raw Mach-O nlist does not record a symbol kind. Its `n_sect` field names the section that
/// provides that information, so retain the section-derived facts beside each entry while parsing
/// the file. In particular, treating every dynamic `N_SECT` entry as a function would create PLT
/// entries for data exports, and treating none as a function would do the opposite for code.
#[derive(Debug, Copy, Clone, Default)]
struct SymbolSectionProperties {
    is_tls: bool,
    is_func: bool,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct SymtabEntry {
    raw: RawSymtabEntry,
    section_properties: SymbolSectionProperties,
}

impl std::ops::Deref for SymtabEntry {
    type Target = RawSymtabEntry;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl std::ops::DerefMut for SymtabEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.raw
    }
}

impl SymtabEntry {
    fn from_raw(raw: RawSymtabEntry, section_properties: SymbolSectionProperties) -> Self {
        Self {
            raw,
            section_properties,
        }
    }
}

/// A relocation after preserving its Mach-O ARM64 companion records at the format boundary.
///
/// Mach-O stores an addend in a separate record immediately before its `BRANCH26`, `PAGE21`, or
/// `PAGEOFF12` relocation. It represents an address difference with adjacent `SUBTRACTOR` and
/// `UNSIGNED` records, with the latter naming the minuend. Generic linker stages deliberately
/// receive only one relocation at a time, so preserve these format-specific relationships at the
/// Mach-O boundary rather than allowing either companion to look independent.
#[derive(Debug, Copy, Clone)]
pub(crate) struct NormalizedRelocation {
    pub(crate) info: object::macho::RelocationInfo,
    pub(crate) addend: i64,
    /// The subtrahend of an `ARM64_RELOC_SUBTRACTOR`/`ARM64_RELOC_UNSIGNED` pair. `info` is its
    /// paired unsigned relocation and therefore names the minuend.
    pub(crate) subtractor: Option<object::macho::RelocationInfo>,
}

pub(crate) struct PairedRelocations<'data> {
    relocations: Iter<'data, Relocation>,
}

pub(crate) fn paired_relocations(relocations: &[Relocation]) -> PairedRelocations<'_> {
    PairedRelocations {
        relocations: relocations.iter(),
    }
}

/// Normalized relocation records cached for each section of one Mach-O object.
///
/// Atom-level dead stripping loads one atom at a time, while Mach-O stores relocations for the
/// whole section. Re-parsing the full relocation list for every live atom turns a section with
/// many Rust functions into quadratic work. The input bytes cannot change while linking, so the
/// first atom can validate, normalize, and address-order the records for every later atom in the
/// same section. Each atom then selects its own relocation subrange with two binary searches.
#[derive(Default)]
pub(crate) struct MachORelocationCache {
    sections: Vec<Option<Vec<NormalizedRelocation>>>,
}

impl MachORelocationCache {
    fn cache(
        &mut self,
        section_index: object::SectionIndex,
        relocations: &[Relocation],
    ) -> Result {
        let section = section_index.0;
        if self.sections.len() <= section {
            self.sections.resize_with(section + 1, || None);
        }
        if self.sections[section].is_none() {
            let mut relocations = paired_relocations(relocations).collect::<Result<Vec<_>>>()?;
            // Mach-O commonly stores relocations in descending address order. Atom liveness is
            // keyed by source range, so address order turns the per-atom scan into a binary-range
            // lookup. Keep equal-address records stable: their graph effects are independent, but
            // their input order remains useful when diagnosing malformed producer output.
            relocations.sort_by_key(|relocation| relocation.info.r_address);
            self.sections[section] = Some(relocations);
        }
        Ok(())
    }

    fn for_section(&self, section_index: object::SectionIndex) -> &[NormalizedRelocation] {
        self.sections
            .get(section_index.0)
            .and_then(Option::as_deref)
            .expect("Mach-O relocation cache must be populated before use")
    }

    fn for_range(
        &self,
        section_index: object::SectionIndex,
        range: &Range<u64>,
    ) -> &[NormalizedRelocation] {
        let relocations = self.for_section(section_index);
        let start = relocations
            .partition_point(|relocation| u64::from(relocation.info.r_address) < range.start);
        let end = relocations
            .partition_point(|relocation| u64::from(relocation.info.r_address) < range.end);
        &relocations[start..end]
    }
}

impl<'data> Iterator for PairedRelocations<'data> {
    type Item = Result<NormalizedRelocation>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.relocations.next()?;
        let first_info = first.info(LE);
        match first_info.r_type {
            macho::ARM64_RELOC_ADDEND => Some((|| {
                ensure!(
                    !first_info.r_extern && !first_info.r_pcrel && first_info.r_length == 2,
                    "ARM64_RELOC_ADDEND requires r_extern=0, r_pcrel=0, and r_length=2"
                );

                let Some(primary) = self.relocations.next() else {
                    bail!("ARM64_RELOC_ADDEND must be immediately followed by ARM64_RELOC_BRANCH26, ARM64_RELOC_PAGE21, or ARM64_RELOC_PAGEOFF12");
                };
                let primary_info = primary.info(LE);
                ensure!(
                    first_info.r_address == primary_info.r_address,
                    "ARM64_RELOC_ADDEND at offset 0x{:x} must be paired with a relocation at the same offset, got 0x{:x}",
                    first_info.r_address,
                    primary_info.r_address
                );
                ensure!(
                    matches!(
                        primary_info.r_type,
                        macho::ARM64_RELOC_BRANCH26
                            | macho::ARM64_RELOC_PAGE21
                            | macho::ARM64_RELOC_PAGEOFF12
                    ),
                    "ARM64_RELOC_ADDEND must be immediately followed by ARM64_RELOC_BRANCH26, ARM64_RELOC_PAGE21, or ARM64_RELOC_PAGEOFF12, got {}",
                    primary_info.r_type
                );

                // `r_symbolnum` occupies a signed 24-bit field in the relocation record.
                let addend = i64::from(((first_info.r_symbolnum << 8) as i32) >> 8);
                Ok(NormalizedRelocation {
                    info: primary_info,
                    addend,
                    subtractor: None,
                })
            })()),
            macho::ARM64_RELOC_SUBTRACTOR => Some((|| {
                let Some(unsigned) = self.relocations.next() else {
                    bail!("ARM64_RELOC_SUBTRACTOR must be immediately followed by ARM64_RELOC_UNSIGNED");
                };
                let unsigned_info = unsigned.info(LE);
                ensure!(
                    first_info.r_address == unsigned_info.r_address,
                    "ARM64_RELOC_SUBTRACTOR at offset 0x{:x} must be paired with ARM64_RELOC_UNSIGNED at the same offset, got 0x{:x}",
                    first_info.r_address,
                    unsigned_info.r_address
                );
                ensure!(
                    unsigned_info.r_type == macho::ARM64_RELOC_UNSIGNED,
                    "ARM64_RELOC_SUBTRACTOR must be immediately followed by ARM64_RELOC_UNSIGNED, got {}",
                    unsigned_info.r_type
                );
                ensure!(
                    first_info.r_extern
                        && unsigned_info.r_extern
                        && !first_info.r_pcrel
                        && !unsigned_info.r_pcrel
                        && first_info.r_length == 3
                        && unsigned_info.r_length == 3,
                    "ARM64_RELOC_SUBTRACTOR/ARM64_RELOC_UNSIGNED requires external non-pcrel 64-bit relocation records"
                );
                Ok(NormalizedRelocation {
                    info: unsigned_info,
                    addend: 0,
                    subtractor: Some(first_info),
                })
            })()),
            _ => Some(Ok(NormalizedRelocation {
                info: first_info,
                addend: 0,
                subtractor: None,
            })),
        }
    }
}

/// The subset of an ARM64 DWARF `.eh_frame` FDE needed to complete an otherwise sparse
/// `__compact_unwind` record. Rust emits the personality and LSDA only here: its accompanying
/// `__LD,__compact_unwind` entry contains the function and encoding, but leaves both optional
/// target words zero. Offsets name relocation storage in the input `__eh_frame` section.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct EhFrameAugmentation {
    pub(crate) function_relocation_offset: usize,
    pub(crate) personality_relocation_offset: usize,
    pub(crate) lsda_relocation_offset: usize,
}

/// A parsed ARM64 CIE. `record_range` includes its DWARF length word and `personality` names
/// the four-byte `DW_EH_PE_pcrel | sdata4 | indirect` field when this is a `zPLR` CIE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EhFrameCie {
    pub(crate) record_range: Range<usize>,
    pub(crate) personality_relocation_offset: Option<usize>,
}

/// A parsed ARM64 FDE. The output writer copies the record, rewrites `cie_pointer`, and patches
/// the encoded pointer fields at these offsets using final image addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EhFrameFde {
    pub(crate) record_range: Range<usize>,
    pub(crate) cie_record_start: usize,
    pub(crate) function_relocation_offset: usize,
    pub(crate) lsda_relocation_offset: Option<usize>,
}

/// The only CIE/FDE grammar currently emitted by the ARM64 Mach-O Rust and Clang producers we
/// support: DWARF32 with `zR` or `zPLR`, with final pointers encoded as `pcrel` 64-bit values.
/// Keep raw ranges rather than decoded instructions so non-pointer DWARF programs survive byte
/// for byte while their address-bearing fields are rebuilt at the final output location.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct EhFrameRecords {
    pub(crate) cies: std::collections::BTreeMap<usize, EhFrameCie>,
    pub(crate) fdes: Vec<EhFrameFde>,
}

/// Read the standard DWARF32 ARM64 `zPLR` augmentation used by current Rust object files.
///
/// An `.eh_frame` section can contain many unrelated CIEs. CIEs without a personality/LSDA are
/// intentionally ignored. A CIE that explicitly advertises all of `zPLR`, but uses a different
/// pointer representation, fails clearly rather than silently producing a catchable panic with
/// the wrong unwind target. The supported encoding is `P=0x9b` (pcrel indirect sdata4), and
/// `L=R=0x10` (pcrel 64-bit), which is the arm64 Mach-O encoding produced by rustc/LLVM.
pub(crate) fn eh_frame_augmentations(data: &[u8]) -> Result<Vec<EhFrameAugmentation>> {
    let records = parse_eh_frame_records(data)?;
    Ok(records
        .fdes
        .iter()
        .filter_map(|fde| {
            let personality_relocation_offset = records
                .cies
                .get(&fde.cie_record_start)?
                .personality_relocation_offset?;
            Some(EhFrameAugmentation {
                function_relocation_offset: fde.function_relocation_offset,
                personality_relocation_offset,
                lsda_relocation_offset: fde.lsda_relocation_offset?,
            })
        })
        .collect())
}

/// Parse all records that may appear in the final table. A record with a CIE we do not understand
/// cannot safely be copied because its function/LSDA pointer locations are not self-describing;
/// reject it now rather than emitting an unwind table that fails only during process unwinding.
pub(crate) fn parse_eh_frame_records(data: &[u8]) -> Result<EhFrameRecords> {
    let mut records = EhFrameRecords::default();
    let mut record_start = 0usize;

    while record_start < data.len() {
        let length = eh_frame_u32(data, record_start)?;
        if length == 0 {
            // `.eh_frame` permits one terminator followed only by alignment padding.
            ensure!(
                data[record_start..].iter().all(|&byte| byte == 0),
                "nonzero bytes after Mach-O __eh_frame terminator"
            );
            break;
        }
        ensure!(
            length != u32::MAX,
            "unsupported 64-bit DWARF __eh_frame record length"
        );
        let record_end = record_start
            .checked_add(4)
            .and_then(|offset| offset.checked_add(length as usize))
            .context("truncated Mach-O __eh_frame record")?;
        ensure!(
            record_end <= data.len() && length >= 4,
            "truncated Mach-O __eh_frame record"
        );
        let cie_pointer = eh_frame_u32(data, record_start + 4)?;
        if cie_pointer == 0 {
            let cie = parse_eh_frame_cie(data, record_start, record_end)?;
            ensure!(
                records.cies.insert(record_start, cie).is_none(),
                "duplicate Mach-O __eh_frame CIE at offset 0x{record_start:x}"
            );
        } else {
            let cie_start = record_start
                .checked_add(4)
                .and_then(|offset| offset.checked_sub(cie_pointer as usize))
                .context("Mach-O __eh_frame FDE CIE pointer precedes the section")?;
            let cie = records.cies.get(&cie_start).with_context(|| {
                format!(
                    "Mach-O __eh_frame FDE at offset 0x{record_start:x} refers to unknown CIE at offset 0x{cie_start:x}"
                )
            })?;
            records
                .fdes
                .push(parse_eh_frame_fde(data, record_start, record_end, cie, cie_start)?);
        }
        record_start = record_end;
    }

    Ok(records)
}

fn parse_eh_frame_cie(
    data: &[u8],
    record_start: usize,
    record_end: usize,
) -> Result<EhFrameCie> {
    let mut offset = record_start + 8;
    let version = *data
        .get(offset)
        .context("truncated Mach-O __eh_frame CIE version")?;
    offset += 1;
    let augmentation_start = offset;
    while *data
        .get(offset)
        .context("unterminated Mach-O __eh_frame CIE augmentation string")?
        != 0
    {
        offset += 1;
        ensure!(
            offset < record_end,
            "unterminated Mach-O __eh_frame CIE augmentation string"
        );
    }
    let augmentation = &data[augmentation_start..offset];
    offset += 1;
    ensure!(
        matches!(augmentation, b"zR" | b"zPLR"),
        "unsupported Mach-O __eh_frame CIE augmentation {:?}: expected zR or zPLR",
        String::from_utf8_lossy(augmentation)
    );

    eh_frame_uleb(data, record_end, &mut offset)?; // code alignment factor
    eh_frame_sleb(data, record_end, &mut offset)?; // data alignment factor
    if version == 1 {
        offset = offset
            .checked_add(1)
            .context("Mach-O __eh_frame CIE return register overflows")?;
        ensure!(
            offset <= record_end,
            "truncated Mach-O __eh_frame CIE return register"
        );
    } else {
        eh_frame_uleb(data, record_end, &mut offset)?; // return-address register
    }

    let augmentation_size = usize::try_from(eh_frame_uleb(data, record_end, &mut offset)?)
        .context("Mach-O __eh_frame CIE augmentation size overflows usize")?;
    let augmentation_end = offset
        .checked_add(augmentation_size)
        .context("Mach-O __eh_frame CIE augmentation size overflows")?;
    ensure!(
        augmentation_end <= record_end,
        "truncated Mach-O __eh_frame CIE augmentation data"
    );

    let personality_relocation_offset = if augmentation == b"zR" {
        let fde_encoding = *data
            .get(offset)
            .context("truncated Mach-O __eh_frame zR FDE encoding")?;
        offset += 1;
        ensure!(
            fde_encoding == 0x10 && offset == augmentation_end,
            "unsupported Mach-O __eh_frame zR encoding: expected R=0x10"
        );
        None
    } else {
        let personality_encoding = *data
            .get(offset)
            .context("truncated Mach-O __eh_frame personality encoding")?;
        offset += 1;
        let pointer_offset = offset;
        offset = eh_frame_skip_encoded_value(data, augmentation_end, offset, personality_encoding)?;
        let lsda_encoding = *data
            .get(offset)
            .context("truncated Mach-O __eh_frame LSDA encoding")?;
        offset += 1;
        let fde_encoding = *data
            .get(offset)
            .context("truncated Mach-O __eh_frame FDE encoding")?;
        offset += 1;
        ensure!(
            personality_encoding == 0x9b
                && lsda_encoding == 0x10
                && fde_encoding == 0x10
                && offset == augmentation_end,
            "unsupported Mach-O __eh_frame zPLR encoding: expected P=0x9b, L=R=0x10"
        );
        Some(pointer_offset)
    };
    Ok(EhFrameCie {
        record_range: record_start..record_end,
        personality_relocation_offset,
    })
}

fn parse_eh_frame_fde(
    data: &[u8],
    record_start: usize,
    record_end: usize,
    cie: &EhFrameCie,
    cie_record_start: usize,
) -> Result<EhFrameFde> {
    // `R=0x10` means the initial location and range are each an eight-byte field. `L=0x10`
    // similarly makes the FDE augmentation's first payload an eight-byte LSDA address.
    let function_relocation_offset = record_start + 8;
    let augmentation_length_offset = function_relocation_offset
        .checked_add(16)
        .context("Mach-O __eh_frame FDE fields overflow")?;
    ensure!(
        augmentation_length_offset < record_end,
        "truncated Mach-O __eh_frame zPLR FDE"
    );
    let mut offset = augmentation_length_offset;
    let augmentation_size = usize::try_from(eh_frame_uleb(data, record_end, &mut offset)?)
        .context("Mach-O __eh_frame FDE augmentation size overflows usize")?;
    let lsda_relocation_offset = if cie.personality_relocation_offset.is_some() {
        ensure!(
            augmentation_size == size_of::<u64>(),
            "unsupported Mach-O __eh_frame zPLR FDE augmentation size {augmentation_size}: expected 8"
        );
        Some(offset)
    } else {
        ensure!(
            augmentation_size == 0,
            "unsupported Mach-O __eh_frame zR FDE augmentation size {augmentation_size}: expected 0"
        );
        None
    };
    let augmentation_end = offset
        .checked_add(augmentation_size)
        .context("Mach-O __eh_frame FDE augmentation size overflows")?;
    ensure!(
        augmentation_end <= record_end,
        "truncated Mach-O __eh_frame FDE augmentation data"
    );
    Ok(EhFrameFde {
        record_range: record_start..record_end,
        cie_record_start,
        function_relocation_offset,
        lsda_relocation_offset,
    })
}

fn eh_frame_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + size_of::<u32>())
        .context("truncated Mach-O __eh_frame u32")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn eh_frame_uleb(data: &[u8], end: usize, offset: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        ensure!(*offset < end, "truncated Mach-O __eh_frame ULEB128");
        let byte = data[*offset];
        *offset += 1;
        ensure!(shift < 64 || byte & 0x7f == 0, "Mach-O __eh_frame ULEB128 overflows");
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn eh_frame_sleb(data: &[u8], end: usize, offset: &mut usize) -> Result<i64> {
    let mut value = 0i64;
    let mut shift = 0u32;
    let byte = loop {
        ensure!(*offset < end, "truncated Mach-O __eh_frame SLEB128");
        let byte = data[*offset];
        *offset += 1;
        ensure!(shift < 64 || byte & 0x7f == 0, "Mach-O __eh_frame SLEB128 overflows");
        value |= i64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break byte;
        }
        shift += 7;
    };
    if shift < 63 && byte & 0x40 != 0 {
        value |= -1i64 << (shift + 7);
    }
    Ok(value)
}

fn eh_frame_skip_encoded_value(
    data: &[u8],
    end: usize,
    offset: usize,
    encoding: u8,
) -> Result<usize> {
    let size = match encoding & 0x0f {
        0x00 => size_of::<u64>(), // DW_EH_PE_absptr
        0x02 | 0x0a => 2,         // udata2 / sdata2
        0x03 | 0x0b => 4,         // udata4 / sdata4
        0x04 | 0x0c => 8,         // udata8 / sdata8
        0x01 => {
            let mut cursor = offset;
            eh_frame_uleb(data, end, &mut cursor)?;
            return Ok(cursor);
        }
        0x09 => {
            let mut cursor = offset;
            eh_frame_sleb(data, end, &mut cursor)?;
            return Ok(cursor);
        }
        _ => bail!("unsupported Mach-O __eh_frame pointer encoding 0x{encoding:02x}"),
    };
    let end_offset = offset
        .checked_add(size)
        .context("Mach-O __eh_frame encoded value overflows")?;
    ensure!(end_offset <= end, "truncated Mach-O __eh_frame encoded value");
    Ok(end_offset)
}

pub(crate) type FileHeader = object::macho::MachHeader64<Endianness>;
pub(crate) type SegmentCommand = object::macho::SegmentCommand64<Endianness>;
pub(crate) type SectionEntry = object::macho::Section64<Endianness>;
pub(crate) type EntryPointCommand = object::macho::EntryPointCommand<Endianness>;
pub(crate) type DylinkerCommand = object::macho::DylinkerCommand<Endianness>;
pub(crate) type DylibCommand = object::macho::DylibCommand<Endianness>;
pub(crate) type RpathCommand = object::macho::RpathCommand<Endianness>;
pub(crate) type CodeSignatureCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type DyldChainedFixupsCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type ChainedFixupsHeader = object::macho::DyldChainedFixupsHeader<Endianness>;
pub(crate) type ChainedStartsInSegment = object::macho::DyldChainedStartsInSegment<Endianness>;
pub(crate) type SymtabCommand = object::macho::SymtabCommand<Endianness>;
pub(crate) type BuildVersionCommand = object::macho::BuildVersionCommand<Endianness>;
pub(crate) type UuidCommand = object::macho::UuidCommand<Endianness>;

pub(crate) const CS_SECTION_ALIGNMENT_EXP: u8 = 4;
pub(crate) const CS_SECTION_ALIGNMENT: u64 = 2u64.pow(CS_SECTION_ALIGNMENT_EXP as u32);

pub(crate) const CS_BLOB_HEADERS_SIZE: u64 =
    (size_of::<macho::CsSuperBlob>() + size_of::<macho::CsBlobIndex>()) as u64;
pub(crate) const CS_CODE_DIRECTORY_SIZE: u64 = (size_of::<macho::CsCodeDirectoryV0>()
    + size_of::<macho::CsCodeDirectoryV1>()
    + size_of::<macho::CsCodeDirectoryV2>()
    + size_of::<macho::CsCodeDirectoryV3>()
    + size_of::<macho::CsCodeDirectoryV4>()) as u64;
pub(crate) const CS_HEADERS_SIZE: u64 = CS_BLOB_HEADERS_SIZE + CS_CODE_DIRECTORY_SIZE;
pub(crate) const CS_BLOCK_SIZE_EXP: u8 = 12;
pub(crate) const CS_BLOCK_SIZE: usize = 2usize.pow(CS_BLOCK_SIZE_EXP as u32);
// SHA-256 is being used
pub(crate) const CS_HASH_SIZE: u8 = 32;

pub(crate) fn code_signature_identifier(args: &MachOArgs) -> &[u8] {
    args.output()
        .file_name()
        .expect("File name should be present at this point")
        .as_encoded_bytes()
}

pub(crate) fn code_signature_padded_identifier_size(args: &MachOArgs) -> u64 {
    (code_signature_identifier(args).len() as u64 + 1).next_multiple_of(CS_SECTION_ALIGNMENT)
}

pub(crate) fn load_dylib_command_size(path: &[u8]) -> usize {
    (size_of::<DylibCommand>() + path.len() + 1).next_multiple_of(MACHO_COMMAND_ALIGNMENT)
}

pub(crate) fn rpath_command_size(path: &[u8]) -> usize {
    (size_of::<RpathCommand>() + path.len() + 1).next_multiple_of(MACHO_COMMAND_ALIGNMENT)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct SegmentName([u8; 16]);

impl SegmentName {
    pub(crate) const PAGEZERO: Self = Self::from_bytes(b"__PAGEZERO");
    pub(crate) const TEXT: Self = Self::from_bytes(b"__TEXT");
    pub(crate) const DATA: Self = Self::from_bytes(b"__DATA");
    pub(crate) const DATA_CONST: Self = Self::from_bytes(b"__DATA_CONST");
    pub(crate) const LINKEDIT: Self = Self::from_bytes(b"__LINKEDIT");
    /// `__LD` contains object-file linker metadata such as `__compact_unwind`. It is not a final
    /// image segment, but compact unwind must be inspected before normal debug-section exclusion.
    pub(crate) const LD: Self = Self::from_bytes(b"__LD");
    pub(crate) const LLVM: Self = Self::from_bytes(b"__LLVM");
    pub(crate) const DWARF: Self = Self::from_bytes(b"__DWARF");

    pub(crate) const fn into_bytes(self) -> [u8; 16] {
        self.0
    }

    const fn from_bytes(name: &[u8]) -> Self {
        assert!(name.len() <= 16);
        let mut bytes = [0; 16];
        bytes.split_at_mut(name.len()).0.copy_from_slice(name);
        Self(bytes)
    }

    fn is_writable(self) -> bool {
        !matches!(
            self,
            Self::PAGEZERO | Self::TEXT | Self::DATA_CONST | Self::LINKEDIT | Self::DWARF | Self::LLVM
        )
    }
}

impl std::fmt::Display for SegmentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.0);
        write!(f, "{}", name.trim_end_matches('\0'))
    }
}

#[derive(Debug, Default)]
pub(crate) struct LayoutExt<'data> {
    /// Imported symbols, sorted by their runtime-bound pointer slot.
    pub(crate) imported_symbols: Vec<ImportedSymbolWithResolution>,
    /// Modern Objective-C selector-dispatch stubs, in their allocated output order.
    pub(crate) objc_message_stubs: Vec<ObjcMessageStub<'data>>,
    /// Every synthetic input undefined symbol is remapped to the unique, lexically ordered
    /// selector stub that owns its spelling.
    pub(crate) objc_message_stub_indexes: BTreeMap<ObjcMessageSymbol, usize>,
}

#[derive(Debug, Default)]
pub(crate) struct FinaliseSizesExt<'data> {
    imported_libraries: Vec<FileId>,
    imported_symbols: Vec<SymbolId>,
    /// Reserved upper bound for the post-layout `__unwind_info` serialization. The epilogue owns
    /// this synthetic data, so it also advances this part during final address assignment.
    unwind_info_size: u64,
    /// Reserved upper bound for selected CIE/FDE records and their one final terminator.
    eh_frame_size: u64,
    objc_message_stubs: Vec<ObjcMessageStub<'data>>,
    objc_message_stub_indexes: BTreeMap<ObjcMessageSymbol, usize>,
}

/// One Clang-generated `_objc_msgSend$selector` reference whose ARM64 ABI requires linker
/// synthesis. `message_symbol` remains the input symbol index so relocation writing can replace
/// exactly that branch; `selector_symbol` names the corresponding string in `__objc_methname`.
/// Keeping both input identities avoids conflating equal selector spellings from different
/// objects before string merging has assigned their final address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ObjcMessageSymbol {
    pub(crate) file_id: FileId,
    pub(crate) symbol: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjcMessageStub<'data> {
    /// Selector spelling, retained only so final output order matches ld64's lexical order.
    pub(crate) selector: &'data [u8],
    /// One input special symbol that resolves to the shared `_objc_msgSend` GOT slot.
    pub(crate) message_symbol: ObjcMessageSymbol,
    /// One input method-name symbol whose merged output address backs the synthetic selref.
    pub(crate) selector_symbol: ObjcMessageSymbol,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PreludeLayoutExt {
    pub(crate) imported_library_file_ids: Vec<FileId>,
    pub(crate) load_dylib_command_sizes: Vec<usize>,
    pub(crate) load_command_count: usize,
}

#[derive(derive_more::Debug, Clone, Copy)]
pub(crate) struct ImportedSymbolWithResolution {
    pub(crate) symbol_id: SymbolId,
    pub(crate) binding: ImportedSymbolBinding,
    /// dyld's `weak_import` bit is a property of every relocation that names this import. A
    /// single strong use upgrades a mixed import to ordinary binding semantics.
    pub(crate) weak_import: bool,
}

/// Storage which dyld binds for an imported symbol.
///
/// A TLVP slot deliberately is not a `__got` entry. It stores a pointer to the exporting dylib's
/// TLV descriptor, which its bootstrap function then uses to find the caller's current-thread
/// storage. Keeping this distinction through layout and writing prevents the local-TLVP rewrite
/// from turning an imported descriptor load into an address of the wrong storage cell.
#[derive(derive_more::Debug, Clone, Copy)]
pub(crate) enum ImportedSymbolBinding {
    Got {
        got_address: NonZeroU64,
        plt_address: Option<NonZeroU64>,
    },
    Tlvp {
        tlvp_address: NonZeroU64,
    },
}

impl ImportedSymbolBinding {
    pub(crate) fn address(self) -> NonZeroU64 {
        match self {
            Self::Got { got_address, .. } => got_address,
            Self::Tlvp { tlvp_address } => tlvp_address,
        }
    }
}

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data>,
    /// nlists enriched with the section facts that Mach-O stores outside the nlist itself.
    #[debug(skip)]
    symbol_entries: Vec<SymtabEntry>,
    #[allow(unused)]
    pub(crate) flags: object::macho::FileFlags,
    kind: ObjectKind<'data>,
}

/// The identity and ABI versions that a dynamic input contributes to its consumer.
///
/// Mach-O resolves dynamic libraries by the `LC_ID_DYLIB` path rather than the path by which the
/// linker happened to open the file. The current and compatibility versions belong to that same
/// identity and must therefore stay with it until `LC_LOAD_DYLIB` is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DylibMetadata<'data> {
    pub(crate) install_name: &'data [u8],
    pub(crate) versions: DylibVersions,
}

/// The two version fields preserved from a dynamic library or represented by a TBD document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DylibVersions {
    pub(crate) current: macho::Version,
    pub(crate) compatibility: macho::Version,
}

impl DylibVersions {
    /// `ld64` uses 1.0.0 for both fields when a TBD omits a version field.
    pub(crate) fn tbd(current: &str, compatibility: &str) -> Result<Self> {
        Ok(Self {
            current: if current.is_empty() {
                macho::Version::new(1, 0, 0)
            } else {
                parse_dylib_version(current)?
            },
            compatibility: if compatibility.is_empty() {
                macho::Version::new(1, 0, 0)
            } else {
                parse_dylib_version(compatibility)?
            },
        })
    }

    /// A newly linked dylib has the producer defaults that `ld64` writes in its LC_ID_DYLIB.
    pub(crate) fn output_default() -> Self {
        Self {
            current: macho::Version::new(1, 0, 0),
            compatibility: macho::Version::new(1, 0, 0),
        }
    }
}

fn parse_dylib_version(value: &str) -> Result<macho::Version> {
    let mut components = value.split('.');
    let major = components
        .next()
        .ok_or_else(|| error!("dylib version must not be empty"))?
        .parse()
        .with_context(|| format!("invalid dylib major version `{value}`"))?;
    let minor = components
        .next()
        .map(str::parse)
        .transpose()
        .with_context(|| format!("invalid dylib minor version `{value}`"))?
        .unwrap_or(0);
    let update = components
        .next()
        .map(str::parse)
        .transpose()
        .with_context(|| format!("invalid dylib update version `{value}`"))?
        .unwrap_or(0);
    ensure!(
        components.next().is_none(),
        "dylib version `{value}` has more than three components"
    );

    Ok(macho::Version::new(major, minor, update))
}

impl<'data> File<'data> {
    /// Returns the exact input spelling for a symbol. Most Mach-O names are passed directly to
    /// the symbol database, but Objective-C selector dispatch keeps a synthetic input spelling
    /// while resolving its dynamic target under a different name.
    pub(crate) fn raw_symbol_name(&self, symbol_index: SymbolIndex) -> Result<&'data [u8]> {
        self.symbol_name(self.symbol(symbol_index)?)
    }

    fn dylib_metadata(&self) -> Option<DylibMetadata<'data>> {
        match self.kind {
            ObjectKind::Regular(_) => None,
            ObjectKind::Dylib(metadata) => Some(metadata),
        }
    }

    /// Returns the target name encoded by an `N_INDR` alias. Unlike an ordinary nlist name,
    /// `n_value` is a string-table offset for this one record type.
    pub(crate) fn indirect_symbol_target(&self, symbol: &SymtabEntry) -> Result<&'data [u8]> {
        debug_assert_eq!(symbol.n_type.typ(), N_INDR);
        let offset = u32::try_from(symbol.n_value.get(LE))
            .map_err(|_| error!("Mach-O indirect symbol target offset exceeds u32"))?;
        self.symbols
            .strings()
            .get(offset)
            .map_err(|_| error!("Mach-O indirect symbol target is outside the string table"))
    }
}

/// A source-level function entry that `dsymutil` can relocate from a supported input object to
/// the linked image. The length deliberately stays in input coordinates: that is the `N_FUN`
/// terminator convention used by Apple's debug-map reader.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DsymutilDebugMapFunction<'data> {
    pub(crate) name: &'data [u8],
    pub(crate) section_index: object::SectionIndex,
    pub(crate) input_offset: u64,
    pub(crate) input_size: u64,
}

/// The deliberately small Mach-O debug-map slice that we can prove for loose C and Rust objects.
///
/// Final Mach-O executables do not carry their input `__DWARF` sections. Instead, `dsymutil`
/// reads those still-available objects through `N_OSO` and uses `N_FUN` entries to relocate CUs
/// into a dSYM. Keep this separate from output-section handling so debug relocations never make
/// dead code live.
#[derive(Debug)]
pub(crate) struct DsymutilDebugMap<'data> {
    pub(crate) source_path: Vec<u8>,
    pub(crate) functions: Vec<DsymutilDebugMapFunction<'data>>,
}

/// Mach-O permits atom-level dead stripping only when the input file opts into
/// `MH_SUBSECTIONS_VIA_SYMBOLS`. Keep the atom's input start in the GC work item: all aliases at
/// the same address intentionally share one unit, while normal inputs retain section granularity.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MachOGcUnit {
    Section(object::SectionIndex),
    Atom {
        section_index: object::SectionIndex,
        start: u64,
    },
}

#[derive(Debug)]
enum ObjectKind<'data> {
    Regular(RegularObject<'data>),
    Dylib(DylibMetadata<'data>),
}

#[derive(derive_more::Debug)]
struct RegularObject<'data> {
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data>,
    /// Atom boundaries are a property of the input file, not a liveness query. Rust's standard
    /// library has enough symbols that rebuilding and then coalescing this list for every graph
    /// edge turns a valid proc-macro link quadratic.
    atom_starts: Vec<Vec<u64>>,
    /// Public definitions, grouped by input section and sorted by their input offsets.
    ///
    /// `-dead_strip` loads Mach-O input one atom at a time. Exporting an atom used to scan the
    /// complete input symbol table, which made a Rust object with thousands of atoms repeatedly
    /// revisit the same local and undefined symbols. Keep the parse-time index separate from
    /// `atom_starts`: a relocation can coalesce atom boundaries, while this index still selects
    /// all public symbols in the live input range.
    exported_symbols_by_section: Vec<Vec<ExportedSymbol>>,
}

/// A public, section-defined Mach-O symbol eligible for executable export after dead stripping.
/// The symbol index remains in input order; the containing vector is sorted only to select a
/// live atom's input range without scanning the object's complete symbol table.
#[derive(Debug, Clone, Copy)]
struct ExportedSymbol {
    input_offset: u64,
    symbol_index: SymbolIndex,
}

fn exported_symbols_in_range<'symbols>(
    exported_symbols: &'symbols [ExportedSymbol],
    range: Option<&Range<u64>>,
) -> &'symbols [ExportedSymbol] {
    let Some(range) = range else {
        return exported_symbols;
    };
    let start = exported_symbols.partition_point(|symbol| symbol.input_offset < range.start);
    let end = exported_symbols.partition_point(|symbol| symbol.input_offset < range.end);
    &exported_symbols[start..end]
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = MachO;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> Result<Self> {
        let header = macho::MachHeader64::<object::Endianness>::parse(input, 0)?;
        let mut commands = header.load_commands(LE, input, 0)?;

        let mut symbols = None;
        let mut sections = None;
        let mut indirect_symbols = None;
        let mut symbol_section_properties = Vec::new();
        let mut dylib_metadata = None;

        while let Some(command) = commands.next()? {
            if let Some(symtab_command) = command.symtab()? {
                ensure!(symbols.is_none(), "At most one symtab command expected");
                symbols = Some(symtab_command.symbols::<macho::MachHeader64<_>, _>(LE, input)?);
            } else if let Some(dysymtab_command) = command.dysymtab()? {
                ensure!(
                    indirect_symbols.is_none(),
                    "At most one dysymtab command expected"
                );
                indirect_symbols = Some(dysymtab_command.indirect_symbols(LE, input)?);
            } else if is_dynamic && command.cmd() == macho::LC_ID_DYLIB {
                ensure!(
                    dylib_metadata.is_none(),
                    "At most one LC_ID_DYLIB command expected"
                );
                let dylib_command: &DylibCommand = command.data()?;
                dylib_metadata = Some(DylibMetadata {
                    install_name: command.string(LE, dylib_command.dylib.name)?,
                    versions: DylibVersions {
                        current: dylib_command.dylib.current_version.get(LE),
                        compatibility: dylib_command.dylib.compatibility_version.get(LE),
                    },
                });
            } else if let Some((segment_command, segment_data)) = command.segment_64()? {
                let section_list = segment_command.sections(LE, segment_data)?;
                symbol_section_properties.extend(
                    section_list
                        .iter()
                        .map(symbol_section_properties_from_section),
                );
                if !is_dynamic {
                    ensure!(sections.is_none(), "At most one segment command expected");
                    sections = Some(section_list);
                }
            }
        }

        let symbols = symbols.ok_or("Missing symbol table")?;
        if !is_dynamic {
            validate_indirect_symbol_sections(
                sections.as_deref().ok_or("Missing segment command")?,
                symbols.len(),
                indirect_symbols,
            )?;
        }
        let symbol_entries = symbols
            .iter()
            .map(|raw| {
                let properties = if !raw.n_type.is_stab()
                    && raw.n_type.typ() == N_SECT
                    && raw.n_sect != 0
                {
                    *symbol_section_properties
                        .get(usize::from(raw.n_sect - 1))
                        .context("Mach-O symbol section index is out of range")?
                } else {
                    SymbolSectionProperties::default()
                };
                Ok(SymtabEntry::from_raw(*raw, properties))
            })
            .collect::<Result<Vec<_>>>()?;

        let kind = if is_dynamic {
            ObjectKind::Dylib(dylib_metadata.ok_or("Missing LC_ID_DYLIB command")?)
        } else {
            ObjectKind::Regular(RegularObject {
                sections: sections.ok_or("Missing segment command")?,
                atom_starts: Vec::new(),
                exported_symbols_by_section: Vec::new(),
            })
        };

        let mut file = File {
            data: input,
            symbols,
            symbol_entries,
            flags: header.flags(LE),
            kind,
        };
        if !file.is_dynamic() {
            let exported_symbols_by_section = file.compute_exported_symbols_by_section()?;
            let ObjectKind::Regular(regular) = &mut file.kind else {
                unreachable!("only regular Mach-O objects may have public export symbols");
            };
            regular.exported_symbols_by_section = exported_symbols_by_section;
        }
        if file.uses_subsections_via_symbols() {
            let atom_starts = file.compute_atom_starts()?;
            let ObjectKind::Regular(regular) = &mut file.kind else {
                unreachable!("only regular Mach-O objects may opt into subsection atoms");
            };
            regular.atom_starts = atom_starts;
        }
        Ok(file)
    }

    fn parse(input: &crate::input_data::InputBytes<'data>, _args: &MachOArgs) -> Result<Self> {
        // TODO
        Self::parse_bytes(input.data, input.kind == FileKind::MachODylib)
    }

    fn is_dynamic(&self) -> bool {
        matches!(self.kind, ObjectKind::Dylib(_))
    }

    fn num_symbols(&self) -> usize {
        self.symbol_entries.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &SymtabEntry> {
        self.symbol_entries.iter()
    }

    fn symbol(&self, index: object::SymbolIndex) -> Result<&SymtabEntry> {
        Ok(self
            .symbol_entries
            .get(index.0)
            .context("Mach-O symbol index out of range")?)
    }

    fn section_size(&self, header: &SectionHeader) -> Result<u64> {
        Ok(header.size.get(LE))
    }

    fn symbol_name(&self, symbol: &SymtabEntry) -> Result<&'data [u8]> {
        Ok(symbol.name(LE, self.symbols.strings())?)
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &SymtabEntry,
        section_index: object::SectionIndex,
    ) -> Result<u64> {
        let section = self.section(section_index)?;
        // On Mach-O the symbol value is the global offset, not a relative to the start of a
        // section.
        symbol
            .n_value
            .get(LE)
            .checked_sub(section.addr.get(LE))
            .ok_or_else(|| error!("Mach-O symbol value is before its section address"))
    }

    fn num_sections(&self) -> usize {
        self.sections().len()
    }

    fn section_iter<'a>(&'a self) -> Iter<'a, SectionHeader> {
        self.sections().iter()
    }

    fn enumerate_sections(&self) -> impl Iterator<Item = (object::SectionIndex, &SectionHeader)> {
        self.sections()
            .iter()
            .enumerate()
            .map(|(i, section)| (object::SectionIndex(i), section))
    }

    fn section(&self, index: object::SectionIndex) -> Result<&SectionHeader> {
        self.sections()
            .get(index.0)
            .ok_or(error!("section index out of range"))
    }

    fn section_by_name(&self, name: &str) -> Option<(object::SectionIndex, &SectionHeader)> {
        self.enumerate_sections()
            .find(|(_, section)| section.name() == name.as_bytes())
    }

    fn symbol_section(
        &self,
        symbol: &SymtabEntry,
        _index: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>> {
        if symbol.n_type.typ() == N_SECT && symbol.n_sect != 0 {
            // The index is one-based, NO_SECT == 0, marks a missing section for the symbol.
            Ok(Some(object::SectionIndex(usize::from(symbol.n_sect - 1))))
        } else {
            Ok(None)
        }
    }

    fn symbol_versions(&self) -> &[()] {
        // Mach-O has no ELF-style per-symbol version table.
        &[]
    }

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        file: &mut layout::DynamicLayoutState<'data, MachO>,
    ) -> Result {
        file.format_specific
            .imported_symbols
            .push(file.symbol_id_range.input_to_id(symbol_index));
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut DynamicLayoutStateExt,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut NonAddressableIndexes,
        _counts: &mut (),
        _state: &mut DynamicLayoutStateExt,
    ) -> Result {
        Ok(())
    }

    fn section_name(&self, index: object::SectionIndex) -> Result<&'data [u8]> {
        let section = self
            .sections()
            .get(index.0)
            .ok_or(error!("section index out of range"))?;
        Ok(section.name())
    }

    fn raw_section_data(&self, section: &SectionHeader) -> Result<&'data [u8]> {
        section
            .data(LE, self.data, section.offset(LE).into())
            .map_err(|_| error!("cannot get section data"))
    }

    fn section_data(
        &self,
        section: &SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> Result<&'data [u8]> {
        let data = self.raw_section_data(section)?;
        loaded_metrics
            .loaded_bytes
            .fetch_add(data.len(), Ordering::Relaxed);
        Ok(data)
    }

    fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> Result {
        let data = section
            .data(LE, self.data, section.offset(LE).into())
            .map_err(|_e| error!("cannot get section data"))?;
        copy_section_data(data, out);

        Ok(())
    }

    fn section_data_cow(&self, section: &SectionHeader) -> Result<std::borrow::Cow<'data, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(self.raw_section_data(section)?))
    }

    fn section_alignment(&self, section: &SectionHeader) -> Result<u64> {
        Ok(minimum_section_alignment(
            section.flags.get(LE).typ(),
            2u64.pow(section.align(LE)),
        ))
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        _relocations: &(),
    ) -> Result<RelocationList<'data>> {
        Ok(RelocationList {
            relocations: self
                .sections()
                .get(index.0)
                .ok_or(error!("section index out of range"))?
                .relocations(LE, self.data)?,
        })
    }

    fn parse_relocations(&self) -> Result<()> {
        Ok(())
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        self.section_name(index).map_or_else(
            |_| format!("<index {}>", index.0).into(),
            String::from_utf8_lossy,
        )
    }

    fn dynamic_tag_values(&self) -> Option<DynamicTagValues<'data>> {
        match self.kind {
            ObjectKind::Regular(_) => None,
            ObjectKind::Dylib(metadata) => Some(DynamicTagValues { metadata }),
        }
    }

    fn get_version_names(&self) -> Result<()> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &SymtabEntry,
        _local_index: usize,
        _version_names: &(),
    ) -> Result<RawSymbolName<'data>> {
        let name = self.symbol_name(symbol)?;
        // Clang's modern ARM64 Objective-C ABI represents a selector send as a synthetic
        // undefined `_objc_msgSend$selector` name. ld64 resolves the actual imported function
        // as `_objc_msgSend` and later creates a selector-loading veneer for the original input
        // symbol. Keep that synthetic spelling for the Mach-O writer's exact relocation lookup,
        // but canonicalise symbol resolution to the real libobjc entry point.
        Ok(RawSymbolName {
            name: objc_message_selector(name).map_or(name, |_| b"_objc_msgSend"),
        })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool {
        // Undefined nlists in a Mach-O dylib are imports for dyld, not obligations of this link.
        // The static linker validates undefined references from regular objects while it resolves
        // their relocations. Recursively auditing the loaded dylib's dependency graph here would
        // reject valid two-level-namespace inputs that the dynamic loader is responsible for.
        false
    }

    fn verneed_table(&self) -> Result<VerneedTable<'data>> {
        Ok(VerneedTable { _phantom: &[] })
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut MachORelocationCache,
        _section_index: object::SectionIndex,
    ) -> Result {
        // GNU property notes are ELF metadata. Mach-O has neither their section type nor an
        // equivalent object-level property table.
        Ok(())
    }

    fn dynamic_tags(&self) -> Result<&'data [()]> {
        // Mach-O load commands are parsed directly; there is no ELF dynamic-tag table.
        Ok(&[])
    }
}

/// Returns whether a section is linker metadata or debug data rather than input to a
/// loadable output segment. Mach-O does not have an `SHF_ALLOC` equivalent; this is
/// defined by the section's attributes and conventional segment role instead.
fn is_non_alloc_section(flags: SectionFlags, segment_name: &[u8]) -> bool {
    (flags.intersects(S_ATTR_DEBUG) && SegmentName::from_bytes(segment_name) != SegmentName::LD)
        || matches!(
            SegmentName::from_bytes(segment_name),
            SegmentName::PAGEZERO
                | SegmentName::LINKEDIT
                | SegmentName::LLVM
                | SegmentName::DWARF
        )
}

fn is_tls_section_type(section_type: macho::SectionType) -> bool {
    matches!(section_type, S_THREAD_LOCAL_REGULAR | S_THREAD_LOCAL_ZEROFILL)
}

/// Returns the name of a section type whose entries are interpreted through `LC_DYSYMTAB`'s
/// indirect-symbol table rather than through ordinary object-file relocations.
///
/// Clang's `MH_OBJECT` output does not use these types: it leaves branch, GOT, and TLVP intent in
/// relocations for the static linker. These types describe the already-linked dynamic-loader
/// tables in a final image. Wild emits the equivalent final ARM64 tables from relocations using
/// chained fixups, and intentionally does not write `LC_DYSYMTAB`. Copying one of these input
/// sections would therefore leave its slot/stub addresses and dynamic bindings unrepresented.
fn indirect_symbol_section_type_name(section_type: macho::SectionType) -> Option<&'static str> {
    Some(match section_type {
        macho::S_NON_LAZY_SYMBOL_POINTERS => "S_NON_LAZY_SYMBOL_POINTERS",
        macho::S_LAZY_SYMBOL_POINTERS => "S_LAZY_SYMBOL_POINTERS",
        macho::S_SYMBOL_STUBS => "S_SYMBOL_STUBS",
        macho::S_LAZY_DYLIB_SYMBOL_POINTERS => "S_LAZY_DYLIB_SYMBOL_POINTERS",
        macho::S_THREAD_LOCAL_VARIABLE_POINTERS => "S_THREAD_LOCAL_VARIABLE_POINTERS",
        _ => return None,
    })
}

fn indirect_symbol_section_display_name(section: &SectionHeader) -> String {
    format!(
        "{},{}",
        String::from_utf8_lossy(section.segment_name()),
        String::from_utf8_lossy(section.name())
    )
}

/// Validates, then rejects, pre-bound dynamic-loader sections in a regular object input.
///
/// The validation makes a corrupt `LC_DYSYMTAB` a normal input diagnostic rather than hiding it
/// behind the unsupported-feature diagnostic. Once the table is structurally valid, rejection is
/// deliberate: the writer has no ABI-correct way to preserve its pre-bound entries without also
/// serialising `LC_DYSYMTAB`, legacy lazy-bind machinery, and architecture-specific stub rewrites.
fn validate_indirect_symbol_sections(
    sections: &[SectionHeader],
    symbol_count: usize,
    indirect_symbols: Option<&[object::endian::U32<Endianness, macho::IndirectSymbol>]>,
) -> Result {
    for section in sections {
        let section_type = section.flags.get(LE).typ();
        let Some(section_type_name) = indirect_symbol_section_type_name(section_type) else {
            continue;
        };
        let section_name = indirect_symbol_section_display_name(section);
        let section_size = section.size.get(LE);
        let entry_size = if section_type == macho::S_SYMBOL_STUBS {
            u64::from(section.reserved2.get(LE))
        } else {
            GOT_ENTRY_SIZE
        };
        ensure!(
            entry_size != 0,
            "Mach-O {section_type_name} section {section_name} has a zero stub entry size"
        );
        ensure!(
            section_size % entry_size == 0,
            "Mach-O {section_type_name} section {section_name} has size {section_size} that is not a multiple of entry size {entry_size}"
        );
        let entry_count = usize::try_from(section_size / entry_size).with_context(|| {
            format!(
                "Mach-O {section_type_name} section {section_name} has too many indirect-symbol entries"
            )
        })?;
        if entry_count != 0 {
            let indirect_symbols = indirect_symbols.with_context(|| {
                format!(
                    "Mach-O {section_type_name} section {section_name} requires LC_DYSYMTAB indirect-symbol entries"
                )
            })?;
            let first_index = usize::try_from(section.reserved1.get(LE)).with_context(|| {
                format!(
                    "Mach-O {section_type_name} section {section_name} has an indirect-symbol index that does not fit usize"
                )
            })?;
            let end_index = first_index.checked_add(entry_count).with_context(|| {
                format!(
                    "Mach-O {section_type_name} section {section_name} indirect-symbol range overflows"
                )
            })?;
            ensure!(
                end_index <= indirect_symbols.len(),
                "Mach-O {section_type_name} section {section_name} requires indirect-symbol entries {first_index}..{end_index}, but LC_DYSYMTAB has only {}",
                indirect_symbols.len()
            );
            for (entry_offset, indirect_symbol) in indirect_symbols[first_index..end_index]
                .iter()
                .enumerate()
            {
                let Some(symbol_index) = indirect_symbol.get(LE).index() else {
                    continue;
                };
                ensure!(
                    usize::try_from(symbol_index).is_ok_and(|index| index < symbol_count),
                    "Mach-O {section_type_name} section {section_name} indirect-symbol entry {} refers to symbol {symbol_index}, but the symbol table has only {symbol_count} entries",
                    first_index + entry_offset
                );
            }
        }

        bail!(
            "Mach-O input section {section_name} uses {section_type_name}, an already-linked indirect-symbol table format that Wild cannot represent in chained-fixup output; rebuild or supply the original relocatable object"
        );
    }
    Ok(())
}

fn symbol_section_properties_from_section(section: &SectionHeader) -> SymbolSectionProperties {
    let flags = section.flags.get(LE);
    SymbolSectionProperties {
        is_tls: is_tls_section_type(flags.typ()),
        is_func: flags.intersects(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS),
    }
}

/// `S_THREAD_LOCAL_VARIABLES` holds three pointer-sized fields (`__tlv_bootstrap`, a key, and
/// the initial-data address). Assemblers commonly report alignment 1 for the section, but the
/// runtime treats the descriptor as a word-aligned structure. Preserve a stronger producer
/// alignment and enforce the ABI's minimum when assigning the output section address.
fn minimum_section_alignment(section_type: macho::SectionType, input_alignment: u64) -> u64 {
    if section_type == S_THREAD_LOCAL_VARIABLES {
        input_alignment.max(8)
    } else {
        input_alignment
    }
}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        !is_non_alloc_section(self.flags.get(LE), self.segment_name())
    }

    fn is_writable(&self) -> bool {
        SegmentName::from_bytes(self.segment_name()).is_writable()
    }

    fn is_executable(&self) -> bool {
        self.flags
            .get(LE)
            .intersects(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
    }

    fn is_tls(&self) -> bool {
        is_tls_section_type(self.flags.get(LE).typ())
    }

    fn is_merge_section(&self) -> bool {
        self.flags.get(LE).typ() == S_CSTRING_LITERALS
    }

    fn is_strings(&self) -> bool {
        self.flags.get(LE).typ() == S_CSTRING_LITERALS
    }

    fn should_retain(&self) -> bool {
        let flags = self.flags.get(LE);
        // Dyld discovers constructor pointers from `__mod_init_func`, rather than through a
        // symbol reference from an ordinary live atom. Keep the pointer section as a GC root so
        // its relocations retain exactly the referenced constructor atoms under `-dead_strip`.
        flags.contains(S_ATTR_NO_DEAD_STRIP) || flags.typ() == macho::S_MOD_INIT_FUNC_POINTERS
    }

    fn should_exclude(&self) -> bool {
        (self.flags.get(LE).intersects(S_ATTR_DEBUG)
            && SegmentName::from_bytes(self.segment_name()) != SegmentName::LD)
            || matches!(
                SegmentName::from_bytes(self.segment_name()),
                SegmentName::PAGEZERO
                    | SegmentName::LINKEDIT
                    | SegmentName::LLVM
                    | SegmentName::DWARF
            )
    }

    fn is_group(&self) -> bool {
        // Mach-O has no section-group analogue. Coalescing is a symbol/linkage
        // property, not an ELF-style COMDAT section group.
        false
    }

    fn is_note(&self) -> bool {
        false
    }

    fn is_prog_bits(&self) -> bool {
        // Mach-O records no generic PROGBITS type. Its zero-fill section types are
        // the only section types that have no bytes in the input file.
        !self.is_no_bits()
    }

    fn is_no_bits(&self) -> bool {
        matches!(
            self.flags.get(LE).typ(),
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }
}

impl platform::SectionType for macho::SectionType {
    fn is_rela(&self) -> bool {
        // Relocations live outside Mach-O sections, so there is no RELA section
        // type to report through this ELF-shaped generic hook.
        false
    }

    fn is_rel(&self) -> bool {
        false
    }

    fn is_symtab(&self) -> bool {
        false
    }

    fn is_strtab(&self) -> bool {
        false
    }
}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        true
    }
}

// Documentation link for Nlist64 type: https://leopard-adc.pepas.com/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html
impl platform::Symbol for SymtabEntry {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // Mach-O stores tentative definitions as `N_UNDF | N_EXT` symbols whose nonzero value is
        // their size. `n_desc[11:8]` optionally carries the requested alignment exponent. This is
        // a definition to generic resolution, despite its raw N_UNDF object representation.
        if self.n_type.typ() != N_UNDF
            || !self.n_type.contains(N_EXT)
            || self.n_sect != 0
            || self.n_value.get(LE) == 0
        {
            return None;
        }

        let requested_exponent = (self.n_desc.get(LE).0 >> 8) & 0x0f;
        let natural_exponent = 64 - (self.n_value.get(LE) - 1).leading_zeros();
        // ld64 accepts the on-disk four-bit exponent but caps __common at the default 16 KiB
        // segment alignment. Keep the allocated part and its emitted section header consistent.
        let alignment_exponent = if requested_exponent == 0 {
            natural_exponent
        } else {
            u32::from(requested_exponent)
        }
        .min(15)
        .min(u32::from(MACHO_PAGE_ALIGNMENT.exponent));
        let alignment = Alignment::from_exponent(alignment_exponent).ok()?;
        let size = self
            .n_value
            .get(LE)
            .checked_add(alignment.mask())?
            & !alignment.mask();

        Some(platform::CommonSymbol {
            size,
            part_id: output_section_id::COMMON.part_id_with_alignment::<MachO>(alignment),
        })
    }

    fn is_undefined(&self) -> bool {
        Nlist::is_undefined(&self.raw) && self.as_common().is_none()
    }

    fn is_local(&self) -> bool {
        !self.n_type.contains(N_EXT)
    }

    fn is_absolute(&self) -> bool {
        self.n_type.typ() == N_ABS
    }

    fn is_weak(&self) -> bool {
        self.n_desc.get(LE).contains(N_WEAK_DEF)
    }

    fn is_weak_reference(&self) -> bool {
        self.n_type.typ() == N_UNDF && self.n_desc.get(LE).contains(N_WEAK_REF)
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        if self.n_type.contains(N_PEXT) {
            Visibility::Hidden
        } else {
            Visibility::Default
        }
    }

    fn value(&self) -> u64 {
        self.n_value.get(LE)
    }

    fn size(&self) -> u64 {
        // `N_UNDF` commons carry their allocation size in `n_value`; ordinary Mach-O nlists do
        // not encode a size, but returning the value is the only information generic common
        // selection needs and makes the largest tentative definition win.
        self.n_value.get(LE)
    }

    fn has_name(&self) -> bool {
        self.n_strx.get(LE) != 0
    }

    fn is_default_strippable(&self, name: &[u8]) -> bool {
        self.is_local() && name.starts_with(b"ltmp")
    }

    fn debug_string(&self) -> String {
        MachOSymDebug(self).to_string()
    }

    fn is_tls(&self) -> bool {
        self.section_properties.is_tls
    }

    fn is_interposable(&self) -> bool {
        self.visibility() == Visibility::Default
    }

    fn is_func(&self) -> bool {
        self.section_properties.is_func
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        self.visibility() == Visibility::Hidden
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }

    fn with_hidden(mut self, hidden: bool) -> Self {
        if hidden {
            self.n_type.insert(N_PEXT);
        } else {
            self.n_type.remove(N_PEXT);
        }
        self
    }
}

struct MachOSymDebug<'a>(&'a SymtabEntry);

impl std::fmt::Display for MachOSymDebug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol = self.0;
        let binding = if symbol.is_local() {
            "Local"
        } else if symbol.is_weak() {
            "Weak"
        } else {
            "Global"
        };

        let kind = if symbol.n_type.is_stab() {
            "Stab"
        } else if symbol.as_common().is_some() {
            "Common"
        } else if symbol.is_undefined() {
            "Undefined"
        } else {
            match symbol.n_type.typ() {
                N_ABS => "Absolute",
                N_SECT if symbol.is_tls() => "Tls",
                N_SECT if symbol.is_func() => "Func",
                N_SECT => "Data",
                N_INDR => "Indirect",
                _ => "Unknown",
            }
        };

        write!(f, "{binding} {kind}")
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {
    ty: macho::SectionType,
    attr: SectionFlags,
    writable: bool,
}

const SECTION_FLAGS_PROPAGATION_MASK: SectionFlags = S_ATTR_EXT_RELOC.with(S_ATTR_LOC_RELOC);

impl SectionAttributes {
    fn new(flags: SectionFlags, segment: Option<SegmentName>) -> Self {
        Self {
            ty: flags.typ(),
            attr: SectionFlags(flags.0 & SECTION_ATTRIBUTES),
            writable: segment.is_some_and(SegmentName::is_writable),
        }
    }
}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = MachO;

    fn merge(&mut self, rhs: Self) {
        self.ty = self.ty.max(rhs.ty);
        self.attr |= rhs.attr;
        self.writable |= rhs.writable;
    }

    fn apply(
        &self,
        output_sections: &mut crate::output_section_id::OutputSections<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
    ) {
        let info = output_sections.section_infos.get_mut(section_id);
        // TODO: For now, we copy what ELF does to break ties in types. This acts as a workaround
        // since S_REGULAR = 0 and more specialized types should win this tiebreak.
        info.section_attributes.ty = info.section_attributes.ty.max(self.ty);
        info.section_attributes.attr |= self.attr.without(SECTION_FLAGS_PROPAGATION_MASK);
        info.section_attributes.writable |= self.writable;
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        true
    }

    fn is_executable(&self) -> bool {
        self.flags()
            .intersects(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
    }

    fn is_tls(&self) -> bool {
        is_tls_section_type(self.ty)
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn is_no_bits(&self) -> bool {
        matches!(
            self.ty,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }

    fn flags(&self) -> SectionFlags {
        self.attr.with_type(self.ty)
    }

    fn ty(&self) -> macho::SectionType {
        self.ty
    }

    fn set_to_default_type(&mut self) {}
}

pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(_symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        NonAddressableIndexes {}
    }
}

impl platform::SegmentType for () {}

/// Represents an actual segment.
#[derive(Debug, Copy, Clone)]
pub(crate) struct ProgramSegmentDef {
    // TODO: When we implement -segprot, we should support both initprot and maxprot here.
    pub(crate) name: SegmentName,
    pub(crate) prot: macho::VmProt,
    pub(crate) flags: macho::SegmentFlags,
}

impl ProgramSegmentDef {
    fn new(name: SegmentName) -> Self {
        let (prot, flags) = match name {
            SegmentName::TEXT => (
                macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
                macho::SegmentFlags::default(),
            ),
            SegmentName::DATA_CONST => (
                macho::VM_PROT_READ | macho::VM_PROT_WRITE,
                macho::SG_READ_ONLY,
            ),
            SegmentName::LINKEDIT => (macho::VM_PROT_READ, macho::SegmentFlags::default()),
            _ => (
                macho::VM_PROT_READ | macho::VM_PROT_WRITE,
                macho::SegmentFlags::default(),
            ),
        };

        Self { name, prot, flags }
    }
}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.name, f)
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    fn is_writable(self) -> bool {
        self.prot.contains(macho::VM_PROT_WRITE)
    }

    fn is_executable(self) -> bool {
        self.prot.contains(macho::VM_PROT_EXECUTE)
    }

    fn always_keep(self) -> bool {
        matches!(self.name, SegmentName::TEXT | SegmentName::LINKEDIT)
    }

    fn is_loadable(self) -> bool {
        true
    }

    fn is_stack(self) -> bool {
        false
    }

    fn is_tls(self) -> bool {
        false
    }

    fn order_key(self) -> usize {
        match self.name {
            SegmentName::TEXT => 0,
            SegmentName::DATA_CONST => 1,
            SegmentName::DATA => 2,
            SegmentName::LINKEDIT => 4,
            _ => 3,
        }
    }
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static, MachO>,
    pub(crate) section_flags: SectionFlags,
    pub(crate) min_alignment: Alignment,
}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionIdentity::new(SectionName(&[]), None)),
    section_flags: SectionFlags(0),
    min_alignment: alignment::MIN,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    metadata: DylibMetadata<'data>,
}

#[derive(Debug)]
pub(crate) struct RelocationList<'data> {
    pub(crate) relocations: &'data [Relocation],
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        self.relocations.len()
    }
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, _input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        self.metadata.install_name
    }
}

#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        Self { name: bytes }
    }

    fn name(&self) -> &'data [u8] {
        self.name
    }

    fn version_name(&self) -> Option<&'data [u8]> {
        None
    }

    fn is_default(&self) -> bool {
        // This port does not use symbol versioning, so every symbol is treated as
        // the default version.
        true
    }
}

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&String::from_utf8_lossy(self.name), f)
    }
}

pub(crate) struct VerneedTable<'data> {
    // TODO
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        // Mach-O dynamic symbols use library ordinals rather than ELF symbol versions.
        None
    }
}

impl platform::Platform for MachO {
    const NUM_SINGLE_PART_SECTIONS: u32 = SinglePartSectionId::Count as u32;
    const NUM_BUILT_IN_REGULAR_SECTIONS: usize = 2;

    const BSS_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::COMMON);

    // The macOS kernel caches code signature state by vnode. Reusing a previously executed output's
    // inode after changing its contents can therefore cause the new executable to SIGKILL, even
    // though its new signature verifies successfully.
    const DEFAULT_FILE_REPLACEMENT_MODE: crate::FileReplacementMode = if cfg!(target_os = "macos") {
        crate::FileReplacementMode::UnlinkAndReplace
    } else {
        crate::FileReplacementMode::UpdateInPlaceWithFallback
    };

    const STRTAB_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::STRTAB);
    const SYMTAB_GLOBAL_SECTION_ID: Option<OutputSectionId> =
        Some(output_section_id::SYMTAB_GLOBAL);
    const GOT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::GOT);
    const PLT_GOT_SECTION_ID: Option<OutputSectionId> = Some(output_section_id::PLT_GOT);

    const VERIFY_IGNORE_ALIGNMENT_SECTION_IDS: &'static [OutputSectionId] =
        &[output_section_id::CODE_SIGNATURE, output_section_id::STRTAB];

    const VERIFY_IGNORE_SECTION_IDS: &'static [OutputSectionId] = &[
        crate::output_section_id::FILE_HEADER,
        output_section_id::LINK_EDIT_SEGMENT,
        output_section_id::LOAD_COMMANDS,
        output_section_id::CHAINED_FIXUP_TABLE,
        output_section_id::EXPORTS_TRIE,
        output_section_id::CODE_SIGNATURE,
    ];

    type File<'data> = File<'data>;
    type FileFlags = u32;
    type SymtabEntry = SymtabEntry;
    type PlatformSpecificSymbol = core::convert::Infallible;
    type SectionHeader = SectionHeader;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes;
    type SectionType = macho::SectionType;
    type SegmentType = ();
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type RelocationInfo = object::macho::RelocationInfo;
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = EpilogueLayoutExt;
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type StubLibraryLayoutStateExt = DynamicLayoutStateExt;
    type StubLibraryLayoutExt = DynamicLayoutExt;
    type ArchIdentifier = ();
    type Args = MachOArgs;
    type ResolutionExt = ResolutionExt;
    type SymtabShndxEntry = ();
    type SymbolVersionIndex = ();
    type FinaliseSizesExt<'data> = FinaliseSizesExt<'data>;
    type LayoutExt<'data> = LayoutExt<'data>;
    type GdbIndexScanResult<'data> = ();
    type SectionIterator<'a> = Iter<'a, SectionHeader>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = DynamicLayoutStateExt;
    type DynamicLayoutExt<'data> = DynamicLayoutExt;
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = PreludeLayoutExt;
    type PreludeLayoutExt = PreludeLayoutExt;
    type ObjectLayoutStateExt<'data> = MachORelocationCache;
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;
    type ResolvedObjectExt<'data> = ();
    type GcUnit = MachOGcUnit;

    /// Mach-O sections are associated with a SegmentName, while synthetic regions (FILE_HEADER,
    /// LOAD_COMMANDS, etc.) are not.
    type SectionIdentityExt = Option<SegmentName>;

    const HAS_NULL_SYMBOL_ENTRY: bool = true;

    fn write_output_file<'data, A: platform::Arch<Platform = Self>, F: FileSystem>(
        output: &crate::file_writer::Output<F>,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> Result {
        output.write(layout, macho_writer::write::<A>)
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes::new(
            header.flags.get(LE),
            Some(SegmentName::from_bytes(header.segment_name())),
        )
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Self::Args,
    ) {
    }

    fn is_zero_sized_section_content(
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        // Mach-O section headers, especially zero-fill sections, remain semantically useful even
        // when their contributing input subsection has no file bytes. Preserve them like ld64.
        true
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &SECTION_DEFINITIONS
    }

    fn finalise_group_layout(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        // `SectionSlot::FrameData` marks input `__compact_unwind` metadata, which has no direct
        // output address. Its records are translated by the writer after normal section and
        // symbol layout; returning zero here prevents metadata-only slots from acquiring a
        // misleading output-section address during generic finalisation.
        0
    }

    fn activate_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        _prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
    }

    fn finalise_sizes_dynamic<'data>(
        _object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> Result {
        Ok(())
    }

    fn finalise_object_sizes<'data>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn finalise_object_layout<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn file_thunk_config<'data>(_file: &Self::File<'data>) -> Option<platform::ThunkConfig> {
        // Mach-O linking currently dispatches only to `MachOAArch64`; keep this format-level hook
        // explicit so generic layout places each island in the primary `__TEXT,__text` part.
        <crate::macho_aarch64::MachOAArch64 as platform::Arch>::thunk_config()
    }

    fn finalise_layout_dynamic<'data>(
        state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> Result<Option<Self::DynamicLayoutExt<'data>>> {
        layout::default_create_resolutions(
            memory_offsets,
            resolutions_out,
            resources,
            state.symbol_id_range,
        )?;

        create_dynamic_layout_ext(state.file_id(), resources)
    }

    fn finalise_layout_stub<'data>(
        state: layout::StubLibraryLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> Result<Option<Self::StubLibraryLayoutExt>> {
        layout::default_create_resolutions(
            memory_offsets,
            resolutions_out,
            resources,
            state.symbol_id_range,
        )?;

        create_dynamic_layout_ext(state.file_id(), resources)
    }

    fn take_dynsym_index(
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> Result<u32> {
        // Mach-O emits imports through the chained-fixup import table, not an ELF `.dynsym`
        // allocation. Reaching this means a generic dynamic-symbol path was selected without a
        // Mach-O representation, so diagnose it rather than emitting a malformed index.
        bail!("Mach-O does not support generic dynamic-symbol table allocation")
    }

    fn compute_object_addresses<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        // Mach-O does not reserve a format-specific object region while iterative section-size
        // relaxation runs. Branch islands are fixed-size and planned separately.
    }

    fn layout_resources_ext<'data>(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn gc_unit_for_symbol<'data>(
        object: &Self::File<'data>,
        symbol: &Self::SymtabEntry,
        symbol_index: object::SymbolIndex,
    ) -> Result<Option<Self::GcUnit>> {
        if let Some((section_index, range)) = object.atom_for_symbol(symbol, symbol_index)? {
            return Ok(Some(MachOGcUnit::Atom {
                section_index,
                start: range.start,
            }));
        }
        Ok(object
            .symbol_section(symbol, symbol_index)?
            .map(MachOGcUnit::Section))
    }

    fn activate_object_gc<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        // `MH_SUBSECTIONS_VIA_SYMBOLS` changes only symbol-triggered liveness. Explicitly
        // retained sections and the no-GC path still keep the complete section, exactly as ld64
        // does for `S_ATTR_NO_DEAD_STRIP` and `-no_dead_strip_inits_and_terms` style roots.
        let no_gc = !resources.symbol_db.args.should_gc_sections();
        for (index, slot) in object.sections.iter().enumerate() {
            let should_load = matches!(
                slot,
                crate::resolution::SectionSlot::MustLoad(_)
                    | crate::resolution::SectionSlot::UnloadedDebugInfo
                    | crate::resolution::SectionSlot::MergeStrings(_)
            ) || (no_gc && matches!(slot, crate::resolution::SectionSlot::Unloaded(_)));
            if should_load {
                queue.send_gc_unit_request::<A>(
                    object.file_id,
                    MachOGcUnit::Section(object::SectionIndex(index)),
                    resources,
                    scope,
                );
            }
        }

        // `__compact_unwind` is not an ordinary input section to copy. Process it while the
        // object is active so its personality and LSDA dependencies participate in the same GC
        // graph as the functions they describe. The final table itself is synthesized later,
        // after all surviving functions have addresses.
        let compact_unwind_sections = object
            .sections
            .iter()
            .filter_map(|slot| match slot {
                resolution::SectionSlot::FrameData(index) => Some(*index),
                _ => None,
            })
            .collect_vec();
        for section_index in compact_unwind_sections {
            Self::load_exception_frame_data::<A>(
                object,
                common,
                section_index,
                resources,
                queue,
                scope,
            )?;
        }

        // Rust's arm64 compact-unwind records do not repeat the personality or LSDA. Those
        // dependencies appear in DWARF `zPLR` CIE/FDE augmentation data instead. Keep them in
        // the normal graph even though `__eh_frame` itself remains object-file-only metadata.
        let eh_frame_sections = object
            .object
            .enumerate_sections()
            .filter_map(|(index, section)| (section.name() == b"__eh_frame").then_some(index))
            .collect_vec();
        for section_index in eh_frame_sections {
            load_macho_eh_frame_data::<A>(
                object,
                section_index,
                resources,
                queue,
                scope,
            )?;
        }
        Ok(())
    }

    fn load_gc_unit<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        unit: Self::GcUnit,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        match unit {
            MachOGcUnit::Section(section_index) => {
                object.handle_section_load_request::<A>(
                    common,
                    resources,
                    queue,
                    section_index,
                    scope,
                )?;
                export_live_symbols_in_section(
                    object,
                    common,
                    resources,
                    section_index,
                    None,
                )
            }
            MachOGcUnit::Atom {
                section_index,
                start,
            } => {
                // `gc_sections == false` queues complete sections during activation. An early
                // symbol request can race ahead of that queue, so it must also select the
                // conventional whole-section path instead of compacting then later shrinking a
                // preallocated section.
                if !resources.symbol_db.args.should_gc_sections() {
                    return object.handle_section_load_request::<A>(
                        common,
                        resources,
                        queue,
                        section_index,
                        scope,
                    );
                }
                let range = {
                    timing_phase!("Find Mach-O atom range");
                    object.object.atom_range(section_index, start)?
                };
                let loaded = {
                    timing_phase!("Record Mach-O live atom");
                    object.load_subsection::<A>(
                        common,
                        section_index,
                        range.clone(),
                        resources,
                        queue,
                        scope,
                    )?
                };
                if !loaded {
                    return Ok(());
                }
                {
                    timing_phase!("Export Mach-O live atom symbols");
                    export_live_symbols_in_section(
                        object,
                        common,
                        resources,
                        section_index,
                        Some(&range),
                    )?;
                }

                // A relocation belongs to the atom containing its source address. Do not let a
                // dead neighbour retain targets merely because Mach-O stores relocations beside
                // the complete input section.
                {
                    timing_phase!("Traverse Mach-O atom relocations");
                    let raw_relocations = object.relocations(section_index)?.relocations;
                    object
                        .format_specific
                        .cache(section_index, raw_relocations)?;
                    for &relocation in object.format_specific.for_range(section_index, &range) {
                        process_normalized_relocation::<A>(
                            object,
                            relocation,
                            section_index,
                            resources,
                            queue,
                            scope,
                        )?;
                    }
                }
                Ok(())
            }
        }
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        state: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        section_index: object::SectionIndex,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        for relocation in paired_relocations(state.relocations(section_index)?.relocations) {
            process_normalized_relocation::<A>(
                state,
                relocation?,
                section_index,
                resources,
                queue,
                scope,
            )?;
        }
        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        Ok(crate::layout::DynamicSymbolDefinition {
            symbol_id,
            name: symbol_db.symbol_name(symbol_id)?.bytes(),
            format_specific: (),
        })
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Self::Args,
    ) {
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn program_segment_should_include_section(
        segment_def: Self::ProgramSegmentDef,
        section_info: &crate::output_section_id::SectionOutputInfo<Self>,
        section_id: crate::output_section_id::OutputSectionId,
        _rosegment: bool,
    ) -> bool {
        match (section_id, section_info.kind) {
            (FILE_HEADER | LOAD_COMMANDS, _) => segment_def.name == SegmentName::TEXT,
            (STRTAB | CHAINED_FIXUP_TABLE | SYMTAB_GLOBAL | EXPORTS_TRIE | CODE_SIGNATURE, _) => {
                segment_def.name == SegmentName::LINKEDIT
            }
            (_, SectionKind::Primary(identity)) => {
                identity.format_specific() == Some(segment_def.name)
            }
            (_, SectionKind::Secondary(_)) => false,
        }
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Self>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        // SymbolId 0 is the generic unresolved-symbol sentinel. Mach-O objects do not carry an
        // ELF-style null entry, so reserve it before assigning IDs to real input symbols.
        symbols
            .add_symbol(crate::parsing::InternalSymDefInfo::new(
                crate::parsing::SymbolPlacement::Undefined,
                b"",
            ))
            .hide();

        // C++ passes this hidden image identity to __cxa_atexit. Apple ld resolves it to the
        // first loadable address (the Mach-O header), never as a dyld import or nullable symbol.
        symbols
            .add_symbol(crate::parsing::InternalSymDefInfo::new(
                crate::parsing::SymbolPlacement::LoadBaseAddress,
                b"___dso_handle",
            ))
            .hide();
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        SECTION_DEFINITIONS
            .iter()
            .map(|d| {
                let segment = match d.kind {
                    SectionKind::Primary(identity) => identity.format_specific(),
                    SectionKind::Secondary(_) => None,
                };
                SectionOutputInfo {
                    section_attributes: SectionAttributes::new(d.section_flags, segment),
                    kind: d.kind,
                    min_alignment: d.min_alignment,
                    location_info: None,
                    secondary_order: None,
                    region_name: None,
                    fill: None,
                    phdrs: Vec::new(),
                }
            })
            .collect()
    }

    fn create_finalise_sizes_ext<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        args: &Self::Args,
        groups: &'files mut [layout::GroupState<'data, Self>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> Result<Self::FinaliseSizesExt<'data>>
    where
        'data: 'files,
        'data: 'states,
    {
        let mut imported_libraries = Vec::new();
        let mut imported_symbols = Vec::new();
        let mut compact_unwind_entry_count = 0usize;
        let mut eh_frame_input_size = 0usize;
        let mut objc_message_stubs_by_selector = BTreeMap::new();
        let mut objc_message_selectors = BTreeMap::new();

        // Mach-O bind ordinals name load commands, whose identity is their install name rather
        // than the input pathname. For example, the macOS SDK's `libSystem`, `libc`, and `libm`
        // stubs all identify as `/usr/lib/libSystem.B.dylib`. Emitting one command per input file
        // makes dyld reject the output; keep the first command and map every same-name input to
        // its ordinal during final layout.
        let mut add_imported_library = |file_id| {
            if !imported_libraries.iter().any(|&existing| {
                install_name(existing, symbol_db) == install_name(file_id, symbol_db)
            }) {
                imported_libraries.push(file_id);
            }
        };

        for group in groups.iter() {
            for file in &group.files {
                match file {
                    layout::FileLayoutState::Object(object) => {
                        for (message_symbol, selector, selector_symbol) in
                            objc_message_references_for_object(object)?
                        {
                            objc_message_stubs_by_selector
                                .entry(selector)
                                .or_insert(ObjcMessageStub {
                                    selector,
                                    message_symbol,
                                    selector_symbol,
                                });
                            objc_message_selectors.insert(message_symbol, selector);
                        }
                        for slot in &object.sections {
                            let resolution::SectionSlot::FrameData(section_index) = slot else {
                                continue;
                            };
                            let section = object.object.section(*section_index)?;
                            let data = object.object.raw_section_data(section)?;
                            ensure!(
                                data.len() % COMPACT_UNWIND_ENTRY_SIZE == 0,
                                "{} has malformed __compact_unwind data: {} bytes is not a multiple of {}",
                                object.input,
                                data.len(),
                                COMPACT_UNWIND_ENTRY_SIZE
                            );
                            compact_unwind_entry_count = compact_unwind_entry_count
                                .checked_add(data.len() / COMPACT_UNWIND_ENTRY_SIZE)
                                .context("too many Mach-O compact unwind entries")?;
                        }
                        for (_, section) in object.object.enumerate_sections() {
                            if section.name() != b"__eh_frame" {
                                continue;
                            }
                            let data = object.object.raw_section_data(section)?;
                            eh_frame_input_size = eh_frame_input_size
                                .checked_add(data.len())
                                .context("too much Mach-O __eh_frame input")?;
                        }
                    }
                    layout::FileLayoutState::StubLibrary(state) => {
                        if state.format_specific.loaded {
                            add_imported_library(state.file_id());
                        }
                        imported_symbols
                            .extend_from_slice(state.format_specific.imported_symbols.as_slice());
                    }
                    layout::FileLayoutState::Dynamic(state) => {
                        if state.format_specific.loaded {
                            add_imported_library(state.file_id());
                        }
                        imported_symbols
                            .extend_from_slice(state.format_specific.imported_symbols.as_slice());
                    }
                    _ => {}
                }
            }
        }

        // The final index is written after function addresses are known. Allocate an upper bound
        // now from the epilogue group; dead stripping can only reduce the serialized size.
        let unwind_info_capacity = compact_unwind_info_capacity(compact_unwind_entry_count);
        if unwind_info_capacity > 0 {
            let epilogue_group = groups
                .last_mut()
                .context("missing Mach-O epilogue group for __unwind_info")?;
            epilogue_group
                .common
                .allocate(part_id::UNWIND_INFO, unwind_info_capacity as u64);
        }
        let eh_frame_size = eh_frame_capacity(eh_frame_input_size)?;
        if eh_frame_input_size > 0 {
            let epilogue_group = groups
                .last_mut()
                .context("missing Mach-O epilogue group for __eh_frame")?;
            epilogue_group
                .common
                .allocate(part_id::EH_FRAME, eh_frame_size as u64);
        }
        let objc_message_stubs = objc_message_stubs_by_selector
            .into_values()
            .collect::<Vec<_>>();
        let objc_message_stub_indexes = objc_message_selectors
            .into_iter()
            .map(|(message_symbol, selector)| {
                let index = objc_message_stubs
                    .binary_search_by_key(&selector, |stub| stub.selector)
                    .expect("Objective-C selector was just inserted into the stub plan");
                (message_symbol, index)
            })
            .collect();

        if !objc_message_stubs.is_empty() {
            let epilogue_group = groups
                .last_mut()
                .context("missing Mach-O epilogue group for Objective-C message stubs")?;
            let count = u64::try_from(objc_message_stubs.len())
                .context("too many Mach-O Objective-C message stubs")?;
            epilogue_group.common.allocate(
                part_id::OBJC_MESSAGE_STUBS,
                count
                    .checked_mul(OBJC_MESSAGE_STUB_SIZE)
                    .context("Mach-O Objective-C message-stub size overflows")?,
            );
            epilogue_group.common.allocate(
                objc_selector_references_part_id(args),
                count
                    .checked_mul(OBJC_SELECTOR_REFERENCE_SIZE)
                    .context("Mach-O Objective-C selector-reference size overflows")?,
            );
        }

        Ok(FinaliseSizesExt {
            imported_libraries,
            imported_symbols,
            unwind_info_size: unwind_info_capacity as u64,
            eh_frame_size: (eh_frame_input_size > 0)
                .then_some(eh_frame_size as u64)
                .unwrap_or(0),
            objc_message_stubs,
            objc_message_stub_indexes,
        })
    }

    fn create_layout_ext<'data>(
        finalise_sizes_ext: Self::FinaliseSizesExt<'data>,
        resolutions: &SymbolResolutions<Self>,
    ) -> Result<Self::LayoutExt<'data>> {
        let mut layout_ext = LayoutExt::default();

        let imported_symbols = finalise_sizes_ext
            .imported_symbols
            .iter()
            .map(|&symbol_id| {
                let resolution = resolutions
                    .get(symbol_id)
                    .with_context(|| "missing resolution for a stub library symbol".to_string())?;

                let binding = match (
                    resolution.format_specific.got_address,
                    resolution.format_specific.tlvp_address,
                ) {
                    (Some(got_address), None) => ImportedSymbolBinding::Got {
                        got_address,
                        plt_address: resolution.format_specific.plt_address,
                    },
                    (None, Some(tlvp_address)) => ImportedSymbolBinding::Tlvp { tlvp_address },
                    (None, None) => {
                        bail!("missing runtime-bound pointer slot for imported Mach-O symbol")
                    }
                    (Some(_), Some(_)) => {
                        bail!("imported Mach-O symbol has both GOT and TLVP slots")
                    }
                };

                Ok(ImportedSymbolWithResolution {
                    symbol_id,
                    binding,
                    weak_import: resolution.flags().is_weak_reference(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        layout_ext.imported_symbols = imported_symbols
            .into_iter()
            .sorted_by_key(|symbol| symbol.binding.address())
            .collect();
        layout_ext.objc_message_stubs = finalise_sizes_ext.objc_message_stubs;
        layout_ext.objc_message_stub_indexes = finalise_sizes_ext.objc_message_stub_indexes;

        Ok(layout_ext)
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        compact_unwind_section_index: object::SectionIndex,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        queue: &mut crate::layout::LocalWorkQueue<Self>,
        scope: &rayon::Scope<'scope>,
    ) -> Result {
        let section = object.object.section(compact_unwind_section_index)?;
        let data = object.object.raw_section_data(section)?;
        ensure!(
            data.len() % COMPACT_UNWIND_ENTRY_SIZE == 0,
            "{} has malformed __compact_unwind data: {} bytes is not a multiple of {}",
            object.input,
            data.len(),
            COMPACT_UNWIND_ENTRY_SIZE
        );

        // The object representation's relocations are dependencies even though the metadata
        // section itself is never copied. In particular, an LSDA is otherwise unreferenced by
        // normal instructions, and a personality often appears only in this section. Reuse the
        // normal Mach-O relocation graph handling for externals so its GOT/dylib bookkeeping
        // remains exactly consistent with an ordinary unsigned pointer relocation.
        for relocation in object
            .relocations(compact_unwind_section_index)?
            .relocations
        {
            let info = relocation.info(LE);
            ensure!(
                info.r_type == macho::ARM64_RELOC_UNSIGNED
                    && !info.r_pcrel
                    && info.r_length == 3,
                "unsupported __compact_unwind relocation in {}: expected ARM64_RELOC_UNSIGNED, r_pcrel=0, r_length=3",
                object.input
            );
            let offset = usize::try_from(info.r_address)
                .context("__compact_unwind relocation offset overflowed usize")?;
            ensure!(
                offset + size_of::<u64>() <= data.len()
                    && matches!(offset % COMPACT_UNWIND_ENTRY_SIZE, 0 | 16 | 24),
                "unsupported __compact_unwind relocation offset 0x{offset:x} in {}",
                object.input
            );

            if info.r_extern {
                process_relocation::<A>(
                    object,
                    info,
                    compact_unwind_section_index,
                    resources,
                    queue,
                    scope,
                )?;
            } else if offset % COMPACT_UNWIND_ENTRY_SIZE == 24 {
                // `r_symbolnum` is a one-based section ordinal for non-external Mach-O
                // relocations. Keeping the whole LSDA section is conservative but correct even
                // when a producer does not emit subsection symbols for its exception table.
                let section_ordinal = usize::try_from(info.r_symbolnum)
                    .context("__compact_unwind section ordinal overflowed usize")?;
                let target_section = section_ordinal.checked_sub(1).context(
                    "__compact_unwind LSDA relocation has section ordinal zero",
                )?;
                ensure!(
                    target_section < object.sections.len(),
                    "__compact_unwind LSDA relocation refers to section {} but {} has only {} sections",
                    section_ordinal,
                    object.input,
                    object.sections.len()
                );
                queue.send_gc_unit_request::<A>(
                    object.file_id,
                    MachOGcUnit::Section(object::SectionIndex(target_section)),
                    resources,
                    scope,
                );
            }
        }

        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue<Self>,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> Result {
        Ok(())
    }

    fn new_epilogue_layout<'data>(
        _args: &Self::Args,
        _output_kind: crate::output_kind::OutputKind,
        _dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'data, Self>],
        group_states: &[layout::GroupState<'data, Self>],
    ) -> Self::EpilogueLayoutExt {
        verbose_timing_phase!("Gather imported symbol IDs");

        let imported_symbols = group_states
            .iter()
            .flat_map(|group| {
                group.files.iter().flat_map(|file| match file {
                    layout::FileLayoutState::StubLibrary(file) => {
                        file.format_specific.imported_symbols.as_slice()
                    }
                    layout::FileLayoutState::Dynamic(file) => {
                        file.format_specific.imported_symbols.as_slice()
                    }
                    _ => &[],
                })
            })
            .copied()
            .collect();

        EpilogueLayoutExt { imported_symbols }
    }

    fn apply_non_addressable_indexes_epilogue(
        _counts: &mut Self::NonAddressableCounts,
        _state: &mut Self::EpilogueLayoutExt,
    ) {
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _counts: &Self::NonAddressableCounts,
        _mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
    }

    fn finalise_sizes_epilogue<'data>(
        state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        _format_specific: &Self::FinaliseSizesExt<'data>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
        let mut fixup_table_size = CHAINED_FIXUP_TABLE_BASE_SIZE;

        fixup_table_size += state
            .imported_symbols
            .iter()
            .map(|&s| {
                CHAINED_FIXUP_IMPORT_SIZE
                    + symbol_db.symbol_name(s).unwrap().bytes().len() as u64
                    + 1
            })
            .sum::<u64>();

        // Chained fixups may now occur in every output segment: imported GOT/TLVP slots are binds
        // and ordinary local data pointers are rebases. Segment addresses are assigned later, so
        // use a bounded reservation here. Counting every non-empty part independently is an upper
        // bound for the number of 16KiB pages after parts are packed into their segments.
        let max_page_count = mem_sizes
            .parts
            .iter()
            .copied()
            .filter(|&size| size != 0)
            .map(|size| size.div_ceil(MACHO_PAGE_ALIGNMENT.value()))
            .sum::<u64>();
        fixup_table_size += CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE as u64
            * u64::try_from(MAX_SEGMENT_COUNT - 1).unwrap();
        fixup_table_size += CHAINED_FIXUP_PAGE_START_SIZE * max_page_count;
        // Segment-start records are only u16-aligned; reserve the padding needed to align the
        // following `dyld_chained_import` array to its u32 ABI alignment.
        fixup_table_size += (size_of::<u32>() - 1) as u64;

        mem_sizes.increment(
            part_id::CHAINED_FIXUP_TABLE,
            alignment::USIZE.align_up(fixup_table_size),
        );

        // Currently we determine the output file size before we assign symbol addresses. This lets
        // us do file creation in parallel with address assignment, however it means that we can't
        // take addresses into account when determining section sizes. The export trie, due to using
        // uleb128 encoding for addresses, needs addresses in order to determine an exact size. We
        // work around this for now by assuming all addresses will be u64::MAX. This gives us an
        // upper bound on how large the trie will be, but wastes some space in the file. TODO:
        // Figure out a good way to fix this.
        let mut exports = dynamic_symbol_definitions
            .iter()
            .map(|symbol| crate::trie::Symbol {
                name: symbol.name,
                address: u64::MAX,
                flags: object::macho::ExportSymbolFlags(0),
            })
            .collect_vec();

        mem_sizes.increment(
            part_id::EXPORTS_TRIE,
            crate::trie::build(&mut exports).len() as u64,
        );
    }

    fn finalise_sizes_all<'data>(
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_layout_epilogue<'data>(
        _epilogue_state: &mut Self::EpilogueLayoutExt,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        format_specific: &Self::FinaliseSizesExt<'data>,
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> Result {
        memory_offsets.increment(part_id::EH_FRAME, format_specific.eh_frame_size);
        memory_offsets.increment(part_id::UNWIND_INFO, format_specific.unwind_info_size);
        let objc_stub_count = u64::try_from(format_specific.objc_message_stubs.len())
            .context("too many Mach-O Objective-C message stubs")?;
        memory_offsets.increment(
            part_id::OBJC_MESSAGE_STUBS,
            objc_stub_count
                .checked_mul(OBJC_MESSAGE_STUB_SIZE)
                .context("Mach-O Objective-C message-stub size overflows")?,
        );
        memory_offsets.increment(
            objc_selector_references_part_id(symbol_db.args),
            objc_stub_count
                .checked_mul(OBJC_SELECTOR_REFERENCE_SIZE)
                .context("Mach-O Objective-C selector-reference size overflows")?,
        );
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        _object: &Self::File<'data>,
        _args: &Self::Args,
        _sym: &Self::SymtabEntry,
        _output_kind: crate::output_kind::OutputKind,
        _export_list: Option<&crate::export_list::ExportList>,
        _lib_name: &[u8],
        _archive_semantics: bool,
        _is_undefined: bool,
    ) -> bool {
        // Wild supports only Mach-O's default two-level namespace: the argument parser does not
        // accept `-flat_namespace`, `-force_flat_namespace`, or `-interposable`, and
        // `macho_writer::populate_file_header` always emits `MH_TWOLEVEL`. A reference is thus
        // bound by the static linker to its chosen dylib ordinal (or to this image's definition),
        // rather than being rebound by flat-namespace lookup. That makes both selected imports
        // and ordinary dylib self-references non-interposable for every supported ARM64 mode.
        true
    }

    fn allocate_header_sizes<'data>(
        prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        header_info: &crate::layout::HeaderInfo,
        program_segments: &ProgramSegments<Self::ProgramSegmentDef>,
        output_sections: &crate::output_section_id::OutputSections<Self>,
        resources: &layout::FinaliseSizesResources<'data, '_, Self>,
        args: &Self::Args,
    ) {
        sizes.increment(crate::part_id::FILE_HEADER, size_of::<FileHeader>() as u64);

        let mut allocate_load_cmd = |command_size| {
            sizes.increment(part_id::LOAD_COMMANDS, command_size as u64);
            prelude.format_specific.load_command_count += 1;
        };

        // __PAGEZERO reserves the low address space for an executable. A dylib instead starts
        // its relocatable image at VM address zero and must not advertise an executable-only
        // synthetic segment.
        if resources.symbol_db.output_kind.is_executable() {
            allocate_load_cmd(size_of::<SegmentCommand>());
        }

        for &segment_id in &header_info.active_segment_ids {
            let segment = program_segments.segment_def(segment_id);
            allocate_load_cmd(
                size_of::<SegmentCommand>()
                    + size_of::<SectionEntry>()
                        * count_sections_for_segment(output_sections, *segment),
            );
        }

        if resources.symbol_db.output_kind.is_executable() {
            allocate_load_cmd(size_of::<EntryPointCommand>());
            allocate_load_cmd(
                (size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
                    .next_multiple_of(MACHO_COMMAND_ALIGNMENT),
            );
        } else if resources.symbol_db.output_kind.is_shared_object() {
            allocate_load_cmd(load_dylib_command_size(args.dylib_install_name()));
        }

        for rpath in &args.rpaths {
            allocate_load_cmd(rpath_command_size(rpath.as_bytes()));
        }

        prelude.format_specific.imported_library_file_ids =
            resources.format_specific.imported_libraries.clone();

        prelude.format_specific.load_dylib_command_sizes = prelude
            .format_specific
            .imported_library_file_ids
            .iter()
            .map(|&file_id| load_dylib_command_size(install_name(file_id, resources.symbol_db)))
            .collect();
        let load_dylib_command_sizes = prelude.format_specific.load_dylib_command_sizes.clone();
        for command_size in load_dylib_command_sizes {
            allocate_load_cmd(command_size);
        }

        allocate_load_cmd(size_of::<DyldChainedFixupsCommand>());
        if resources.symbol_db.output_kind.needs_dynsym() {
            allocate_load_cmd(size_of::<object::macho::LinkeditDataCommand<Endianness>>());
        }
        allocate_load_cmd(size_of::<SymtabCommand>());
        allocate_load_cmd(size_of::<CodeSignatureCommand>());
        allocate_load_cmd(size_of::<UuidCommand>());
        if args.platform_version.is_some() {
            allocate_load_cmd(size_of::<BuildVersionCommand>());
        }
    }

    fn new_stub_library_layout_state_ext<'data>(
        stub: &resolution::ResolvedStubLibrary<'data>,
        args: &Self::Args,
    ) -> Self::StubLibraryLayoutStateExt {
        DynamicLayoutStateExt::new(args, stub.defined_symbols.dylib)
    }

    fn new_dynamic_layout_state_ext<'data>(
        file: &resolution::ResolvedDynamic<'data, Self>,
        args: &Self::Args,
    ) -> Self::DynamicLayoutStateExt<'data> {
        let metadata = file
            .common
            .object
            .dylib_metadata()
            .expect("Resolved Mach-O dynamic input must carry LC_ID_DYLIB metadata");
        DynamicLayoutStateExt::new(args, metadata)
    }

    fn load_stub_library_symbol<'data>(
        state: &mut StubLibraryLayoutState<Self>,
        symbol_id: SymbolId,
    ) -> Result {
        state.format_specific.loaded = true;
        state.format_specific.imported_symbols.push(symbol_id);

        Ok(())
    }

    fn finalise_sizes_for_symbol<'data>(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
        _flags: crate::value_flags::ValueFlags,
    ) -> Result {
        Ok(())
    }

    fn allocate_resolution(
        flags: crate::value_flags::ValueFlags,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        // Keep size finalisation in lockstep with `create_resolution`: a local resolution can
        // still consume a PLT, GOT, or TLVP slot. Restricting this to dynamic flags leaves a
        // zero-sized provisional synthetic section that final layout later advances.
        if flags.needs_plt() {
            mem_sizes.increment(part_id::PLT_GOT, PLT_ENTRY_SIZE);
        }
        if flags.needs_got() {
            mem_sizes.increment(part_id::GOT, GOT_ENTRY_SIZE);
        }
        if flags.needs_got_tls_descriptor() {
            mem_sizes.increment(part_id::TLVP, GOT_ENTRY_SIZE);
        }
    }

    fn allocate_object_symtab_space<'data>(
        state: &crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) -> Result {
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), flags) in state
            .object
            .enumerate_symbols()
            .zip(per_symbol_flags.range(state.symbol_id_range))
        {
            let symbol_id = state.symbol_id_range.input_to_id(sym_index);
            if let Some(section_index) = state.object.symbol_section(sym, sym_index)? {
                let input_offset = state
                    .object
                    .symbol_offset_in_section(sym, section_index)?;
                if !state.input_offset_is_live(section_index, input_offset) {
                    continue;
                }
            }
            if let Some(info) = SymbolCopyInfo::new(
                state.object,
                sym_index,
                sym,
                symbol_id,
                symbol_db,
                flags.get(),
                &state.sections,
            ) {
                num_globals += 1;
                strings_size += info.name.len() + 1;
            }
        }

        // An executable's final image intentionally omits ordinary `__DWARF`. For the restricted
        // C/Rust path, reserve the STABS debug map that lets `dsymutil` reopen this loose input
        // object and do the address rewriting itself. Keep this allocation exactly in sync with
        // `write_dsymutil_debug_map` in the writer.
        if !symbol_db.args.should_strip_debug() && state.input.entry.is_none() {
            if let Some(debug_map) = state.object.dsymutil_debug_map(&state.sections, |section, offset| {
                state.input_offset_is_live(section, offset)
            })? {
                num_globals += 3 + 2 * debug_map.functions.len() as u64;
                strings_size += debug_map.source_path.len() + 1;
                strings_size += state.input.file.filename.as_os_str().as_encoded_bytes().len() + 1;
                strings_size += debug_map
                    .functions
                    .iter()
                    .map(|function| function.name.len() + 1)
                    .sum::<usize>();
            }
        }
        let entry_size = size_of::<RawSymtabEntry>() as u64;
        common.allocate(part_id::SYMTAB_GLOBAL, num_globals * entry_size);
        common.allocate(part_id::STRTAB, strings_size as u64);

        Ok(())
    }

    fn allocate_internal_symbol(
        _symbol_id: crate::symbol_db::SymbolId,
        def_info: &crate::parsing::InternalSymDefInfo<Self>,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> Result {
        // Mach-O's internal ABI symbols (currently `___dso_handle`) are linker-private. Their
        // resolutions are used by relocations but they intentionally have no nlist entry, so no
        // symtab or string-table allocation is required.
        debug_assert!(def_info.symbol.is_hidden());
        Ok(())
    }

    fn allocate_prelude(
        common: &mut crate::layout::CommonGroupState<Self>,
        symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
        // Allocate one extra character as n_strx == 0 is treated as unnamed.
        common.allocate(part_id::STRTAB, 1);
        common.allocate(
            part_id::CODE_SIGNATURE,
            CS_HEADERS_SIZE + code_signature_padded_identifier_size(symbol_db.args),
        );
    }

    fn finalise_prelude_layout<'data>(
        prelude: &crate::layout::PreludeLayoutState<Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> Result<Self::PreludeLayoutExt> {
        Ok(prelude.format_specific.clone())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _args: &<Self as crate::platform::Platform>::Args,
        _output_kind: crate::OutputKind,
    ) -> crate::layout::Resolution<Self> {
        let mut resolution: Resolution<MachO> = Resolution {
            raw_value,
            dynamic_symbol_index,
            format_specific: ResolutionExt {
                // `raw_value` below becomes a GOT/PLT/TLVP address when a relocation requires
                // an indirection. Keep the symbol's own address for metadata and local GOT
                // rebases (notably sectionless common definitions).
                symbol_address: raw_value,
                got_address: None,
                tlvp_address: None,
                plt_address: None,
            },
            flags,
        };

        if flags.needs_plt() {
            let plt_address = allocate_plt(memory_offsets);
            resolution.raw_value = plt_address.get();
            resolution.format_specific.plt_address = Some(plt_address);
            resolution.format_specific.got_address = Some(allocate_got(memory_offsets));
        } else if flags.needs_got() {
            let got_address = allocate_got(memory_offsets);
            resolution.raw_value = got_address.get();
            resolution.format_specific.got_address = Some(got_address);
        } else if flags.needs_got_tls_descriptor() {
            let tlvp_address = allocate_tlvp(memory_offsets);
            resolution.raw_value = tlvp_address.get();
            resolution.format_specific.tlvp_address = Some(tlvp_address);
        }

        resolution
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName {
            name: objc_message_selector(name_bytes).map_or(name_bytes, |_| b"_objc_msgSend"),
        }
    }

    fn default_layout_rules(_args: &Self::Args) -> Vec<crate::layout_rules::SectionRule<'static>> {
        DEFAULT_SECTION_RULES.to_vec()
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &crate::output_section_id::CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
        _location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> (
        crate::output_section_id::OutputOrder<'data>,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        // TODO: Order sections within each segment according to Mach-O conventions.
        let arbitrary_segments: Vec<SegmentName> = output_sections
            .ids_with_info()
            .filter_map(|(_, info)| match info.kind {
                SectionKind::Primary(identity) => identity.format_specific(),
                SectionKind::Secondary(_) => None,
            })
            .filter(|name| {
                !matches!(
                    *name,
                    SegmentName::PAGEZERO
                        | SegmentName::TEXT
                        | SegmentName::DATA_CONST
                        | SegmentName::DATA
                        | SegmentName::LINKEDIT
                )
            })
            .unique()
            .collect();

        let segment_defs = [
            SegmentName::TEXT,
            SegmentName::DATA_CONST,
            SegmentName::DATA,
        ]
        .into_iter()
        .chain(arbitrary_segments.iter().copied())
        .chain([SegmentName::LINKEDIT])
        .map(ProgramSegmentDef::new)
        .collect();

        let mut builder = OutputOrderBuilder::<Self>::new(
            segment_defs,
            output_kind,
            output_sections,
            secondary,
            false,
            &[],
        );

        // File header and all load commands.
        builder.add_section(crate::output_section_id::FILE_HEADER);
        builder.add_section(output_section_id::LOAD_COMMANDS);

        // The ordinary `__TEXT,__text` section is regular rather than custom so ARM64 branch
        // islands can be inserted between object allocations. It must precede the remaining
        // executable custom sections, just as it does in ld64 output.
        builder.add_section(output_section_id::TEXT);

        // Content of the remaining sections (e.g. custom executable sections and __data).
        add_sections_in_segment(
            &mut builder,
            output_sections,
            &custom.exec,
            SegmentName::TEXT,
        );

        builder.add_section(output_section_id::PLT_GOT);
        // Clang's modern Objective-C dispatch veneer is executable code, but it is distinct from
        // dyld's ordinary 12-byte `__stubs`: every entry first loads a selector into x1.
        builder.add_section(output_section_id::OBJC_MESSAGE_STUBS);
        add_sections_in_segment(&mut builder, output_sections, &custom.ro, SegmentName::TEXT);
        // Apple places the compact-unwind index before the coalesced DWARF table. The DWARF
        // rows' rewritten pcrel fields are independent of this order, but preserving the native
        // section arrangement lets libunwind discover both representations conventionally.
        builder.add_section(output_section_id::UNWIND_INFO);
        builder.add_section(output_section_id::EH_FRAME);
        builder.add_section(output_section_id::GOT);

        for segment in [SegmentName::DATA_CONST] {
            add_sections_in_segment(&mut builder, output_sections, &custom.exec, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.ro, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.data, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.bss, segment);
            // `-const_selrefs` makes selector slots read-only after dyld rebases them. Keep them
            // after other data-const Objective-C registrations (such as `__objc_classlist`), as
            // ld64 does; the ordinary writable variant is emitted in the __DATA block below.
            builder.add_section(output_section_id::OBJC_CONST_SELECTOR_REFERENCES);
        }

        // A dynamic TLS reference is a pointer to a dylib's `__thread_vars` descriptor, not a
        // normal `__got` value. Keep it in the ABI's dedicated pointer section, ahead of ordinary
        // writable data just as ld64.lld does.
        builder.add_section(output_section_id::TLVP);
        for segment in [SegmentName::DATA] {
            add_sections_in_segment(&mut builder, output_sections, &custom.exec, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.ro, segment);
            // Objective-C object metadata is conventionally a writable `__DATA,__objc_const`
            // input section despite its name. Emit that one named section before synthetic
            // selector references, matching ld64's image-registration layout.
            add_named_sections_in_segment(
                &mut builder,
                output_sections,
                &custom.data,
                segment,
                b"__objc_const",
            );
            // libobjc scans this literal-pointer section during image registration and replaces
            // its rebased method-name addresses with canonical selector values. ld64 keeps it
            // after read-only Objective-C metadata such as `__objc_const`, before mutable data.
            builder.add_section(output_section_id::OBJC_SELECTOR_REFERENCES);
            add_sections_in_segment_except(
                &mut builder,
                output_sections,
                &custom.data,
                segment,
                b"__objc_const",
            );
            // Thread-local payloads are ordinary Mach-O `__DATA` sections, even though the
            // generic layout keeps them separate so it can preserve TLS-specific liveness and
            // zero-fill semantics. The regular and zero-fill TLS sections form one contiguous
            // image TLS template: descriptors contain offsets from `__thread_data`, so an
            // ordinary `__bss` section must not be placed between them.
            add_sections_in_segment(&mut builder, output_sections, &custom.tdata, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.tbss, segment);
            add_sections_in_segment(&mut builder, output_sections, &custom.bss, segment);
        }
        builder.add_section(output_section_id::COMMON);

        // Arbitrary segment sections are added in first-seen order.
        for segment in arbitrary_segments {
            for (section_id, info) in output_sections.ids_with_info() {
                if matches!(info.kind, SectionKind::Primary(identity) if identity.format_specific() == Some(segment))
                {
                    builder.add_section(section_id);
                }
            }
        }

        // The rest (e.g. symbol table, string table).
        builder.add_section(output_section_id::STRTAB);
        builder.add_section(output_section_id::CHAINED_FIXUP_TABLE);
        builder.add_section(output_section_id::EXPORTS_TRIE);
        builder.add_section(output_section_id::SYMTAB_GLOBAL);
        builder.add_section(output_section_id::CODE_SIGNATURE);

        builder.build()
    }

    fn align_load_segment_start(
        _segment_def: ProgramSegmentDef,
        segment_alignment: Alignment,
        file_offset: &mut usize,
        mem_offset: &mut u64,
    ) {
        *file_offset = segment_alignment.align_up(*file_offset as u64) as usize;
        *mem_offset = segment_alignment.align_up(*mem_offset);
    }

    fn default_symtab_entry() -> Self::SymtabEntry {
        SymtabEntry::from_raw(
            RawSymtabEntry {
                n_strx: Default::default(),
                n_type: Default::default(),
                n_sect: Default::default(),
                n_desc: Default::default(),
                n_value: Default::default(),
            },
            SymbolSectionProperties::default(),
        )
    }

    fn output_symtab_entry_size() -> usize {
        size_of::<RawSymtabEntry>()
    }

    fn tls_nobits_extend_load_segment() -> bool {
        true
    }

    fn last_part_size_to_extend(
        record: &OutputRecordLayout,
        last_part_id: PartId,
    ) -> Result<usize> {
        ensure!(
            last_part_id == part_id::CODE_SIGNATURE,
            "code signature must be last part_id"
        );
        // The CODE_SIGNATURE size depends on the final file size, excluding the
        // signature itself. Compute it after layout because there is one SHA hash
        // per file block (4 KiB) covered by the signature.
        Ok(record.file_offset.div_ceil(CS_BLOCK_SIZE) * CS_HASH_SIZE as usize)
    }

    fn is_allowed_in_archive(kind: crate::file_kind::FileKind) -> bool {
        kind == crate::file_kind::FileKind::MachOObject
    }

    fn section_identity<'data>(
        name: SectionName<'data>,
        section: &Self::SectionHeader,
    ) -> SectionIdentity<'data, Self> {
        SectionIdentity::new(name, Some(SegmentName::from_bytes(section.segment_name())))
    }

    fn fmt_section_identity(
        section_name: SectionName<'_>,
        segment_name: &Self::SectionIdentityExt,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match segment_name {
            Some(segment_name) => write!(f, "{segment_name},{section_name}"),
            None => write!(f, "{section_name}"),
        }
    }
}

fn load_macho_eh_frame_data<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    object: &mut crate::layout::ObjectLayoutState<'data, MachO>,
    eh_frame_section_index: object::SectionIndex,
    resources: &'scope crate::layout::GraphResources<'data, '_, MachO>,
    queue: &mut crate::layout::LocalWorkQueue<MachO>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    let section = object.object.section(eh_frame_section_index)?;
    let data = object.object.raw_section_data(section)?;
    let augmentations = eh_frame_augmentations(data)?;
    if augmentations.is_empty() {
        return Ok(());
    }

    let mut relocations = std::collections::BTreeMap::new();
    for relocation in object.relocations(eh_frame_section_index)?.relocations {
        let info = relocation.info(LE);
        if matches!(
            info.r_type,
            macho::ARM64_RELOC_POINTER_TO_GOT | macho::ARM64_RELOC_UNSIGNED
        ) {
            let offset = usize::try_from(info.r_address)
                .context("Mach-O __eh_frame relocation offset overflowed usize")?;
            ensure!(
                relocations.insert(offset, info).is_none(),
                "duplicate Mach-O __eh_frame relocation at offset 0x{offset:x} in {}",
                object.input
            );
        }
    }

    let mut personality_offsets = std::collections::BTreeSet::new();
    let mut lsda_offsets = std::collections::BTreeSet::new();
    for augmentation in augmentations {
        personality_offsets.insert(augmentation.personality_relocation_offset);
        lsda_offsets.insert(augmentation.lsda_relocation_offset);
    }
    for offset in personality_offsets {
        let info = *relocations.get(&offset).with_context(|| {
            format!(
                "missing personality relocation at Mach-O __eh_frame offset 0x{offset:x} in {}",
                object.input
            )
        })?;
        ensure!(
            info.r_type == macho::ARM64_RELOC_POINTER_TO_GOT
                && info.r_extern
                && info.r_pcrel
                && info.r_length == 2,
            "unsupported Mach-O __eh_frame personality relocation in {}: expected external ARM64_RELOC_POINTER_TO_GOT, r_pcrel=1, r_length=2",
            object.input
        );
        process_relocation::<A>(
            object,
            info,
            eh_frame_section_index,
            resources,
            queue,
            scope,
        )?;
    }
    for offset in lsda_offsets {
        let info = *relocations.get(&offset).with_context(|| {
            format!(
                "missing LSDA relocation at Mach-O __eh_frame offset 0x{offset:x} in {}",
                object.input
            )
        })?;
        ensure!(
            info.r_type == macho::ARM64_RELOC_UNSIGNED && info.r_length == 3,
            "unsupported Mach-O __eh_frame LSDA relocation in {}: expected ARM64_RELOC_UNSIGNED with r_length=3",
            object.input
        );
        if info.r_extern {
            process_relocation::<A>(
                object,
                info,
                eh_frame_section_index,
                resources,
                queue,
                scope,
            )?;
        } else {
            let section_ordinal = usize::try_from(info.r_symbolnum)
                .context("Mach-O __eh_frame LSDA section ordinal overflowed usize")?;
            let target_section = section_ordinal
                .checked_sub(1)
                .context("Mach-O __eh_frame LSDA relocation has section ordinal zero")?;
            ensure!(
                target_section < object.sections.len(),
                "Mach-O __eh_frame LSDA relocation refers to section {} but {} has only {} sections",
                section_ordinal,
                object.input,
                object.sections.len()
            );
            queue.send_gc_unit_request::<A>(
                object.file_id,
                MachOGcUnit::Section(object::SectionIndex(target_section)),
                resources,
                scope,
            );
        }
    }
    Ok(())
}

pub(crate) fn install_name<'data>(
    file_id: FileId,
    symbol_db: &crate::symbol_db::SymbolDb<'data, MachO>,
) -> &'data [u8] {
    dylib_metadata(file_id, symbol_db).install_name
}

/// Returns the one dynamic-library identity used consistently for duplicate suppression,
/// ordinals, and the emitted `LC_LOAD_DYLIB` command.
pub(crate) fn dylib_metadata<'data>(
    file_id: FileId,
    symbol_db: &crate::symbol_db::SymbolDb<'data, MachO>,
) -> DylibMetadata<'data> {
    match symbol_db.file(file_id) {
        SequencedInput::StubLibrary(stub) => stub.defined_symbols.dylib,
        SequencedInput::Object(obj) => obj
            .parsed
            .object
            .dylib_metadata()
            .expect("Expected a dynamic Mach-O input"),
        _ => {
            panic!("Internal error: Expected StubLibrary or Dynamic");
        }
    }
}

fn create_dynamic_layout_ext<'data>(
    target_file_id: FileId,
    resources: &layout::FinaliseLayoutResources<'_, 'data, MachO>,
) -> Result<Option<DynamicLayoutExt>> {
    let target_install_name = install_name(target_file_id, resources.symbol_db);
    let Some(index) = resources
        .format_specific
        .imported_libraries
        .iter()
        .position(|&file_id| install_name(file_id, resources.symbol_db) == target_install_name)
    else {
        return Ok(None);
    };

    Ok(Some(DynamicLayoutExt {
        ordinal: NonZeroU8::new(u8::try_from(index + 1).context("Too many loaded stub libraries")?)
            .unwrap(),
    }))
}

const NUM_BUILT_IN_SECTIONS: usize = crate::output_section_id::num_built_in_sections::<MachO>();

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = {
    let mut defs = [DEFAULT_DEFS; NUM_BUILT_IN_SECTIONS];

    defs[crate::output_section_id::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"FILE_HEADER"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::LOAD_COMMANDS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"LOAD_COMMANDS"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::LINK_EDIT_SEGMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(SEG_LINKEDIT.as_bytes()),
            None,
        )),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::STRTAB.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"STRTAB"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CHAINED_FIXUP_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"DYLD_CHAINED_FIXUPS_TABLE"),
            None,
        )),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::EXPORTS_TRIE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"EXPORTS_TRIE"), None)),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::SYMTAB_GLOBAL.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"SYMTAB"), None)),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CODE_SIGNATURE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(SectionName(b"CODE_SIGNATURE"), None)),
        min_alignment: Alignment {
            exponent: CS_SECTION_ALIGNMENT_EXP,
        },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::GOT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__got"),
            Some(SegmentName::DATA_CONST),
        )),
        section_flags: macho::S_NON_LAZY_SYMBOL_POINTERS.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::TLVP.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__thread_ptrs"),
            Some(SegmentName::DATA),
        )),
        section_flags: macho::S_THREAD_LOCAL_VARIABLE_POINTERS.to_flags(),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::PLT_GOT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__stubs"),
            Some(SegmentName::TEXT),
        )),
        section_flags: macho::S_SYMBOL_STUBS
            .to_flags()
            .with(macho::S_ATTR_PURE_INSTRUCTIONS)
            .with(macho::S_ATTR_SOME_INSTRUCTIONS),
        min_alignment: Alignment { exponent: 2 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::OBJC_MESSAGE_STUBS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__objc_stubs"),
            Some(SegmentName::TEXT),
        )),
        section_flags: macho::S_REGULAR
            .to_flags()
            .with(macho::S_ATTR_PURE_INSTRUCTIONS)
            .with(macho::S_ATTR_SOME_INSTRUCTIONS),
        min_alignment: Alignment { exponent: 5 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::OBJC_SELECTOR_REFERENCES.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__objc_selrefs"),
            Some(SegmentName::DATA),
        )),
        section_flags: macho::S_LITERAL_POINTERS
            .to_flags()
            .with(S_ATTR_NO_DEAD_STRIP),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::OBJC_CONST_SELECTOR_REFERENCES.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__objc_selrefs"),
            Some(SegmentName::DATA_CONST),
        )),
        // ld64 emits a regular zero-flag section here. The selector list is already limited to
        // live selector-dispatch stubs, so the writable variant's no-dead-strip attribute is not
        // part of the `-const_selrefs` contract.
        section_flags: macho::S_REGULAR.to_flags(),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::EH_FRAME.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__eh_frame"),
            Some(SegmentName::TEXT),
        )),
        section_flags: macho::S_COALESCED
            .to_flags()
            .with(S_ATTR_LIVE_SUPPORT)
            .with(S_ATTR_NO_TOC),
        min_alignment: Alignment { exponent: 3 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::UNWIND_INFO.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__unwind_info"),
            Some(SegmentName::TEXT),
        )),
        min_alignment: Alignment { exponent: 2 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::TEXT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__text"),
            Some(SegmentName::TEXT),
        )),
        section_flags: macho::S_REGULAR
            .to_flags()
            .with(macho::S_ATTR_PURE_INSTRUCTIONS)
            .with(macho::S_ATTR_SOME_INSTRUCTIONS),
        min_alignment: Alignment { exponent: 2 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::COMMON.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionIdentity::new(
            SectionName(b"__common"),
            Some(SegmentName::DATA),
        )),
        section_flags: S_ZEROFILL.to_flags(),
        ..DEFAULT_DEFS
    };

    defs
};

#[derive(Debug, Default)]
pub(crate) struct EpilogueLayoutExt {
    imported_symbols: Vec<SymbolId>,
}

#[derive(Debug)]
pub(crate) struct DynamicLayoutStateExt {
    imported_symbols: Vec<SymbolId>,
    loaded: bool,
}

#[derive(Debug)]
pub(crate) struct DynamicLayoutExt {
    pub(crate) ordinal: NonZeroU8,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ResolutionExt {
    /// The definition address before relocation-specific indirection rewrites `raw_value`.
    pub(crate) symbol_address: u64,
    pub(crate) got_address: Option<NonZeroU64>,
    /// Runtime-bound pointer to an imported dylib's TLV descriptor in `__thread_ptrs`.
    pub(crate) tlvp_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
}

fn allocate_got(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let got_address = NonZeroU64::new(*memory_offsets.get(part_id::GOT)).unwrap();
    memory_offsets.increment(part_id::GOT, GOT_ENTRY_SIZE);
    got_address
}

fn allocate_tlvp(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let tlvp_address = NonZeroU64::new(*memory_offsets.get(part_id::TLVP)).unwrap();
    memory_offsets.increment(part_id::TLVP, GOT_ENTRY_SIZE);
    tlvp_address
}

fn allocate_plt(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let plt_address = NonZeroU64::new(*memory_offsets.get(part_id::PLT_GOT)).unwrap();
    memory_offsets.increment(part_id::PLT_GOT, PLT_ENTRY_SIZE);
    plt_address
}

const DEFAULT_SECTION_RULES: &[SectionRule<'static>] = &[
    // This is object-file linker metadata, not a section to copy into the final image. It must
    // remain visible to the graph loader so it can retain its LSDA and personality dependencies;
    // `macho_writer::write_compact_unwind_info` emits the final `__unwind_info` representation.
    SectionRule::exact(b"__compact_unwind", crate::layout_rules::SectionRuleOutcome::EhFrame),
];

fn section_header_name_for_segment<'data>(
    output_sections: &crate::output_section_id::OutputSections<'data, MachO>,
    section_id: OutputSectionId,
    segment_def: ProgramSegmentDef,
) -> Option<SectionName<'data>> {
    if !output_sections.will_emit_section(section_id) {
        return None;
    }

    output_sections
        .identity(section_id)
        .filter(|identity| identity.format_specific().is_some())
        .filter(|_| output_sections.should_include_in_segment(section_id, segment_def))
        .map(|identity| identity.section_name())
}

fn count_sections_for_segment(
    output_sections: &crate::output_section_id::OutputSections<MachO>,
    segment_def: ProgramSegmentDef,
) -> usize {
    output_sections
        .ids_with_info()
        .filter(|(section_id, _)| {
            section_header_name_for_segment(output_sections, *section_id, segment_def).is_some()
        })
        .count()
}

pub(crate) fn get_segment_sections<'data>(
    layout: &Layout<'data, MachO>,
    segment_id: ProgramSegmentId,
) -> Vec<(OutputRecordLayout, SectionName<'data>, SectionFlags)> {
    let mut in_matching_segment = false;
    let mut segment_sections = Vec::new();
    let segment_def = *layout.program_segments.segment_def(segment_id);

    for event in &layout.output_order {
        match event {
            OrderEvent::SegmentStart(seg_id) if seg_id == segment_id => {
                in_matching_segment = true;
            }
            OrderEvent::SegmentEnd(seg_id) if seg_id == segment_id && in_matching_segment => {
                break;
            }
            OrderEvent::Section(section_id) if in_matching_segment => {
                let Some(section_name) = section_header_name_for_segment(
                    &layout.output_sections,
                    section_id,
                    segment_def,
                ) else {
                    continue;
                };

                segment_sections.push((
                    *layout.merged_section_layouts.get(section_id),
                    section_name,
                    layout.output_sections.section_flags(section_id),
                ));
            }
            _ => {}
        }
    }

    segment_sections
}

fn add_sections_in_segment<'data>(
    builder: &mut OutputOrderBuilder<'_, 'data, MachO>,
    output_sections: &crate::output_section_id::OutputSections<'data, MachO>,
    sections: &[OutputSectionId],
    segment: SegmentName,
) {
    for &section_id in sections {
        if output_sections
            .identity(section_id)
            .is_some_and(|identity| identity.format_specific() == Some(segment))
        {
            builder.add_section(section_id);
        }
    }
}

fn add_named_sections_in_segment<'data>(
    builder: &mut OutputOrderBuilder<'_, 'data, MachO>,
    output_sections: &crate::output_section_id::OutputSections<'data, MachO>,
    sections: &[OutputSectionId],
    segment: SegmentName,
    section_name: &[u8],
) {
    for &section_id in sections {
        if output_sections.identity(section_id).is_some_and(|identity| {
            identity.format_specific() == Some(segment)
                && identity.section_name().0 == section_name
        }) {
            builder.add_section(section_id);
        }
    }
}

fn add_sections_in_segment_except<'data>(
    builder: &mut OutputOrderBuilder<'_, 'data, MachO>,
    output_sections: &crate::output_section_id::OutputSections<'data, MachO>,
    sections: &[OutputSectionId],
    segment: SegmentName,
    excluded_section_name: &[u8],
) {
    for &section_id in sections {
        if output_sections.identity(section_id).is_some_and(|identity| {
            identity.format_specific() == Some(segment)
                && identity.section_name().0 != excluded_section_name
        }) {
            builder.add_section(section_id);
        }
    }
}

#[inline(always)]
fn process_relocation<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    object: &layout::ObjectLayoutState<'data, MachO>,
    rel_info: object::macho::RelocationInfo,
    section_index: object::SectionIndex,
    resources: &'scope layout::GraphResources<'data, '_, MachO>,
    queue: &mut layout::LocalWorkQueue<MachO>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    // r_extern == true if the reference points to a symbol
    if rel_info.r_extern {
        let local_sym_index = SymbolIndex(rel_info.r_symbolnum as usize);
        let symbol_db = resources.symbol_db;
        let local_symbol_id = object.symbol_id_range.input_to_id(local_sym_index);
        let local_symbol = object.object.symbol(local_sym_index)?;
        let symbol_id = symbol_db.definition(local_symbol_id);
        let target_is_dynamic = is_dynamic_library(&symbol_db.file(symbol_db.file_id_for_symbol(symbol_id)));
        let objc_selector_dispatch = objc_message_selector(
            object.object.raw_symbol_name(local_sym_index)?,
        )
        .is_some();

        let mut flags = resources.local_flags_for_symbol(symbol_id);
        flags.merge(resources.local_flags_for_symbol(local_symbol_id));

        let relocation = A::relocation_from_raw(rel_info)?;
        // Record range-limited calls while the graph still knows their source section. The
        // generic thunk planner decides after GC whether this particular call can remain direct
        // and, if not, assigns a nearby `__TEXT,__text` island to its owning object.
        if !objc_selector_dispatch {
            crate::thunks::handle_thunk_extensions_for_relocation::<A>(
                object.section_part_id(section_index, &resources.symbol_db.section_part_ids),
                resources,
                local_symbol_id,
                symbol_id,
                rel_info,
            );
        }
        let mut flags_to_add = layout::resolution_flags(relocation.kind);
        if target_is_dynamic {
            flags_to_add |= if local_symbol.is_weak_reference() {
                ValueFlags::WEAK_REFERENCE
            } else {
                ValueFlags::STRONG_REFERENCE
            };
            if matches!(
                rel_info.r_type,
                object::macho::ARM64_RELOC_TLVP_LOAD_PAGE21
                    | object::macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12
            ) {
                // The imported value is the dylib's `__thread_vars` descriptor. Unlike an
                // ordinary dynamic address it must remain a TLVP load through a dedicated
                // `__thread_ptrs` slot, whose chained bind dyld fills at load time.
                flags_to_add.remove(ValueFlags::DIRECT);
                flags_to_add |= ValueFlags::GOT_TLS_DESCRIPTOR;
            } else {
                flags_to_add |= ValueFlags::GOT;
            }
            // TODO: classify symbols more reliably, likely by checking whether their section is
            // __text.
            if (rel_info.r_type == object::macho::ARM64_RELOC_BRANCH26 && !objc_selector_dispatch)
                // A local TLS descriptor stores this libSystem function pointer directly. Make
                // it point at the normal PLT stub so its chained GOT bind remains callable.
                || (rel_info.r_type == object::macho::ARM64_RELOC_UNSIGNED
                    && symbol_db.symbol_name(symbol_id)?.bytes() == b"__tlv_bootstrap")
            {
                flags_to_add |= ValueFlags::FUNCTION | ValueFlags::PLT;
            }
        }

        let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
        let previous_flags = atomic_flags.fetch_or(flags_to_add);

        layout::check_for_undefined::<A>(
            object,
            object.object.section(section_index)?,
            rel_info.r_address.into(),
            local_sym_index,
            flags,
            symbol_id,
            resources,
        )?;

        if !previous_flags.has_resolution() {
            queue.send_symbol_request::<A>(symbol_id, resources, scope);
        }
    }

    Ok(())
}

/// Records the graph edges implied by a normalized ARM64 relocation. The unsigned half of a
/// subtractor pair is still an ordinary direct-address dependency, but its companion names a
/// second atom which must survive dead stripping even though it has no independent relocation
/// storage. Keep that second edge here, before addresses are assigned, rather than trying to
/// reconstruct it in the writer after GC has already made its decision.
#[inline(always)]
fn process_normalized_relocation<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    object: &layout::ObjectLayoutState<'data, MachO>,
    relocation: NormalizedRelocation,
    section_index: object::SectionIndex,
    resources: &'scope layout::GraphResources<'data, '_, MachO>,
    queue: &mut layout::LocalWorkQueue<MachO>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    if let Some(subtractor) = relocation.subtractor {
        validate_subtractor_pair_targets(object, relocation.info, subtractor, resources)?;
    }
    process_relocation::<A>(
        object,
        relocation.info,
        section_index,
        resources,
        queue,
        scope,
    )?;
    if let Some(subtractor) = relocation.subtractor {
        process_subtractor_target::<A>(object, subtractor, section_index, resources, queue, scope)?;
    }
    Ok(())
}

/// An ARM64 subtractor expression is fixed at static-link time. In particular, neither operand
/// can be a dyld import or a weak import whose final address would be selected by dyld.
fn validate_subtractor_pair_targets(
    object: &layout::ObjectLayoutState<'_, MachO>,
    minuend: object::macho::RelocationInfo,
    subtrahend: object::macho::RelocationInfo,
    resources: &layout::GraphResources<'_, '_, MachO>,
) -> Result {
    for (role, rel) in [("minuend", minuend), ("subtrahend", subtrahend)] {
        let local_symbol_index = SymbolIndex(rel.r_symbolnum as usize);
        let local_symbol = object.object.symbol(local_symbol_index)?;
        let symbol_id = resources
            .symbol_db
            .definition(object.symbol_id_range.input_to_id(local_symbol_index));
        ensure!(
            !local_symbol.is_weak_reference(),
            "ARM64_RELOC_SUBTRACTOR {role} cannot be a weak import"
        );
        ensure!(
            !is_dynamic_library(
                &resources
                    .symbol_db
                    .file(resources.symbol_db.file_id_for_symbol(symbol_id))
            ),
            "ARM64_RELOC_SUBTRACTOR {role} cannot be supplied by a dylib"
        );
    }
    Ok(())
}

/// Records the subtractor half of a validated pair as a direct graph dependency without ever
/// presenting its standalone relocation opcode to the architecture converter or writer.
fn process_subtractor_target<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    object: &layout::ObjectLayoutState<'data, MachO>,
    rel_info: object::macho::RelocationInfo,
    section_index: object::SectionIndex,
    resources: &'scope layout::GraphResources<'data, '_, MachO>,
    queue: &mut layout::LocalWorkQueue<MachO>,
    scope: &rayon::Scope<'scope>,
) -> Result {
    let local_symbol_index = SymbolIndex(rel_info.r_symbolnum as usize);
    let local_symbol_id = object.symbol_id_range.input_to_id(local_symbol_index);
    let symbol_id = resources.symbol_db.definition(local_symbol_id);
    let mut flags = resources.local_flags_for_symbol(symbol_id);
    flags.merge(resources.local_flags_for_symbol(local_symbol_id));

    let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
    let previous_flags = atomic_flags.fetch_or(ValueFlags::DIRECT);
    layout::check_for_undefined::<A>(
        object,
        object.object.section(section_index)?,
        rel_info.r_address.into(),
        local_symbol_index,
        flags,
        symbol_id,
        resources,
    )?;
    if !previous_flags.has_resolution() {
        queue.send_symbol_request::<A>(symbol_id, resources, scope);
    }
    Ok(())
}

/// During ordinary executable linking Mach-O exports public object definitions. Under
/// `-dead_strip`, that policy must run *after* atom liveness is known: making every external
/// definition a root first would retain the very atoms dead stripping is meant to discard.
fn export_live_symbols_in_section<'data>(
    object: &layout::ObjectLayoutState<'data, MachO>,
    common: &mut layout::CommonGroupState<'data, MachO>,
    resources: &layout::GraphResources<'data, '_, MachO>,
    section_index: object::SectionIndex,
    atom: Option<&Range<u64>>,
) -> Result {
    if !resources.symbol_db.args.should_gc_sections()
        || !resources.symbol_db.output_kind.is_executable()
        || resources.symbol_db.export_list.is_some()
    {
        return Ok(());
    }

    for exported_symbol in object
        .object
        .exported_symbols_in_range(section_index, atom)?
    {
        let symbol_id = object
            .symbol_id_range
            .input_to_id(exported_symbol.symbol_index);
        if !resources.symbol_db.is_canonical(symbol_id) {
            continue;
        }
        let old_flags = resources
            .per_symbol_flags
            .get_atomic(symbol_id)
            .fetch_or(ValueFlags::EXPORT_DYNAMIC);
        if !old_flags.needs_export_dynamic() {
            layout::export_dynamic(common, symbol_id, resources.symbol_db)?;
        }
    }

    Ok(())
}

fn is_dynamic_library(file: &SequencedInput<MachO>) -> bool {
    match file {
        SequencedInput::StubLibrary(_) => true,
        SequencedInput::Object(obj) => obj.is_dynamic(),
        _ => false,
    }
}

/// Finds the live Clang ARM64 selector-send references in one object after graph loading.
///
/// The input's synthetic `_objc_msgSend$selector` symbol is deliberately not put in the final
/// symbol database: it aliases `_objc_msgSend` for ordinary dylib resolution. Preserve its input
/// identity here so the writer can replace precisely its `BRANCH26` relocation with the local
/// selector-loading stub. `__objc_methname` owns the selector spelling that the companion
/// `__objc_selrefs` slot must point at.
fn objc_message_references_for_object<'data>(
    object: &layout::ObjectLayoutState<'data, MachO>,
) -> Result<Vec<(ObjcMessageSymbol, &'data [u8], ObjcMessageSymbol)>> {
    let mut references = Vec::new();

    for (section_index, slot) in object.sections.iter().enumerate() {
        if !matches!(slot, resolution::SectionSlot::Loaded(_)) {
            continue;
        }
        let section_index = object::SectionIndex(section_index);
        for relocation in paired_relocations(object.relocations(section_index)?.relocations) {
            let relocation = relocation?;
            let info = relocation.info;
            if !info.r_extern
                || info.r_type != macho::ARM64_RELOC_BRANCH26
                || !object.input_offset_is_live(section_index, u64::from(info.r_address))
            {
                continue;
            }

            let message_symbol = ObjcMessageSymbol {
                file_id: object.file_id,
                symbol: info.r_symbolnum as usize,
            };
            let Some(selector) = objc_message_selector(
                object.object.raw_symbol_name(SymbolIndex(message_symbol.symbol))?,
            )
            else {
                continue;
            };
            let selector_symbol = objc_selector_symbol(object.object, selector)?.with_context(|| {
                format!(
                    "Mach-O Objective-C selector {} has no matching symbol in __objc_methname for {}",
                    String::from_utf8_lossy(selector),
                    object.input
                )
            })?;
            let selector_symbol = ObjcMessageSymbol {
                file_id: object.file_id,
                symbol: selector_symbol.0,
            };
            let reference = (message_symbol, selector, selector_symbol);
            if !references.contains(&reference) {
                references.push(reference);
            }
        }
    }

    Ok(references)
}

/// Finds the named `__objc_methname` string that backs one synthetic selector-send symbol.
/// A selector slot must refer to the same input string as Objective-C method metadata; accepting
/// a substring would produce a valid-looking pointer that libobjc cannot canonicalise.
fn objc_selector_symbol(file: &File<'_>, selector: &[u8]) -> Result<Option<SymbolIndex>> {
    for (symbol_index, symbol) in file.enumerate_symbols() {
        let Some(section_index) = file.symbol_section(symbol, symbol_index)? else {
            continue;
        };
        let section = file.section(section_index)?;
        if section.name() != b"__objc_methname" {
            continue;
        }
        let offset = usize::try_from(file.symbol_offset_in_section(symbol, section_index)?)
            .context("Mach-O Objective-C selector offset does not fit usize")?;
        let data = file.raw_section_data(section)?;
        let Some(end) = data.get(offset..).and_then(|tail| tail.iter().position(|&byte| byte == 0))
        else {
            continue;
        };
        if data[offset..offset + end] == *selector {
            return Ok(Some(symbol_index));
        }
    }
    Ok(None)
}

impl<'data> File<'data> {
    /// Returns a supported compilation-unit path recorded in ordinary DWARF, if this object is
    /// in the intentionally narrow debug-map subset. DWARF relocations are not applied here:
    /// extracting `DW_AT_language` and `DW_AT_name` does not need code addresses, and applying
    /// them during layout could make otherwise dead atoms live.
    ///
    /// ARM64 `macho/rust-debug-dwarf` establishes the Rust half of this contract with the exact
    /// `nightly-2026-07-24` toolchain. `macho/cxx-debug-dwarf` and `macho/objc-debug-dwarf`
    /// establish exactly `DW_LANG_C_plus_plus_14` and `DW_LANG_ObjC`, respectively. Keep other
    /// language forms out until their map and `dsymutil` behavior have comparable controls.
    fn debug_map_source_path(&self) -> Result<Option<Vec<u8>>> {
        let dwarf_sections = gimli::DwarfSections::load(&|id: gimli::SectionId| -> Result<Cow<[u8]>> {
            // Mach-O spells DWARF section names with two leading underscores, while gimli uses
            // their ELF spelling (for example `.debug_info`).
            let section_name = format!("__{}", id.name().trim_start_matches('.'));
            let data = self
                .section_by_name(&section_name)
                .map_or(Ok(&[][..]), |(_, section)| self.raw_section_data(section))?;
            Ok(Cow::Borrowed(data))
        })?;
        let borrow_section: &dyn for<'a> Fn(
            &'a Cow<[u8]>,
        ) -> gimli::EndianSlice<'a, gimli::LittleEndian> =
            &|section| gimli::EndianSlice::new(section, gimli::LittleEndian);
        let dwarf = dwarf_sections.borrow(borrow_section);

        let mut units = dwarf.units();
        let Some(header) = units.next()? else {
            return Ok(None);
        };
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        let Some(root) = entries.next_dfs()? else {
            return Ok(None);
        };
        if root.tag() != gimli::DW_TAG_compile_unit {
            return Ok(None);
        }
        let Some(gimli::AttributeValue::Language(language)) =
            root.attr_value(gimli::DW_AT_language)
        else {
            return Ok(None);
        };
        if !matches!(
            language,
            gimli::DW_LANG_C89
                | gimli::DW_LANG_C
                | gimli::DW_LANG_C99
                | gimli::DW_LANG_C11
                | gimli::DW_LANG_C17
                | gimli::DW_LANG_Rust
                | gimli::DW_LANG_C_plus_plus_14
                | gimli::DW_LANG_ObjC
        ) {
            return Ok(None);
        }
        let Some(name) = root.attr_value(gimli::DW_AT_name) else {
            return Ok(None);
        };
        Ok(Some(dwarf.attr_string(&unit, name)?.to_slice()?.into_owned()))
    }

    /// Builds the `N_SO`/`N_OSO`/`N_FUN` payload for a supported loose input object. This only
    /// names live, loaded executable atoms: merged sections have no linear input-to-output
    /// mapping and unloaded/dead atoms must not get an address in the debug map.
    pub(crate) fn dsymutil_debug_map(
        &'data self,
        sections: &[resolution::SectionSlot],
        mut input_offset_is_live: impl FnMut(object::SectionIndex, u64) -> bool,
    ) -> Result<Option<DsymutilDebugMap<'data>>> {
        if !self.uses_subsections_via_symbols() {
            return Ok(None);
        }
        let Some(source_path) = self.debug_map_source_path()? else {
            return Ok(None);
        };

        let mut functions = Vec::new();
        let mut emitted_atoms = BTreeSet::new();
        for (symbol_index, symbol) in self.enumerate_symbols() {
            if symbol.n_type.is_stab() || symbol.n_type.typ() != N_SECT {
                continue;
            }
            let Some((section_index, atom_range)) = self.atom_for_symbol(symbol, symbol_index)?
            else {
                continue;
            };
            let section = self.section(section_index)?;
            if !section.is_executable()
                || !matches!(sections.get(section_index.0), Some(resolution::SectionSlot::Loaded(_)))
                || !input_offset_is_live(section_index, atom_range.start)
                || atom_range.is_empty()
            {
                continue;
            }
            let name = self.symbol_name(symbol)?;
            // `ltmp` marks compiler section labels rather than user functions. It shares the
            // first function atom on clang-generated C inputs, so omitting it before de-duping
            // lets the function symbol own that atom's dSYM mapping.
            if name.is_empty() || name.starts_with(b"ltmp") {
                continue;
            }
            if !emitted_atoms.insert((section_index.0, atom_range.start)) {
                continue;
            }
            functions.push(DsymutilDebugMapFunction {
                name,
                section_index,
                input_offset: atom_range.start,
                input_size: atom_range.end - atom_range.start,
            });
        }

        if functions.is_empty() {
            return Ok(None);
        }
        Ok(Some(DsymutilDebugMap {
            source_path,
            functions,
        }))
    }

    fn uses_subsections_via_symbols(&self) -> bool {
        self.flags.0 & macho::MH_SUBSECTIONS_VIA_SYMBOLS.0 != 0
    }

    /// Returns the atom containing `symbol`. Leading bytes are owned by the first symbol atom and
    /// trailing bytes by the last one, matching ld64's useful conservative interpretation of
    /// section labels. Symbols sharing an address are aliases of the same atom. A section symbol
    /// at its end becomes a zero-sized atom, so referencing it has a stable end-of-section
    /// address without inventing data to copy.
    fn atom_for_symbol(
        &self,
        symbol: &SymtabEntry,
        symbol_index: object::SymbolIndex,
    ) -> Result<Option<(object::SectionIndex, Range<u64>)>> {
        if !self.uses_subsections_via_symbols() {
            return Ok(None);
        }
        let Some(section_index) = self.symbol_section(symbol, symbol_index)? else {
            return Ok(None);
        };
        // C-string sections are represented by the generic string-merging pool, which already
        // owns their non-linear input-to-output mapping. Keep that path whole-section until the
        // merger itself has an atom-aware liveness model.
        if self.section(section_index)?.is_merge_section() {
            return Ok(None);
        }
        let start = self.symbol_offset_in_section(symbol, section_index)?;
        let range = self.atom_range(section_index, start)?;
        Ok(Some((section_index, range)))
    }

    fn atom_range(
        &self,
        section_index: object::SectionIndex,
        start: u64,
    ) -> Result<Range<u64>> {
        let section = self.section(section_index)?;
        let section_size = self.section_size(section)?;
        let starts = self.atom_starts(section_index)?;
        // The synthetic zero boundary gives the first symbol ownership of any leading bytes.
        // Later atoms begin at real symbol boundaries. This also accepts aliases without
        // allocating a separate atom for every symbol table entry at the same address.
        let mut start_index = starts
            .partition_point(|candidate| *candidate <= start)
            .checked_sub(1)
            .context("Mach-O symbol is before the start of its section")?;
        // A symbol exactly at section end is a zero-size label. Keep the preceding atom instead
        // of creating an empty output fragment: it gives the label the compacted end address and
        // conservatively retains the bytes that establish that address.
        if start == section_size && starts.get(start_index) == Some(&section_size) && start_index > 0
        {
            start_index -= 1;
        }
        let end = starts.get(start_index + 1).copied().unwrap_or(section_size);
        Ok(start..end)
    }

    fn atom_starts(&self, section_index: object::SectionIndex) -> Result<&[u64]> {
        let ObjectKind::Regular(regular) = &self.kind else {
            bail!("dynamic Mach-O input has no subsection atoms");
        };
        Ok(regular
            .atom_starts
            .get(section_index.0)
            .map(Vec::as_slice)
            .context("Mach-O subsection atom section index out of range")?)
    }

    /// Returns the public definitions that belong to one live input range. Atom-level dead
    /// stripping supplies that range for `MH_SUBSECTIONS_VIA_SYMBOLS` inputs; section-level
    /// liveness passes `None` and receives every public definition in the section.
    fn exported_symbols_in_range(
        &self,
        section_index: object::SectionIndex,
        range: Option<&Range<u64>>,
    ) -> Result<&[ExportedSymbol]> {
        let ObjectKind::Regular(regular) = &self.kind else {
            bail!("dynamic Mach-O input has no public dead-strip export index");
        };
        let symbols = regular
            .exported_symbols_by_section
            .get(section_index.0)
            .context("Mach-O export symbol section index out of range")?;
        Ok(exported_symbols_in_range(symbols, range))
    }

    /// Builds the structural part of `export_live_symbols_in_section` once, while parsing an
    /// immutable object. Canonical-definition checks remain in graph traversal because they are
    /// a property of the complete input set, not this one object.
    fn compute_exported_symbols_by_section(&self) -> Result<Vec<Vec<ExportedSymbol>>> {
        let mut exported_symbols_by_section = vec![Vec::new(); self.sections().len()];
        for (symbol_index, symbol) in self.enumerate_symbols() {
            if platform::Symbol::is_undefined(symbol)
                || symbol.is_local()
                || symbol.visibility() != Visibility::Default
            {
                continue;
            }
            let Some(section_index) = self.symbol_section(symbol, symbol_index)? else {
                continue;
            };
            let input_offset = self.symbol_offset_in_section(symbol, section_index)?;
            exported_symbols_by_section
                .get_mut(section_index.0)
                .context("Mach-O export symbol section index out of range")?
                .push(ExportedSymbol {
                    input_offset,
                    symbol_index,
                });
        }
        for exported_symbols in &mut exported_symbols_by_section {
            exported_symbols.sort_by_key(|symbol| symbol.input_offset);
        }
        Ok(exported_symbols_by_section)
    }

    fn compute_atom_starts(&self) -> Result<Vec<Vec<u64>>> {
        let mut all_starts = vec![vec![0]; self.sections().len()];
        for (symbol_index, symbol) in self.enumerate_symbols() {
            let Some(section_index) = self.symbol_section(symbol, symbol_index)? else {
                continue;
            };
            let starts = all_starts
                .get_mut(section_index.0)
                .context("Mach-O symbol section index out of range while forming dead-strip atoms")?;
            let section = self.section(section_index)?;
            let section_size = self.section_size(section)?;
            let offset = self.symbol_offset_in_section(symbol, section_index)?;
            ensure!(
                offset <= section_size,
                "Mach-O symbol lies past the end of its section while forming dead-strip atoms"
            );
            starts.push(offset);
        }

        // Do not create an atom boundary through a relocation field. The relocation belongs to
        // the atom containing its first byte, but its storage must remain contiguous even when a
        // symbol labels the middle of a pointer or instruction operand. Merging those boundaries
        // is conservative and avoids silently patching a dead neighbouring atom.
        for (section_index, section) in self.enumerate_sections() {
            let section_size = self.section_size(section)?;
            let starts = &mut all_starts[section_index.0];
            starts.sort_unstable();
            starts.dedup();
            for relocation in paired_relocations(self.relocations(section_index, &())?.relocations) {
                let relocation = relocation?;
                let relocation_start = u64::from(relocation.info.r_address);
                let width = 1u64
                    .checked_shl(u32::from(relocation.info.r_length))
                    .context("Mach-O relocation width is invalid")?;
                let relocation_end = relocation_start
                    .checked_add(width)
                    .context("Mach-O relocation range overflows")?;
                ensure!(
                    relocation_end <= section_size,
                    "Mach-O relocation extends past the end of its section"
                );
                starts.retain(|boundary| {
                    *boundary == 0 || !(*boundary > relocation_start && *boundary < relocation_end)
                });
            }
        }
        Ok(all_starts)
    }

    fn sections(&self) -> &'data [SectionHeader] {
        self.kind.sections()
    }
}

impl<'data> ObjectKind<'data> {
    fn sections(&self) -> &'data [SectionHeader] {
        match self {
            ObjectKind::Regular(regular_object) => regular_object.sections,
            ObjectKind::Dylib(_) => &[],
        }
    }
}

impl DynamicLayoutStateExt {
    fn new(args: &MachOArgs, metadata: DylibMetadata<'_>) -> Self {
        Self {
            imported_symbols: Default::default(),
            // Even an otherwise unreferenced executable must retain libSystem. dyld requires an
            // LC_LOAD_DYLIB for it before launching the main image; `-dead_strip_dylibs` may
            // remove ordinary unused dependencies but cannot turn a valid executable into one
            // dyld rejects before its entry point.
            loaded: !args.dead_strip_dylibs
                || metadata.install_name == b"/usr/lib/libSystem.B.dylib",
        }
    }
}

impl SinglePartSectionId {
    const fn part_id(self) -> PartId {
        PartId::from_u32(self as u32)
    }

    const fn output_section_id(self) -> OutputSectionId {
        OutputSectionId::from_u32(self as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::RelocationModel;
    use crate::output_kind::OutputKind;
    use crate::output_section_id::OutputSections;

    #[test]
    fn exported_symbol_index_selects_only_the_live_atom_range() {
        let symbols = [
            ExportedSymbol {
                input_offset: 0,
                symbol_index: SymbolIndex(8),
            },
            ExportedSymbol {
                input_offset: 4,
                symbol_index: SymbolIndex(3),
            },
            ExportedSymbol {
                input_offset: 4,
                symbol_index: SymbolIndex(7),
            },
            ExportedSymbol {
                input_offset: 16,
                symbol_index: SymbolIndex(1),
            },
        ];

        let atom = 4..16;
        assert_eq!(
            exported_symbols_in_range(&symbols, Some(&atom))
                .iter()
                .map(|symbol| symbol.symbol_index.0)
                .collect_vec(),
            vec![3, 7]
        );
        assert_eq!(
            exported_symbols_in_range(&symbols, None)
                .iter()
                .map(|symbol| symbol.symbol_index.0)
                .collect_vec(),
            vec![8, 3, 7, 1]
        );
    }

    /// Builds the smallest regular ARM64 Mach-O object with one indirect-symbol-backed section.
    /// Clang intentionally does not produce these sections for a relocatable object, so retain a
    /// byte-level fixture for the pre-bound-input boundary instead of relying on an Apple SDK
    /// image or a particular linker version.
    fn indirect_symbol_object(section_type: macho::SectionType) -> Vec<u8> {
        const HEADER_SIZE: usize = 32;
        const SEGMENT_COMMAND_SIZE: usize = 72;
        const SECTION_SIZE: usize = 80;
        const DYSYMTAB_SIZE: usize = 80;
        const SYMTAB_SIZE: usize = 24;
        const SECTION_HEADER_OFFSET: usize = HEADER_SIZE + SEGMENT_COMMAND_SIZE;
        const DYSYMTAB_OFFSET: usize = HEADER_SIZE + SEGMENT_COMMAND_SIZE + SECTION_SIZE;
        const SYMTAB_OFFSET: usize = DYSYMTAB_OFFSET + DYSYMTAB_SIZE;
        const SECTION_DATA_OFFSET: usize = SYMTAB_OFFSET + SYMTAB_SIZE;

        let (section_name, segment_name, entry_size) = match section_type {
            macho::S_NON_LAZY_SYMBOL_POINTERS => {
                (b"__nl_symbol_ptr".as_slice(), b"__DATA".as_slice(), GOT_ENTRY_SIZE)
            }
            macho::S_LAZY_SYMBOL_POINTERS => {
                (b"__la_symbol_ptr".as_slice(), b"__DATA".as_slice(), GOT_ENTRY_SIZE)
            }
            macho::S_SYMBOL_STUBS => (b"__stubs".as_slice(), b"__TEXT".as_slice(), PLT_ENTRY_SIZE),
            macho::S_LAZY_DYLIB_SYMBOL_POINTERS => {
                (b"__la_dylib_ptr".as_slice(), b"__DATA".as_slice(), GOT_ENTRY_SIZE)
            }
            macho::S_THREAD_LOCAL_VARIABLE_POINTERS => {
                (b"__thread_ptrs".as_slice(), b"__DATA".as_slice(), GOT_ENTRY_SIZE)
            }
            _ => panic!("fixture requires an indirect-symbol-backed section type"),
        };
        let section_size = usize::try_from(entry_size).unwrap();
        let indirect_symbol_offset = SECTION_DATA_OFFSET + section_size;
        let symbol_offset = indirect_symbol_offset + size_of::<u32>();
        let string_offset = symbol_offset + size_of::<RawSymtabEntry>();
        let mut data = vec![0; string_offset + 1];

        let put_u32 = |data: &mut [u8], offset: usize, value: u32| {
            data[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
        };
        let put_u64 = |data: &mut [u8], offset: usize, value: u64| {
            data[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
        };

        // mach_header_64
        put_u32(&mut data, 0, macho::MH_MAGIC_64);
        put_u32(&mut data, 4, macho::CPU_TYPE_ARM64.0);
        put_u32(&mut data, 12, macho::MH_OBJECT.0);
        put_u32(&mut data, 16, 3);
        put_u32(
            &mut data,
            20,
            u32::try_from(SEGMENT_COMMAND_SIZE + SECTION_SIZE + DYSYMTAB_SIZE + SYMTAB_SIZE)
                .unwrap(),
        );

        // LC_SEGMENT_64 with one section. MH_OBJECT uses one compact unnamed segment.
        put_u32(&mut data, HEADER_SIZE, macho::LC_SEGMENT_64.0);
        put_u32(
            &mut data,
            HEADER_SIZE + 4,
            u32::try_from(SEGMENT_COMMAND_SIZE + SECTION_SIZE).unwrap(),
        );
        put_u64(
            &mut data,
            HEADER_SIZE + 40,
            u64::try_from(SECTION_DATA_OFFSET).unwrap(),
        );
        put_u64(
            &mut data,
            HEADER_SIZE + 48,
            u64::try_from(section_size).unwrap(),
        );
        put_u32(&mut data, HEADER_SIZE + 64, 1);

        // section_64. All five types use one indexed entry; stubs alone use reserved2 for their
        // entry size. The one index targets the sole undefined nlist below.
        data[SECTION_HEADER_OFFSET..SECTION_HEADER_OFFSET + section_name.len()]
            .copy_from_slice(section_name);
        data[SECTION_HEADER_OFFSET + 16..SECTION_HEADER_OFFSET + 16 + segment_name.len()]
            .copy_from_slice(segment_name);
        put_u64(
            &mut data,
            SECTION_HEADER_OFFSET + 40,
            u64::try_from(section_size).unwrap(),
        );
        put_u32(
            &mut data,
            SECTION_HEADER_OFFSET + 48,
            u32::try_from(SECTION_DATA_OFFSET).unwrap(),
        );
        put_u32(&mut data, SECTION_HEADER_OFFSET + 52, 3);
        put_u32(&mut data, SECTION_HEADER_OFFSET + 64, u32::from(section_type.0));
        put_u32(
            &mut data,
            SECTION_HEADER_OFFSET + 72,
            u32::try_from(entry_size).unwrap(),
        );

        // LC_DYSYMTAB's indirect-symbol table and the matching LC_SYMTAB.
        put_u32(&mut data, DYSYMTAB_OFFSET, macho::LC_DYSYMTAB.0);
        put_u32(
            &mut data,
            DYSYMTAB_OFFSET + 4,
            u32::try_from(DYSYMTAB_SIZE).unwrap(),
        );
        put_u32(
            &mut data,
            DYSYMTAB_OFFSET + 56,
            u32::try_from(indirect_symbol_offset).unwrap(),
        );
        put_u32(&mut data, DYSYMTAB_OFFSET + 60, 1);
        put_u32(&mut data, SYMTAB_OFFSET, macho::LC_SYMTAB.0);
        put_u32(
            &mut data,
            SYMTAB_OFFSET + 4,
            u32::try_from(SYMTAB_SIZE).unwrap(),
        );
        put_u32(
            &mut data,
            SYMTAB_OFFSET + 8,
            u32::try_from(symbol_offset).unwrap(),
        );
        put_u32(&mut data, SYMTAB_OFFSET + 12, 1);
        put_u32(
            &mut data,
            SYMTAB_OFFSET + 16,
            u32::try_from(string_offset).unwrap(),
        );
        put_u32(&mut data, SYMTAB_OFFSET + 20, 1);

        // nlist_64[0] is an external undefined symbol. The indirect entry at
        // `indirect_symbol_offset` is already zero, so it names this nlist.
        data[symbol_offset + 4] = macho::N_UNDF.0 | macho::N_EXT.0;
        data
    }

    #[test]
    fn malformed_object_header_is_rejected_before_layout() {
        // File detection routes a Mach-O candidate into this parser before any layout state is
        // created. Keep truncated input a normal diagnostic rather than allowing malformed bytes
        // to reach the linker graph.
        let error = match <File<'_> as platform::ObjectFile>::parse_bytes(&[], false) {
            Ok(_) => panic!("an empty Mach-O object must not parse"),
            Err(error) => error,
        };

        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn indirect_symbol_sections_are_rejected_before_layout() {
        // These are final-image dyld structures, not regular Clang relocation sections. Test
        // every supported Mach-O spelling so a future SectionHeader classification change cannot
        // make one disappear silently again.
        for (section_type, section_type_name) in [
            (macho::S_NON_LAZY_SYMBOL_POINTERS, "S_NON_LAZY_SYMBOL_POINTERS"),
            (macho::S_LAZY_SYMBOL_POINTERS, "S_LAZY_SYMBOL_POINTERS"),
            (macho::S_SYMBOL_STUBS, "S_SYMBOL_STUBS"),
            (
                macho::S_LAZY_DYLIB_SYMBOL_POINTERS,
                "S_LAZY_DYLIB_SYMBOL_POINTERS",
            ),
            (
                macho::S_THREAD_LOCAL_VARIABLE_POINTERS,
                "S_THREAD_LOCAL_VARIABLE_POINTERS",
            ),
        ] {
            let object = indirect_symbol_object(section_type);
            let header = macho::MachHeader64::<Endianness>::parse(&*object, 0).unwrap();
            let mut commands = header.load_commands(LE, &*object, 0).unwrap();
            let command = commands.next().unwrap().unwrap();
            let (segment, segment_data) = command.segment_64().unwrap().unwrap();
            let section = &segment.sections(LE, segment_data).unwrap()[0];
            assert!(
                !section.should_exclude(),
                "{section_type_name} must not disappear during section resolution"
            );

            let error =
                <File<'_> as platform::ObjectFile>::parse_bytes(&object, false).unwrap_err();
            let message = error.to_string();
            assert!(message.contains(section_type_name), "{message}");
            assert!(message.contains("already-linked indirect-symbol table format"), "{message}");
        }
    }

    #[test]
    fn malformed_indirect_symbol_section_reports_its_missing_table_entry() {
        let mut object = indirect_symbol_object(macho::S_NON_LAZY_SYMBOL_POINTERS);
        // LC_DYSYMTAB says it has no indirect entries, while the section still has one pointer.
        // This must report the broken structural contract rather than falling through to the
        // generic unsupported-input message.
        const DYSYMTAB_INDIRECT_SYMBOL_COUNT_OFFSET: usize = 32 + 72 + 80 + 60;
        object[DYSYMTAB_INDIRECT_SYMBOL_COUNT_OFFSET..DYSYMTAB_INDIRECT_SYMBOL_COUNT_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());

        let error = <File<'_> as platform::ObjectFile>::parse_bytes(&object, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires indirect-symbol entries 0..1, but LC_DYSYMTAB has only 0")
        );
    }

    #[test]
    fn malformed_indirect_symbol_section_reports_its_out_of_range_symbol() {
        let mut object = indirect_symbol_object(macho::S_NON_LAZY_SYMBOL_POINTERS);
        // The sole table entry follows an eight-byte non-lazy pointer. It must name the sole
        // nlist (index zero), so index one proves that every indirect entry is checked before the
        // unsupported-input diagnostic is issued.
        const INDIRECT_SYMBOL_OFFSET: usize = 32 + 72 + 80 + 80 + 24 + 8;
        object[INDIRECT_SYMBOL_OFFSET..INDIRECT_SYMBOL_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());

        let error = <File<'_> as platform::ObjectFile>::parse_bytes(&object, false).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains(
                "indirect-symbol entry 0 refers to symbol 1, but the symbol table has only 1 entries"
            ),
            "{message}"
        );
    }

    #[test]
    fn eh_frame_zplr_reports_relocation_storage() {
        // One DWARF32 CIE with `zPLR`, then an FDE referring back to it. Keep this byte-level
        // regression independent of a Rust toolchain so malformed length/LEB handling is caught
        // before a real object reaches the compact-unwind metadata path.
        let mut data = vec![
            24, 0, 0, 0, // CIE length
            0, 0, 0, 0, // CIE marker
            1, b'z', b'P', b'L', b'R', 0, 1, 0x78, 30, 7, 0x9b,
            0, 0, 0, 0, // personality pointer relocation storage
            0x10, 0x10, 0x0c, 0x1f, 0,
            29, 0, 0, 0, // FDE length
            32, 0, 0, 0, // CIE pointer: (FDE + 4) - CIE
        ];
        data.extend_from_slice(&[0; 16]); // function and range
        data.push(8); // FDE augmentation size
        data.extend_from_slice(&[0; 8]); // LSDA relocation storage
        data.extend_from_slice(&[0; 4]); // final zero-length record

        assert_eq!(
            eh_frame_augmentations(&data).unwrap(),
            vec![EhFrameAugmentation {
                function_relocation_offset: 36,
                personality_relocation_offset: 19,
                lsda_relocation_offset: 53,
            }]
        );

        let records = parse_eh_frame_records(&data).unwrap();
        assert_eq!(records.cies.len(), 1);
        assert_eq!(records.fdes.len(), 1);
        assert_eq!(
            records.fdes[0],
            EhFrameFde {
                record_range: 28..61,
                cie_record_start: 0,
                function_relocation_offset: 36,
                lsda_relocation_offset: Some(53),
            }
        );
    }

    #[test]
    fn eh_frame_zr_retains_an_fde_without_personality_or_lsda() {
        // The first CIE in a rustc object is commonly `zR`: it describes ordinary functions
        // that have no personality or LSDA. It still needs a final FDE because compact unwind's
        // DWARF mode delegates recovery to this table.
        let mut data = vec![
            13, 0, 0, 0, // CIE length
            0, 0, 0, 0, // CIE marker
            1, b'z', b'R', 0, 1, 0x78, 30, 1, 0x10,
            21, 0, 0, 0, // FDE length
            21, 0, 0, 0, // CIE pointer: (FDE + 4) - CIE
        ];
        data.extend_from_slice(&[0; 16]); // function and range
        data.push(0); // FDE augmentation size
        data.extend_from_slice(&[0; 4]); // final zero-length record

        let records = parse_eh_frame_records(&data).unwrap();
        assert_eq!(records.cies[&0].personality_relocation_offset, None);
        assert_eq!(records.fdes.len(), 1);
        assert_eq!(records.fdes[0].lsda_relocation_offset, None);
        assert!(eh_frame_augmentations(&data).unwrap().is_empty());
    }

    #[test]
    fn regular_text_section_requires_the_text_segment_identity() {
        let mut output_sections = OutputSections::<MachO>::with_base_address(
            MACHO_START_MEM_ADDRESS,
            OutputKind::StaticExecutable(RelocationModel::NonRelocatable),
        );
        let text_identity = SectionIdentity::new(SectionName(b"__text"), Some(SegmentName::TEXT));
        let text_id = output_sections.add_named_section(
            text_identity,
            Alignment { exponent: 2 },
            None,
            None,
            None,
            Vec::new(),
            None,
        );
        assert_eq!(text_id, output_section_id::TEXT);

        let data_identity = SectionIdentity::new(SectionName(b"__text"), Some(SegmentName::DATA));
        let data_id = output_sections.add_named_section(
            data_identity,
            Alignment { exponent: 2 },
            None,
            None,
            None,
            Vec::new(),
            None,
        );
        assert_ne!(data_id, output_section_id::TEXT);
        assert!(data_id.is_custom::<MachO>());
    }

    fn raw_relocation(
        r_address: u32,
        r_symbolnum: u32,
        r_pcrel: bool,
        r_length: u8,
        r_extern: bool,
        r_type: object::macho::RelocationType,
    ) -> Relocation {
        object::macho::RelocationInfo {
            r_address,
            r_symbolnum,
            r_pcrel,
            r_length,
            r_extern,
            r_type,
        }
        .relocation(LE)
    }

    #[test]
    fn folds_signed_arm64_addends_into_the_following_relocation() {
        let relocations = [
            raw_relocation(8, 0x24, false, 2, false, macho::ARM64_RELOC_ADDEND),
            raw_relocation(8, 7, true, 2, true, macho::ARM64_RELOC_BRANCH26),
            raw_relocation(4, 0x00ff_fffc, false, 2, false, macho::ARM64_RELOC_ADDEND),
            raw_relocation(4, 3, false, 2, true, macho::ARM64_RELOC_PAGEOFF12),
        ];

        let relocations = paired_relocations(&relocations)
            .collect::<Result<Vec<_>>>()
            .unwrap();

        assert_eq!(relocations.len(), 2);
        assert_eq!(relocations[0].info.r_type, macho::ARM64_RELOC_BRANCH26);
        assert_eq!(relocations[0].addend, 0x24);
        assert_eq!(relocations[1].info.r_type, macho::ARM64_RELOC_PAGEOFF12);
        assert_eq!(relocations[1].addend, -4);
    }

    #[test]
    fn relocation_cache_reuses_normalized_section_relocations() {
        let relocations = [
            raw_relocation(8, 0x24, false, 2, false, macho::ARM64_RELOC_ADDEND),
            raw_relocation(8, 7, true, 2, true, macho::ARM64_RELOC_BRANCH26),
        ];
        let section_index = object::SectionIndex(3);
        let mut cache = MachORelocationCache::default();

        cache.cache(section_index, &relocations).unwrap();
        assert_eq!(cache.for_section(section_index).len(), 1);
        assert_eq!(
            cache.for_section(section_index)[0].info.r_type,
            macho::ARM64_RELOC_BRANCH26
        );
        assert_eq!(cache.for_section(section_index)[0].addend, 0x24);

        // The input object is immutable while linking. A second atom in this section must use
        // its existing normalized records instead of reparsing even malformed replacement data.
        let malformed = [raw_relocation(
            0,
            1,
            false,
            2,
            false,
            macho::ARM64_RELOC_ADDEND,
        )];
        cache.cache(section_index, &malformed).unwrap();
        assert_eq!(cache.for_section(section_index).len(), 1);
        assert_eq!(
            cache.for_section(section_index)[0].info.r_type,
            macho::ARM64_RELOC_BRANCH26
        );
    }

    #[test]
    fn relocation_cache_selects_only_the_current_atom_range() {
        let relocations = [
            raw_relocation(20, 1, true, 2, true, macho::ARM64_RELOC_BRANCH26),
            raw_relocation(4, 2, true, 2, true, macho::ARM64_RELOC_BRANCH26),
            raw_relocation(12, 3, true, 2, true, macho::ARM64_RELOC_BRANCH26),
        ];
        let section_index = object::SectionIndex(0);
        let mut cache = MachORelocationCache::default();

        cache.cache(section_index, &relocations).unwrap();

        assert_eq!(
            cache
                .for_range(section_index, &(8..16))
                .iter()
                .map(|relocation| relocation.info.r_address)
                .collect_vec(),
            vec![12]
        );
        assert_eq!(
            cache
                .for_range(section_index, &(0..32))
                .iter()
                .map(|relocation| relocation.info.r_address)
                .collect_vec(),
            vec![4, 12, 20]
        );
    }

    #[test]
    fn preserves_arm64_subtractor_pairs_as_one_relocation_expression() {
        let relocations = [
            raw_relocation(16, 5, false, 3, true, macho::ARM64_RELOC_SUBTRACTOR),
            raw_relocation(16, 9, false, 3, true, macho::ARM64_RELOC_UNSIGNED),
        ];

        let relocations = paired_relocations(&relocations)
            .collect::<Result<Vec<_>>>()
            .unwrap();

        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].info.r_type, macho::ARM64_RELOC_UNSIGNED);
        assert_eq!(relocations[0].info.r_symbolnum, 9);
        assert_eq!(
            relocations[0].subtractor.unwrap().r_symbolnum,
            5,
            "the subtractor remains associated with the unsigned minuend"
        );
    }

    #[test]
    fn rejects_malformed_arm64_addend_pairs() {
        let missing_primary = [raw_relocation(
            0,
            1,
            false,
            2,
            false,
            macho::ARM64_RELOC_ADDEND,
        )];
        assert!(paired_relocations(&missing_primary)
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("must be immediately followed"));

        let wrong_offset = [
            raw_relocation(4, 1, false, 2, false, macho::ARM64_RELOC_ADDEND),
            raw_relocation(0, 3, true, 2, true, macho::ARM64_RELOC_BRANCH26),
        ];
        assert!(paired_relocations(&wrong_offset)
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("same offset"));

        let wrong_target = [
            raw_relocation(0, 1, false, 2, false, macho::ARM64_RELOC_ADDEND),
            raw_relocation(0, 3, true, 2, true, macho::ARM64_RELOC_GOT_LOAD_PAGE21),
        ];
        assert!(paired_relocations(&wrong_target)
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("must be immediately followed"));
    }

    #[test]
    fn rejects_malformed_arm64_subtractor_pairs() {
        let missing_unsigned = [raw_relocation(
            0,
            1,
            false,
            3,
            true,
            macho::ARM64_RELOC_SUBTRACTOR,
        )];
        assert!(paired_relocations(&missing_unsigned)
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("must be immediately followed by ARM64_RELOC_UNSIGNED"));

        let wrong_offset = [
            raw_relocation(4, 1, false, 3, true, macho::ARM64_RELOC_SUBTRACTOR),
            raw_relocation(0, 3, false, 3, true, macho::ARM64_RELOC_UNSIGNED),
        ];
        assert!(paired_relocations(&wrong_offset)
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("same offset"));

        let unsupported_fields = [
            raw_relocation(0, 1, false, 2, true, macho::ARM64_RELOC_SUBTRACTOR),
            raw_relocation(0, 3, false, 2, true, macho::ARM64_RELOC_UNSIGNED),
        ];
        assert!(paired_relocations(&unsupported_fields)
            .next()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("external non-pcrel 64-bit"));
    }

    #[test]
    fn classifies_non_loadable_macho_sections_from_format_metadata() {
        assert!(!is_non_alloc_section(
            macho::S_REGULAR.to_flags(),
            SegmentName::TEXT.into_bytes().as_slice()
        ));
        assert!(is_non_alloc_section(
            macho::S_REGULAR.to_flags().with(S_ATTR_DEBUG),
            SegmentName::TEXT.into_bytes().as_slice()
        ));
        assert!(!is_non_alloc_section(
            macho::S_REGULAR.to_flags().with(S_ATTR_DEBUG),
            SegmentName::LD.into_bytes().as_slice()
        ));
        assert!(is_non_alloc_section(
            macho::S_REGULAR.to_flags(),
            SegmentName::DWARF.into_bytes().as_slice()
        ));
        assert!(is_non_alloc_section(
            macho::S_REGULAR.to_flags(),
            SegmentName::LINKEDIT.into_bytes().as_slice()
        ));
    }

    #[test]
    fn classifies_tlv_storage_without_treating_descriptors_as_tls_data() {
        assert!(is_tls_section_type(S_THREAD_LOCAL_REGULAR));
        assert!(is_tls_section_type(S_THREAD_LOCAL_ZEROFILL));
        assert!(!is_tls_section_type(macho::S_THREAD_LOCAL_VARIABLES));
        assert!(!is_tls_section_type(macho::S_THREAD_LOCAL_VARIABLE_POINTERS));
        assert!(!is_tls_section_type(macho::S_REGULAR));
    }

    fn test_symbol(section_properties: SymbolSectionProperties) -> SymtabEntry {
        let mut raw = RawSymtabEntry {
            n_strx: Default::default(),
            n_type: Default::default(),
            n_sect: Default::default(),
            n_desc: Default::default(),
            n_value: Default::default(),
        };
        raw.n_type = raw.n_type.with_type(N_SECT);
        raw.n_type.insert(N_EXT);
        SymtabEntry::from_raw(raw, section_properties)
    }

    fn test_undefined_symbol() -> SymtabEntry {
        let mut raw = RawSymtabEntry {
            n_strx: Default::default(),
            n_type: Default::default(),
            n_sect: Default::default(),
            n_desc: Default::default(),
            n_value: Default::default(),
        };
        raw.n_type = raw.n_type.with_type(N_UNDF);
        raw.n_type.insert(N_EXT);
        SymtabEntry::from_raw(raw, SymbolSectionProperties::default())
    }

    #[test]
    fn symbol_properties_follow_the_defining_section() {
        let function = test_symbol(
            SymbolSectionProperties {
                is_tls: false,
                is_func: true,
            },
        );
        assert!(function.is_func());
        assert!(!function.is_tls());
        assert_eq!(function.debug_string(), "Global Func");

        let tls = test_symbol(
            SymbolSectionProperties {
                is_tls: true,
                is_func: false,
            },
        );
        assert!(tls.is_tls());
        assert!(!tls.is_func());
        assert_eq!(tls.debug_string(), "Global Tls");

        let undefined = test_undefined_symbol();
        assert_eq!(undefined.debug_string(), "Global Undefined");
    }

    #[test]
    fn section_attributes_keep_macho_tls_section_types() {
        let tls = SectionAttributes::new(S_THREAD_LOCAL_REGULAR.to_flags(), Some(SegmentName::DATA));
        assert!(platform::SectionAttributes::is_tls(&tls));

        let descriptor =
            SectionAttributes::new(S_THREAD_LOCAL_VARIABLES.to_flags(), Some(SegmentName::DATA));
        assert!(!platform::SectionAttributes::is_tls(&descriptor));
    }

    #[test]
    fn thread_variable_descriptors_are_at_least_word_aligned() {
        assert_eq!(minimum_section_alignment(S_THREAD_LOCAL_VARIABLES, 1), 8);
        assert_eq!(minimum_section_alignment(S_THREAD_LOCAL_VARIABLES, 16), 16);
        assert_eq!(minimum_section_alignment(macho::S_REGULAR, 1), 1);
    }

    #[test]
    fn preserves_read_only_data_const_segment_semantics() {
        assert!(!SegmentName::DATA_CONST.is_writable());
        assert!(!SegmentName::DWARF.is_writable());
        assert!(SegmentName::DATA.is_writable());
    }

    #[test]
    fn reserves_got_for_a_non_dynamic_got_resolution() {
        use crate::args::RelocationModel;
        use crate::layout::compute_allocations;
        use crate::output_kind::OutputKind;
        use crate::platform::Platform;

        let args = MachOArgs::default();
        let output_kind = OutputKind::DynamicExecutable(RelocationModel::Relocatable);
        let output_sections =
            crate::output_section_id::OutputSections::<MachO>::with_base_address(0, output_kind);
        let mut memory_offsets = output_sections.new_part_map();
        *memory_offsets.get_mut(part_id::GOT) = 0x10;

        let resolution = MachO::create_resolution(
            ValueFlags::GOT,
            0xfeed_face,
            None,
            &mut memory_offsets,
            &args,
            output_kind,
        );

        assert_eq!(resolution.raw_value, 0x10);
        assert_eq!(*memory_offsets.get(part_id::GOT), 0x10 + GOT_ENTRY_SIZE);
        assert_eq!(
            *compute_allocations::<MachO>(&resolution, output_kind, &args).get(part_id::GOT),
            GOT_ENTRY_SIZE
        );
    }

    #[test]
    fn reserves_a_distinct_tlvp_slot_for_a_dynamic_tls_descriptor() {
        use crate::args::RelocationModel;
        use crate::layout::compute_allocations;
        use crate::output_kind::OutputKind;
        use crate::platform::Platform;

        let args = MachOArgs::default();
        let output_kind = OutputKind::DynamicExecutable(RelocationModel::Relocatable);
        let output_sections =
            crate::output_section_id::OutputSections::<MachO>::with_base_address(0, output_kind);
        let mut memory_offsets = output_sections.new_part_map();
        *memory_offsets.get_mut(part_id::TLVP) = 0x20;

        let resolution = MachO::create_resolution(
            ValueFlags::GOT_TLS_DESCRIPTOR,
            0xfeed_face,
            None,
            &mut memory_offsets,
            &args,
            output_kind,
        );

        assert_eq!(resolution.raw_value, 0x20);
        assert_eq!(resolution.format_specific.tlvp_address.unwrap().get(), 0x20);
        assert!(resolution.format_specific.got_address.is_none());
        assert_eq!(*memory_offsets.get(part_id::TLVP), 0x20 + GOT_ENTRY_SIZE);
        assert_eq!(
            *compute_allocations::<MachO>(&resolution, output_kind, &args).get(part_id::TLVP),
            GOT_ENTRY_SIZE
        );
    }

}
