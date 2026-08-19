use crate::OutputFileData;
use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::bail;
use crate::elf::get_page_mask;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::file_writer::split_buffers_by_alignment;
use crate::file_writer::split_output_by_group;
use crate::file_writer::split_output_into_sections;
use crate::layout::EpilogueLayout;
use crate::layout::FileLayout;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayout;
use crate::layout::Resolution;
use crate::layout::Section;
use crate::layout::SymbolCopyInfo;
use crate::macho::BuildVersionCommand;
use crate::macho::CS_BLOB_HEADERS_SIZE;
use crate::macho::CS_BLOCK_SIZE;
use crate::macho::CS_BLOCK_SIZE_EXP;
use crate::macho::CS_CODE_DIRECTORY_SIZE;
use crate::macho::CS_HASH_SIZE;
use crate::macho::CS_HEADERS_SIZE;
use crate::macho::CHAINED_STARTS_IN_IMAGE_OFFSET;
use crate::macho::CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE;
use crate::macho::ChainedFixupsHeader;
use crate::macho::ChainedStartsInSegment;
use crate::macho::CodeSignatureCommand;
use crate::macho::COMPACT_UNWIND_ENTRY_SIZE;
use crate::macho::COMPACT_UNWIND_REGULAR_PAGE_MAX_ENTRIES;
use crate::macho::DYLINKER_PATH;
use crate::macho::DyldChainedFixupsCommand;
use crate::macho::DylibCommand;
use crate::macho::DylinkerCommand;
use crate::macho::EntryPointCommand;
use crate::macho::FileHeader;
use crate::macho::GOT_ENTRY_SIZE;
use crate::macho::MACHO_COMMAND_ALIGNMENT;
use crate::macho::MACHO_START_MEM_ADDRESS;
use crate::macho::MAX_SEGMENT_COUNT;
use crate::macho::MachO;
use crate::macho::PLT_ENTRY_SIZE;
use crate::macho::RpathCommand;
use crate::macho::SectionEntry;
use crate::macho::SegmentCommand;
use crate::macho::SegmentName;
use crate::macho::SymtabCommand;
use crate::macho::UuidCommand;
use crate::macho::code_signature_identifier;
use crate::macho::code_signature_padded_identifier_size;
use crate::macho::eh_frame_augmentations;
use crate::macho::get_segment_sections;
use crate::macho::load_dylib_command_size;
use crate::macho::rpath_command_size;
use crate::macho::output_section_id;
use crate::macho::output_section_id::LOAD_COMMANDS;
use crate::macho::part_id;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionName;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::HexU64;
use crate::output_trace::TraceOutput;
use crate::platform::Arch;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::platform::Symbol;
use crate::resolution::SectionSlot;
use crate::symbol_db::SymbolId;
use crate::thunks::ThunkBlockId;
use crate::timing_phase;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use itertools::Itertools;
#[cfg(test)]
use linker_utils::elf::AArch64Instruction;
use linker_utils::elf::RelocationKind;
use linker_utils::utils::slice_from_all_bytes_mut;
use object::BigEndian;
use object::Endianness;
use object::SymbolIndex;
use object::U16;
use object::U32;
use object::from_bytes_mut;
use object::macho;
use object::macho::CPU_SUBTYPE_ARM64_ALL;
use object::macho::CPU_TYPE_ARM64;
use object::macho::CS_ADHOC;
use object::macho::CS_EXECSEG_MAIN_BINARY;
use object::macho::CS_HASHTYPE_SHA256;
use object::macho::CS_LINKER_SIGNED;
use object::macho::CS_SUPPORTSEXECSEG;
use object::macho::CSSLOT_CODEDIRECTORY;
use object::macho::DYLD_CHAINED_IMPORT;
use object::macho::DYLD_CHAINED_PTR_64_OFFSET;
use object::macho::DYLD_CHAINED_PTR_START_NONE;
use object::macho::LC_BUILD_VERSION;
use object::macho::LC_CODE_SIGNATURE;
use object::macho::LC_DYLD_CHAINED_FIXUPS;
use object::macho::LC_DYLD_EXPORTS_TRIE;
use object::macho::LC_ID_DYLIB;
use object::macho::LC_LOAD_DYLIB;
use object::macho::LC_LOAD_DYLINKER;
use object::macho::LC_MAIN;
use object::macho::LC_RPATH;
use object::macho::LC_SEGMENT_64;
use object::macho::LC_SYMTAB;
use object::macho::LC_UUID;
use object::macho::LoadCommand;
use object::macho::MH_CIGAM_64;
use object::macho::MH_DYLIB;
use object::macho::MH_EXECUTE;
use object::macho::MH_HAS_TLV_DESCRIPTORS;
use object::macho::N_ABS;
use object::macho::N_SECT;
use object::macho::PLATFORM_MACOS;
use object::macho::RelocationInfo;
use object::macho::SegmentFlags;
use object::read::macho::Section as _;
use object::slice_from_bytes_mut;
use object::write::macho::CodeDirectory;
use object::write::macho::CodeSignatureEncoder;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::BitAnd;
use tracing::debug_span;
use zerocopy::FromZeros;

const LE: Endianness = Endianness::Little;

type MachOLayout<'data> = Layout<'data, MachO>;
type SymtabEntry = object::macho::Nlist64<Endianness>;
type ExportsTrieCommand = object::macho::LinkeditDataCommand<Endianness>;

pub(crate) fn write<'data, A: Arch<Platform = MachO>>(
    sized_output: &mut SizedOutput<impl OutputFileData>,
    layout: &MachOLayout<'data>,
) -> Result {
    timing_phase!("Write data to file");
    let exports_trie = build_exports_trie(layout)?;
    let (mut section_buffers, mut padding) =
        split_output_into_sections(layout, &mut sized_output.out);
    padding.fill_zero();

    let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
    let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
    groups_and_buffers
        .into_par_iter()
        .try_for_each(|(group, mut buffers)| -> Result {
            verbose_timing_phase!("Write group");

            let mut symbol_writer = MachOSymbolTableWriter {
                next_strtab_offset: group.strtab_start_offset,
            };
            for file in &group.files {
                write_file::<A>(
                    file,
                    &mut buffers,
                    layout,
                    &sized_output.trace,
                    &mut symbol_writer,
                    &exports_trie,
                )
                .with_context(|| format!("Failed copying from {file} to output file"))?;
            }
            Ok(())
        })?;

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    write_plt_entries::<A>(layout, section_buffers.get_mut(output_section_id::PLT_GOT))?;
    write_merged_strings(layout, &mut section_buffers);
    write_compact_unwind_info(layout, section_buffers.get_mut(output_section_id::UNWIND_INFO))?;
    drop(section_buffers);

    // Plan before encoding: local relocations still contain their link-time target addresses.
    // The same plan drives both the starts table and the in-place chained pointer words.
    let chained_fixups = chained_fixups(layout, &sized_output.out)?;
    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    write_chained_fixup_table(
        layout,
        &chained_fixups,
        section_buffers.get_mut(output_section_id::CHAINED_FIXUP_TABLE),
    )?;
    drop(section_buffers);

    // All object relocations have now written their link-time pointer values. Rewrite the
    // locations dyld owns as chained bind/rebase words before UUID and code-signature hashing.
    write_chained_fixup_pointers(layout, &chained_fixups, &mut sized_output.out)?;

    write_code_signature_metadata(layout, sized_output)?;
    write_uuid(layout, sized_output)?;
    write_code_signature_hashes(layout, sized_output)?;

    Ok(())
}

/// Merged string sections are represented by layout-owned buckets rather than by an input object
/// section. They must therefore be emitted after object copying and before the final code-signature
/// hash, just as regular input data is.
fn write_merged_strings(
    layout: &MachOLayout<'_>,
    buffers: &mut OutputSectionMap<&mut [u8]>,
) {
    layout.merged_strings.for_each(|section_id, merged| {
        if merged.len() > 0 {
            let buffer = buffers.get_mut(section_id);
            crate::elf_writer::write_merged_strings_to_buffer(merged, buffer);
        }
    });
}

/// A compact-unwind record after its object-file relocations have been resolved to final image
/// addresses. The final Mach-O table stores all of these addresses as 32-bit offsets from the
/// image base, so retaining the full addresses here makes range validation straightforward.
#[derive(Debug)]
struct CompactUnwindEntry {
    function_address: u64,
    function_length: u32,
    encoding: u32,
    personality_address: Option<u64>,
    lsda_address: Option<u64>,
}

/// Synthesize `__TEXT,__unwind_info` from object-file `__LD,__compact_unwind` records.
///
/// Mach-O deliberately uses a different final representation from its object files: final
/// records are sorted by post-GC function address and grouped into an indexed two-level page
/// table. We always emit the regular page form (kind 2). It is larger than the compressed form
/// but has no artificial encoding-count or function-offset limit and is the format's specified
/// lossless fallback.
fn write_compact_unwind_info(layout: &MachOLayout<'_>, output: &mut [u8]) -> Result {
    if output.is_empty() {
        return Ok(());
    }

    timing_phase!("Write compact unwind info");
    let mut entries = Vec::new();
    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };
            for (section_index, slot) in object.sections.iter().enumerate() {
                let SectionSlot::FrameData(compact_unwind_section_index) = slot else {
                    continue;
                };
                debug_assert_eq!(section_index, compact_unwind_section_index.0);
                entries.extend(read_compact_unwind_entries(
                    layout,
                    object,
                    *compact_unwind_section_index,
                )?);
            }
        }
    }

    entries.sort_by_key(|entry| entry.function_address);
    // ARM64's DWARF mode delegates actual frame recovery to a final `__TEXT,__eh_frame` table.
    // Wild does not yet serialize that relocation-rich table, so emitting an apparently complete
    // `__unwind_info` would turn a deterministic link-time limitation into a process-time abort.
    // Frame and frameless compact encodings remain self-contained and are supported below.
    const ARM64_UNWIND_MODE_MASK: u32 = 0x0f00_0000;
    const ARM64_UNWIND_MODE_DWARF: u32 = 0x0300_0000;
    ensure!(
        entries.iter().all(|entry| entry.encoding & ARM64_UNWIND_MODE_MASK != ARM64_UNWIND_MODE_DWARF),
        "ARM64 compact unwind DWARF mode requires final __TEXT,__eh_frame serialization, which Wild does not yet implement"
    );
    for adjacent in entries.windows(2) {
        let previous_end = adjacent[0]
            .function_address
            .checked_add(u64::from(adjacent[0].function_length))
            .context("compact-unwind function range overflow")?;
        ensure!(
            previous_end <= adjacent[1].function_address,
            "overlapping compact-unwind function ranges at 0x{:x} and 0x{:x}",
            adjacent[0].function_address,
            adjacent[1].function_address
        );
    }

    let mut personalities = Vec::new();
    for entry in &entries {
        let Some(personality) = entry.personality_address else {
            continue;
        };
        if !personalities.contains(&personality) {
            ensure!(
                personalities.len() < 3,
                "Mach-O compact unwind supports at most three distinct personality functions"
            );
            personalities.push(personality);
        }
    }

    let serialized = serialize_compact_unwind_info(&entries, &personalities)?;
    ensure!(
        serialized.len() <= output.len(),
        "allocated {} bytes for __unwind_info but need {}",
        output.len(),
        serialized.len()
    );
    output.fill(0);
    output[..serialized.len()].copy_from_slice(&serialized);
    Ok(())
}

fn read_compact_unwind_entries(
    layout: &MachOLayout<'_>,
    object: &ObjectLayout<'_, MachO>,
    compact_unwind_section_index: object::SectionIndex,
) -> Result<Vec<CompactUnwindEntry>> {
    let section = object.object.section(compact_unwind_section_index)?;
    let data = object.object.raw_section_data(section)?;
    ensure!(
        data.len() % COMPACT_UNWIND_ENTRY_SIZE == 0,
        "{} has malformed __compact_unwind data: {} bytes is not a multiple of {}",
        object.input,
        data.len(),
        COMPACT_UNWIND_ENTRY_SIZE
    );

    let mut relocations = std::collections::BTreeMap::new();
    for relocation in object
        .relocations(compact_unwind_section_index)?
        .relocations
    {
        let info = relocation.info(LE);
        ensure!(
            info.r_type == macho::ARM64_RELOC_UNSIGNED && !info.r_pcrel && info.r_length == 3,
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
        ensure!(
            relocations.insert(offset, info).is_none(),
            "duplicate __compact_unwind relocation at offset 0x{offset:x} in {}",
            object.input
        );
    }

    let mut entries = Vec::new();
    for record_offset in (0..data.len()).step_by(COMPACT_UNWIND_ENTRY_SIZE) {
        let function_addend = compact_unwind_u64(data, record_offset)?;
        let function_length = compact_unwind_u32(data, record_offset + 8)?;
        ensure!(
            function_length != 0,
            "{} has zero-length __compact_unwind function at offset 0x{record_offset:x}",
            object.input
        );
        let encoding = compact_unwind_u32(data, record_offset + 12)?;
        let personality_addend = compact_unwind_u64(data, record_offset + 16)?;
        let lsda_addend = compact_unwind_u64(data, record_offset + 24)?;

        let Some(function_address) = compact_unwind_function_address(
            layout,
            object,
            *relocations.get(&record_offset).context(
                "__compact_unwind function has no relocation",
            )?,
            function_addend,
            function_length,
        )?
        else {
            // The function's Mach-O atom was dead-stripped. Its metadata and any associated
            // LSDA must disappear with it rather than retaining an invalid input address.
            continue;
        };

        let personality_address = compact_unwind_optional_target_address(
            layout,
            object,
            relocations.get(&(record_offset + 16)).copied(),
            personality_addend,
            "personality",
        )?;
        let lsda_address = compact_unwind_optional_target_address(
            layout,
            object,
            relocations.get(&(record_offset + 24)).copied(),
            lsda_addend,
            "LSDA",
        )?;

        entries.push(CompactUnwindEntry {
            function_address,
            function_length,
            encoding,
            personality_address,
            lsda_address,
        });
    }
    merge_eh_frame_augmentations(layout, object, &mut entries)?;
    Ok(entries)
}

/// Complete sparse Rust compact-unwind rows from their paired DWARF FDEs. LLVM's C++ Mach-O
/// producer puts personality and LSDA relocations directly in `__compact_unwind`; rustc instead
/// uses the standard `zPLR` CIE/FDE augmentation and leaves those two words zero. The parser is
/// deliberately shared with GC so the metadata retained here and the dependencies retained
/// there have exactly the same bounded ARM64 representation.
fn merge_eh_frame_augmentations(
    layout: &MachOLayout<'_>,
    object: &ObjectLayout<'_, MachO>,
    entries: &mut [CompactUnwindEntry],
) -> Result {
    if entries.is_empty() {
        return Ok(());
    }
    let mut targets = std::collections::BTreeMap::new();
    for (section_index, section) in object.object.enumerate_sections() {
        if section.name() != b"__eh_frame" {
            continue;
        }
        let data = object.object.raw_section_data(section)?;
        let augmentations = eh_frame_augmentations(data)?;
        if augmentations.is_empty() {
            continue;
        }
        let mut relocations = std::collections::BTreeMap::new();
        for relocation in object.relocations(section_index)?.relocations {
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

        for augmentation in augmentations {
            let Some(function) = eh_frame_target_address(
                layout,
                object,
                *relocations
                    .get(&augmentation.function_relocation_offset)
                    .with_context(|| {
                        format!(
                            "missing function relocation at Mach-O __eh_frame offset 0x{:x} in {}",
                            augmentation.function_relocation_offset, object.input
                        )
                    })?,
                macho::ARM64_RELOC_UNSIGNED,
                "function",
                false,
            )?
            else {
                // An FDE is input metadata too. Rust keeps FDEs for dead libstd atoms, whose
                // symbol has no final resolution; the matching compact row was already omitted.
                continue;
            };
            let personality = eh_frame_target_address(
                layout,
                object,
                *relocations
                    .get(&augmentation.personality_relocation_offset)
                    .with_context(|| {
                        format!(
                            "missing personality relocation at Mach-O __eh_frame offset 0x{:x} in {}",
                            augmentation.personality_relocation_offset, object.input
                        )
                    })?,
                macho::ARM64_RELOC_POINTER_TO_GOT,
                "personality",
                true,
            )?
            .expect("required __eh_frame personality target");
            let lsda = eh_frame_target_address(
                layout,
                object,
                *relocations
                    .get(&augmentation.lsda_relocation_offset)
                    .with_context(|| {
                        format!(
                            "missing LSDA relocation at Mach-O __eh_frame offset 0x{:x} in {}",
                            augmentation.lsda_relocation_offset, object.input
                        )
                    })?,
                macho::ARM64_RELOC_UNSIGNED,
                "LSDA",
                true,
            )?
            .expect("required __eh_frame LSDA target");
            let previous = targets.insert(function, (personality, lsda));
            ensure!(
                previous.is_none_or(|previous| previous == (personality, lsda)),
                "conflicting Mach-O __eh_frame zPLR metadata for function at 0x{function:x}"
            );
        }
    }

    for entry in entries {
        let Some(&(personality, lsda)) = targets.get(&entry.function_address) else {
            continue;
        };
        if entry.personality_address.is_none() {
            entry.personality_address = Some(personality);
        }
        if entry.lsda_address.is_none() {
            entry.lsda_address = Some(lsda);
        }
    }
    Ok(())
}

fn eh_frame_target_address(
    layout: &MachOLayout<'_>,
    object: &ObjectLayout<'_, MachO>,
    relocation: RelocationInfo,
    expected_type: macho::RelocationType,
    field_name: &str,
    required: bool,
) -> Result<Option<u64>> {
    ensure!(
        relocation.r_type == expected_type && relocation.r_extern,
        "unsupported Mach-O __eh_frame {field_name} relocation in {}",
        object.input
    );
    if expected_type == macho::ARM64_RELOC_POINTER_TO_GOT {
        ensure!(
            relocation.r_pcrel && relocation.r_length == 2,
            "unsupported Mach-O __eh_frame personality relocation in {}: expected ARM64_RELOC_POINTER_TO_GOT, r_pcrel=1, r_length=2",
            object.input
        );
    } else {
        ensure!(
            !relocation.r_pcrel && relocation.r_length == 3,
            "unsupported Mach-O __eh_frame {field_name} relocation in {}: expected r_pcrel=0",
            object.input
        );
    }
    let local_symbol_index = SymbolIndex(relocation.r_symbolnum as usize);
    let symbol_id = object.symbol_id_range.input_to_id(local_symbol_index);
    let resolution = layout.merged_symbol_resolution(symbol_id);
    if required {
        return resolution
            .with_context(|| {
            format!(
                "unresolved Mach-O __eh_frame {field_name} symbol {} in {}",
                layout.symbol_debug(symbol_id),
                object.input
            )
        })
            .map(|resolution| Some(resolution.raw_value));
    }
    Ok(resolution.map(|resolution| resolution.raw_value))
}

/// Compact-unwind records are metadata, so their relocation target can be a valid end label even
/// when the function body was discarded. A final end label does have an output address, but it
/// must not create an unwind row. Require the complete function range to survive before resolving
/// its start address; personalities and LSDAs remain ordinary address targets below.
fn compact_unwind_function_address(
    layout: &MachOLayout<'_>,
    object: &ObjectLayout<'_, MachO>,
    relocation: RelocationInfo,
    addend: u64,
    function_length: u32,
) -> Result<Option<u64>> {
    if !relocation.r_extern {
        let section_ordinal = usize::try_from(relocation.r_symbolnum)
            .context("__compact_unwind function section ordinal overflowed usize")?;
        let section_index = object::SectionIndex(
            section_ordinal
                .checked_sub(1)
                .context("__compact_unwind function relocation has section ordinal zero")?,
        );
        let input_section = object.object.section(section_index)?;
        let input_offset = addend
            .checked_sub(input_section.addr.get(LE))
            .context("__compact_unwind function target precedes its input section")?;
        let input_end = input_offset
            .checked_add(u64::from(function_length))
            .context("__compact_unwind function range overflows")?;
        if !object.input_range_is_live(section_index, input_offset..input_end) {
            return Ok(None);
        }
    }

    compact_unwind_target_address(layout, object, relocation, addend)
}

fn compact_unwind_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + size_of::<u32>())
        .context("truncated __compact_unwind u32 field")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn compact_unwind_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + size_of::<u64>())
        .context("truncated __compact_unwind u64 field")?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn compact_unwind_optional_target_address(
    layout: &MachOLayout<'_>,
    object: &ObjectLayout<'_, MachO>,
    relocation: Option<RelocationInfo>,
    addend: u64,
    field_name: &str,
) -> Result<Option<u64>> {
    match relocation {
        Some(relocation) => compact_unwind_target_address(layout, object, relocation, addend),
        None if addend == 0 => Ok(None),
        None => bail!(
            "{} has a nonzero __compact_unwind {field_name} without a relocation",
            object.input
        ),
    }
}

fn compact_unwind_target_address(
    layout: &MachOLayout<'_>,
    object: &ObjectLayout<'_, MachO>,
    relocation: RelocationInfo,
    addend: u64,
) -> Result<Option<u64>> {
    ensure!(
        relocation.r_type == macho::ARM64_RELOC_UNSIGNED
            && !relocation.r_pcrel
            && relocation.r_length == 3,
        "unsupported __compact_unwind target relocation in {}",
        object.input
    );

    if relocation.r_extern {
        let local_symbol_index = SymbolIndex(relocation.r_symbolnum as usize);
        let symbol_id = object.symbol_id_range.input_to_id(local_symbol_index);
        let resolution = layout.merged_symbol_resolution(symbol_id).with_context(|| {
            format!(
                "unresolved __compact_unwind symbol {} in {}",
                layout.symbol_debug(symbol_id),
                object.input
            )
        })?;
        return resolution
            .raw_value
            .checked_add(addend)
            .map(Some)
            .context("__compact_unwind external target address overflow");
    }

    let section_ordinal = usize::try_from(relocation.r_symbolnum)
        .context("__compact_unwind section ordinal overflowed usize")?;
    let section_index = object::SectionIndex(
        section_ordinal
            .checked_sub(1)
            .context("__compact_unwind local relocation has section ordinal zero")?,
    );
    let Some(section_address) = object
        .section_resolutions
        .get(section_index.0)
        .and_then(|resolution| resolution.address())
    else {
        return Ok(None);
    };
    // A local Mach-O relocation's in-place word is a section-relative *address*, not always an
    // offset: object files commonly lay `__gcc_except_tab` after `__text`, so the LSDA word is
    // the section's object address plus its in-section offset. Convert it before applying the
    // post-GC input-to-output mapping. `__text` often begins at zero, which is why treating the
    // raw word as an offset superficially works until an exception table is involved.
    let input_section = object.object.section(section_index)?;
    let input_offset = addend
        .checked_sub(input_section.addr.get(LE))
        .context("__compact_unwind local target precedes its input section")?;
    let Some(output_offset) = object.output_offset_for_input(section_index, input_offset) else {
        return Ok(None);
    };
    section_address
        .checked_add(output_offset)
        .map(Some)
        .context("__compact_unwind local target address overflow")
}

fn serialize_compact_unwind_info(
    entries: &[CompactUnwindEntry],
    personalities: &[u64],
) -> Result<Vec<u8>> {
    const VERSION: u32 = 1;
    const HEADER_SIZE: u32 = 28;
    const REGULAR_SECOND_LEVEL_PAGE: u32 = 2;
    const REGULAR_PAGE_HEADER_SIZE: u16 = 8;
    const PERSONALITY_MASK: u32 = 0x3000_0000;
    const PERSONALITY_SHIFT: u32 = 28;

    let pages: Vec<&[CompactUnwindEntry]> = entries
        .chunks(COMPACT_UNWIND_REGULAR_PAGE_MAX_ENTRIES)
        .collect();
    let index_count = pages
        .len()
        .checked_add(1)
        .context("too many compact-unwind pages")?;
    let personality_offset = HEADER_SIZE;
    let index_offset = personality_offset
        .checked_add(
            u32::try_from(personalities.len() * size_of::<u32>())
                .context("compact-unwind personality table exceeds u32")?,
        )
        .context("compact-unwind index offset overflow")?;

    let mut data = Vec::new();
    for value in [
        VERSION,
        HEADER_SIZE,
        0,
        personality_offset,
        u32::try_from(personalities.len()).context("too many compact-unwind personalities")?,
        index_offset,
        u32::try_from(index_count).context("too many compact-unwind indices")?,
    ] {
        push_u32(&mut data, value);
    }
    for &personality in personalities {
        push_u32(&mut data, compact_unwind_image_offset(personality, "personality")?);
    }

    debug_assert_eq!(data.len(), index_offset as usize);
    let index_start = data.len();
    data.resize(index_start + index_count * 12, 0);

    // Each index points at the first LSDA descriptor for its page. The sentinel's LSDA offset is
    // the end of the shared descriptor table, which gives libunwind a bounded range for the last
    // page as specified by the Mach-O compact-unwind ABI.
    let mut lsda_offsets = Vec::with_capacity(pages.len());
    for page in &pages {
        lsda_offsets.push(
            u32::try_from(data.len()).context("compact-unwind LSDA offset exceeds u32")?,
        );
        for entry in *page {
            if let Some(lsda) = entry.lsda_address {
                push_u32(
                    &mut data,
                    compact_unwind_image_offset(entry.function_address, "function")?,
                );
                push_u32(&mut data, compact_unwind_image_offset(lsda, "LSDA")?);
            }
        }
    }
    let lsda_end = u32::try_from(data.len()).context("compact-unwind LSDA table exceeds u32")?;

    let mut page_offsets = Vec::with_capacity(pages.len());
    for page in &pages {
        align_u32(&mut data, 4);
        page_offsets.push(
            u32::try_from(data.len()).context("compact-unwind page offset exceeds u32")?,
        );
        push_u32(&mut data, REGULAR_SECOND_LEVEL_PAGE);
        push_u16(&mut data, REGULAR_PAGE_HEADER_SIZE);
        push_u16(
            &mut data,
            u16::try_from(page.len()).context("too many entries in compact-unwind page")?,
        );
        for entry in *page {
            let mut encoding = entry.encoding & !PERSONALITY_MASK;
            if let Some(personality) = entry.personality_address {
                let index = personalities
                    .iter()
                    .position(|candidate| *candidate == personality)
                    .context("compact-unwind personality was not recorded")?;
                encoding |= u32::try_from(index + 1)
                    .context("compact-unwind personality index overflow")?
                    << PERSONALITY_SHIFT;
            }
            push_u32(
                &mut data,
                compact_unwind_image_offset(entry.function_address, "function")?,
            );
            push_u32(&mut data, encoding);
        }
    }

    for (page_index, page) in pages.iter().enumerate() {
        let index_offset = index_start + page_index * 12;
        write_u32_at(
            &mut data,
            index_offset,
            compact_unwind_image_offset(page[0].function_address, "function")?,
        );
        write_u32_at(&mut data, index_offset + 4, page_offsets[page_index]);
        write_u32_at(&mut data, index_offset + 8, lsda_offsets[page_index]);
    }

    let sentinel_offset = index_start + pages.len() * 12;
    let sentinel_function = entries.last().map_or(0, |entry| {
        entry
            .function_address
            .checked_add(u64::from(entry.function_length))
            .expect("compact-unwind function range was already checked")
    });
    write_u32_at(
        &mut data,
        sentinel_offset,
        compact_unwind_image_offset(sentinel_function, "function")?,
    );
    write_u32_at(&mut data, sentinel_offset + 4, 0);
    write_u32_at(&mut data, sentinel_offset + 8, lsda_end);

    Ok(data)
}

fn compact_unwind_image_offset(address: u64, what: &str) -> Result<u32> {
    let offset = address
        .checked_sub(MACHO_START_MEM_ADDRESS)
        .with_context(|| format!("compact-unwind {what} address 0x{address:x} is below image"))?;
    u32::try_from(offset)
        .with_context(|| format!("compact-unwind {what} address 0x{address:x} is over 4GiB from image base"))
}

fn push_u16(data: &mut Vec<u8>, value: u16) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(data: &mut Vec<u8>, value: u32) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn write_u32_at(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

fn align_u32(data: &mut Vec<u8>, alignment: usize) {
    data.resize(data.len().next_multiple_of(alignment), 0);
}

fn write_file<'data, A: Arch<Platform = MachO>>(
    file: &FileLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    _trace: &TraceOutput,
    symbol_writer: &mut MachOSymbolTableWriter,
    exports_trie: &[u8],
) -> Result {
    match file {
        FileLayout::Object(s) => {
            write_object::<A>(s, buffers, layout, symbol_writer)?;
        }
        FileLayout::Prelude(s) => write_prelude(s, buffers, layout, exports_trie)?,
        FileLayout::Epilogue(s) => write_epilogue(s, buffers, layout, exports_trie)?,
        _ => {
            // TODO
        }
    }
    Ok(())
}

/// Takes enough bytes from `bytes` for a T, returning those bytes as an `&mut T`.
fn take_mut<'out, T: object::Pod>(bytes: &mut &'out mut [u8]) -> Result<&'out mut T> {
    let bytes = bytes
        .split_off_mut(..size_of::<T>())
        .context("Insufficient allocation")?;
    from_bytes_mut::<T>(bytes)
        .map_err(|()| error!("Unaligned write"))
        .map(|(a, _)| a)
}

fn write_prelude<'data>(
    prelude: &PreludeLayout<MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    exports_trie: &[u8],
) -> Result {
    verbose_timing_phase!("Write prelude");
    debug_assert_eq!(
        prelude.format_specific.imported_library_file_ids.len(),
        prelude.format_specific.load_dylib_command_sizes.len()
    );

    let header_buffer = buffers.get_mut(crate::part_id::FILE_HEADER);
    populate_file_header(layout, prelude, take_mut(header_buffer)?);
    ensure!(header_buffer.is_empty(), "Excess FILE_HEADER allocation");

    let mut load_command_buffer = slice_from_all_bytes_mut(buffers.get_mut(part_id::LOAD_COMMANDS));
    write_segment_commands(layout, &mut load_command_buffer)?;

    if layout.symbol_db.output_kind.is_executable() {
        write_entry_point_command(layout, take_mut(&mut load_command_buffer)?)?;
    }

    write_uuid_command(take_mut(&mut load_command_buffer)?);

    if layout.args().platform_version.is_some() {
        let build_version_command = take_mut(&mut load_command_buffer)?;
        write_build_version_command(layout, build_version_command)?;
    }

    if layout.symbol_db.output_kind.is_executable() {
        let command_size = (size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
            .next_multiple_of(MACHO_COMMAND_ALIGNMENT);
        let mut command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
        let dylinker_command = take_mut(&mut command_buffer)?;
        write_dylinker_command(dylinker_command, command_buffer);
    } else if layout.symbol_db.output_kind.is_shared_object() {
        let install_name = layout.args().dylib_install_name();
        let command_size = load_dylib_command_size(install_name);
        let mut command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
        let dylib_command = take_mut(&mut command_buffer)?;
        write_dylib_command(dylib_command, command_buffer, install_name, LC_ID_DYLIB);
    }

    for rpath in &layout.args().rpaths {
        let command_size = rpath_command_size(rpath.as_bytes());
        let mut command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
        let rpath_command = take_mut(&mut command_buffer)?;
        write_rpath_command(rpath_command, command_buffer, rpath.as_bytes());
    }

    for (&file_id, &command_size) in prelude
        .format_specific
        .imported_library_file_ids
        .iter()
        .zip(&prelude.format_specific.load_dylib_command_sizes)
    {
        let mut command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
        let dylib_command = take_mut(&mut command_buffer)?;
        let path = crate::macho::install_name(file_id, &layout.symbol_db);

        write_dylib_command(dylib_command, command_buffer, path, LC_LOAD_DYLIB);
    }

    write_dyld_chained_fixups_command(layout, take_mut(&mut load_command_buffer)?);

    if layout.symbol_db.output_kind.needs_dynsym() {
        write_exports_trie_command(layout, exports_trie, take_mut(&mut load_command_buffer)?)?;
    }

    write_symtab_command(layout, take_mut(&mut load_command_buffer)?);

    write_code_signature_command(layout, take_mut(&mut load_command_buffer)?);

    ensure!(
        load_command_buffer.is_empty(),
        "Excess LOAD_COMMANDS allocation"
    );

    // Fill up one extra character as n_strx == 0 is treated as unnamed.
    buffers.get_mut(part_id::STRTAB).fill(0);

    Ok(())
}

fn write_epilogue(
    _epilogue: &EpilogueLayout<MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    _layout: &MachOLayout<'_>,
    exports_trie: &[u8],
) -> Result {
    verbose_timing_phase!("Write epilogue");
    let out = buffers.get_mut(part_id::EXPORTS_TRIE);
    ensure!(
        exports_trie.len() <= out.len(),
        "Mach-O exports trie exceeded its reserved size"
    );
    out[..exports_trie.len()].copy_from_slice(exports_trie);
    out[exports_trie.len()..].fill(0);

    // `__unwind_info` is allocated to this synthetic file so normal per-group allocation
    // verification accounts for it. Its bytes cannot be finalized until every object has been
    // copied and all final symbol addresses are available, so reserve/zero this span here and
    // populate it from the whole-output section view later in `write`.
    let unwind_info = buffers.get_mut(part_id::UNWIND_INFO);
    let unwind_info_len = unwind_info.len();
    unwind_info
        .split_off_mut(..unwind_info_len)
        .context("Insufficient __unwind_info allocation")?
        .fill(0);

    Ok(())
}

fn build_exports_trie(layout: &MachOLayout<'_>) -> Result<Vec<u8>> {
    if !layout.symbol_db.output_kind.needs_dynsym() {
        return Ok(Vec::new());
    }

    let text_segment = layout
        .segment_layouts
        .segments
        .iter()
        .find(|segment| layout.program_segments.segment_def(segment.id).name == SegmentName::TEXT)
        .context("Missing Mach-O __TEXT segment")?;

    let image_base = text_segment.sizes.mem_offset;

    let mut symbols = layout
        .dynamic_symbol_definitions
        .iter()
        .map(|symbol| {
            let resolution = layout
                .symbol_resolutions
                .get(symbol.symbol_id)
                .with_context(|| {
                    format!(
                        "Missing resolution for exported symbol `{}`",
                        String::from_utf8_lossy(symbol.name)
                    )
                })?;

            let (address, mut flags) = if resolution.is_absolute() {
                (
                    resolution.raw_value,
                    object::macho::EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE.into(),
                )
            } else {
                (
                    resolution
                        .raw_value
                        .checked_sub(image_base)
                        .with_context(|| {
                            format!(
                                "Exported symbol `{}` is before the Mach-O image base",
                                String::from_utf8_lossy(symbol.name)
                            )
                        })?,
                    object::macho::ExportSymbolFlags(0),
                )
            };

            if exported_symbol_is_weak(layout, symbol.symbol_id)? {
                flags |= object::macho::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
            }

            Ok(crate::trie::Symbol {
                name: symbol.name,
                address,
                flags,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(crate::trie::build(&mut symbols))
}

fn exported_symbol_is_weak(layout: &MachOLayout<'_>, symbol_id: SymbolId) -> Result<bool> {
    let file_id = layout.symbol_db.file_id_for_symbol(symbol_id);
    let FileLayout::Object(object) = layout.file_layout(file_id) else {
        return Ok(false);
    };
    let symbol_index = object.symbol_id_range.id_to_input(symbol_id);
    Ok(object.object.symbol(symbol_index)?.is_weak())
}

/// `DYLD_CHAINED_PTR_64_OFFSET` chains are defined independently per load segment and 16KiB
/// page. A chain can mix local rebases with imported binds; they differ only in the high bit of
/// the encoded pointer. Keeping the plan in VM-address order makes the on-disk starts table and
/// pointer `next` fields deterministic.
#[derive(Debug, PartialEq, Eq)]
struct ChainedFixups {
    segments: Vec<SegmentChainedFixups>,
}

#[derive(Debug, PartialEq, Eq)]
struct SegmentChainedFixups {
    /// Index into `Layout::segment_layouts.segments`, excluding the synthetic __PAGEZERO entry.
    segment_index: usize,
    segment_start: u64,
    page_starts: Vec<u16>,
    fixups: Vec<ChainedFixup>,
    next_by_fixup: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChainedFixup {
    address: u64,
    kind: ChainedFixupKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainedFixupKind {
    /// The index of the `dyld_chained_import` record for a dynamically imported symbol.
    Bind { import_index: usize },
    /// The link-time VM address of a local target. The wire format stores this relative to the
    /// image base for `DYLD_CHAINED_PTR_64_OFFSET`.
    Rebase { target: u64 },
}

fn plan_segment_chained_fixups(
    segment_index: usize,
    segment_start: u64,
    segment_size: u64,
    mut fixups: Vec<ChainedFixup>,
) -> Result<SegmentChainedFixups> {
    const POINTER_STRIDE: u64 = 4;
    const MAX_NEXT: u64 = (1 << 12) - 1;

    let page_size = MACHO_PAGE_ALIGNMENT.value();
    let segment_end = segment_start
        .checked_add(segment_size)
        .ok_or_else(|| error!("Mach-O segment range overflows the address space"))?;

    if fixups.is_empty() {
        return Ok(SegmentChainedFixups {
            segment_index,
            segment_start,
            page_starts: Vec::new(),
            fixups,
            next_by_fixup: Vec::new(),
        });
    }

    fixups.sort_by_key(|fixup| fixup.address);

    let mut locations = Vec::with_capacity(fixups.len());
    for (index, fixup) in fixups.iter().enumerate() {
        let address = fixup.address;
        if index != 0 {
            let previous_address = fixups[index - 1].address;
            ensure!(
                address > previous_address,
                "Mach-O chained fixups must have distinct addresses: {previous_address:#x} then {address:#x}"
            );
        }
        ensure!(
            address >= segment_start
                && address
                    .checked_add(GOT_ENTRY_SIZE)
                    .is_some_and(|end| end <= segment_end),
            "Mach-O chained fixup at {address:#x} is outside its segment"
        );
        ensure!(
            address % GOT_ENTRY_SIZE == 0,
            "Mach-O chained fixup at {address:#x} is not pointer aligned"
        );

        let segment_offset = address - segment_start;
        let page_index = usize::try_from(segment_offset / page_size)
            .map_err(|_| error!("Mach-O chained-fixup page index does not fit usize"))?;
        let page_offset = segment_offset % page_size;
        locations.push((page_index, page_offset, address));
    }

    let page_count = locations.last().unwrap().0 + 1;
    ensure!(
        page_count <= usize::from(u16::MAX),
        "Mach-O segment has too many pages for chained fixups"
    );
    let mut page_starts = vec![DYLD_CHAINED_PTR_START_NONE; page_count];
    let mut next_by_fixup = vec![0; fixups.len()];

    for (index, &(page_index, page_offset, address)) in locations.iter().enumerate() {
        ensure!(
            page_offset <= u64::from(u16::MAX),
            "Mach-O chained-fixup page offset does not fit"
        );

        if index == 0 || locations[index - 1].0 != page_index {
            page_starts[page_index] = page_offset as u16;
            continue;
        }

        let previous_address = locations[index - 1].2;
        let delta = address.checked_sub(previous_address).ok_or_else(|| {
            error!(
                "Mach-O chained fixups must be sorted by address: {previous_address:#x} then {address:#x}"
            )
        })?;
        ensure!(
            delta % POINTER_STRIDE == 0,
            "Mach-O chained-fixup distance {delta:#x} is not a chain stride"
        );
        let next = delta / POINTER_STRIDE;
        ensure!(
            next <= MAX_NEXT,
            "Mach-O chained-fixup distance {delta:#x} exceeds the next field"
        );
        next_by_fixup[index - 1] = next as u16;
    }

    Ok(SegmentChainedFixups {
        segment_index,
        segment_start,
        page_starts,
        fixups,
        next_by_fixup,
    })
}

fn image_base(layout: &MachOLayout<'_>) -> Result<u64> {
    layout
        .segment_layouts
        .segments
        .iter()
        .find(|segment| layout.program_segments.segment_def(segment.id).name == SegmentName::TEXT)
        .map(|segment| segment.sizes.mem_offset)
        .context("Mach-O chained fixups require a __TEXT segment")
}

fn segment_for_address<'layout, 'data>(
    layout: &'layout MachOLayout<'data>,
    address: u64,
    size: u64,
) -> Result<(usize, &'layout crate::layout::SegmentLayout)> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| error!("Mach-O chained-fixup address range overflows"))?;
    layout
        .segment_layouts
        .segments
        .iter()
        .enumerate()
        .find(|(_, segment)| {
            address >= segment.sizes.mem_offset
                && end <= segment.sizes.mem_offset.saturating_add(segment.sizes.mem_size)
        })
        .context("Mach-O chained fixup is outside all output segments")
}

fn file_offset_for_address(
    layout: &MachOLayout<'_>,
    address: u64,
    size: usize,
) -> Result<usize> {
    let (_, segment) = segment_for_address(layout, address, size as u64)?;
    let offset = address
        .checked_sub(segment.sizes.mem_offset)
        .and_then(|offset| segment.sizes.file_offset.checked_add(offset as usize))
        .context("Mach-O chained fixup file offset overflows")?;
    ensure!(
        offset.checked_add(size).is_some_and(|end| end <= segment.sizes.file_end()),
        "Mach-O chained fixup points into zero-fill data"
    );
    Ok(offset)
}

fn local_rebase_fixups(
    layout: &MachOLayout<'_>,
    output: &[u8],
) -> Result<Vec<ChainedFixup>> {
    let mut fixups = Vec::new();

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };

            for (section_index, slot) in object.sections.iter().enumerate() {
                if !matches!(slot, SectionSlot::Loaded(_)) {
                    continue;
                }
                let section_index = object::SectionIndex(section_index);
                let section_address = object.section_resolutions[section_index.0]
                    .address()
                    .context("loaded Mach-O section has no output address")?;

                for relocation in crate::macho::paired_relocations(
                    object.relocations(section_index)?.relocations,
                ) {
                    let relocation = relocation?;
                    let info = relocation.info;
                    // A 64-bit unsigned relocation writes a data pointer. Other absolute forms
                    // are instruction immediates or smaller scalar constants and must stay raw.
                    if info.r_type != object::macho::ARM64_RELOC_UNSIGNED
                        || info.r_length != 3
                        || info.r_pcrel
                    {
                        continue;
                    }
                    if !relocation_storage_is_live(object, section_index, info)? {
                        continue;
                    }
                    let Some(output_offset) =
                        object.output_offset_for_input(section_index, u64::from(info.r_address))
                    else {
                        continue;
                    };

                    let symbol_index = SymbolIndex(info.r_symbolnum as usize);
                    if info.r_extern
                        && tlv_descriptor_tls_data_start(
                            info,
                            section_index,
                            symbol_index,
                            object,
                            layout,
                        )?
                        .is_some()
                    {
                        // The data word in a local `__thread_vars` descriptor is a TLS-template
                        // offset, not an image pointer. Dyld must not slide it.
                        continue;
                    }

                    let address = section_address
                        .checked_add(output_offset)
                        .context("Mach-O rebase address overflows")?;
                    let file_offset = file_offset_for_address(layout, address, GOT_ENTRY_SIZE as usize)?;
                    let target = u64::from_le_bytes(
                        output[file_offset..file_offset + GOT_ENTRY_SIZE as usize]
                            .try_into()
                            .unwrap(),
                    );

                    // The relocation writer can also use ARM64_RELOC_UNSIGNED for an absolute
                    // scalar. Only a value that names this image is a dyld rebase.
                    if segment_for_address(layout, target, 0).is_ok() {
                        fixups.push(ChainedFixup {
                            address,
                            kind: ChainedFixupKind::Rebase { target },
                        });
                    }
                }
            }
        }
    }

    Ok(fixups)
}

/// A local `GOT_LOAD` relocation allocates a slot exactly like an imported symbol, but dyld must
/// slide the locally defined target rather than resolve an import. The old writer only populated
/// `format_specific.imported_symbols`, leaving these slots as zero. Rust's test formatter reaches
/// local trait-format functions through this path.
fn local_got_rebase_fixups(layout: &MachOLayout<'_>) -> Result<Vec<ChainedFixup>> {
    let mut fixups = Vec::new();
    let mut seen_got_addresses = BTreeSet::new();

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };

            for (section_index, slot) in object.sections.iter().enumerate() {
                if !matches!(slot, SectionSlot::Loaded(_)) {
                    continue;
                }
                let section_index = object::SectionIndex(section_index);

                for relocation in crate::macho::paired_relocations(
                    object.relocations(section_index)?.relocations,
                ) {
                    let relocation = relocation?;
                    let info = relocation.info;
                    if !info.r_extern
                        || !matches!(
                            info.r_type,
                            object::macho::ARM64_RELOC_GOT_LOAD_PAGE21
                                | object::macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12
                                | object::macho::ARM64_RELOC_POINTER_TO_GOT
                        )
                    {
                        continue;
                    }
                    if !relocation_storage_is_live(object, section_index, info)? {
                        continue;
                    }

                    let (_, _, local_symbol_id) = get_resolution(info, object, layout)?;
                    let symbol_id = layout.symbol_db.definition(local_symbol_id);
                    let FileLayout::Object(definition) = layout
                        .file_layout(layout.symbol_db.file_id_for_symbol(symbol_id))
                    else {
                        // Dynamic symbols use `ImportedSymbolWithResolution` and become binds.
                        continue;
                    };

                    let symbol_index = definition.symbol_id_range.id_to_input(symbol_id);
                    let symbol = definition.object.symbol(symbol_index)?;
                    let section_index = definition
                        .object
                        .symbol_section(symbol, symbol_index)?
                        .context("local Mach-O GOT target is not section-defined")?;
                    let section_address = definition.section_resolutions[section_index.0]
                        .address()
                        .context("local Mach-O GOT target section has no output address")?;
                    let target = section_address
                        .checked_add(
                            definition
                                .output_offset_for_input(
                                    section_index,
                                    definition
                                        .object
                                        .symbol_offset_in_section(symbol, section_index)?,
                                )
                                .context("local Mach-O GOT target is in a dead atom")?,
                        )
                        .context("local Mach-O GOT target address overflows")?;
                    let got_address = layout
                        .symbol_resolutions
                        .get(symbol_id)
                        .and_then(|resolution| resolution.format_specific.got_address)
                        .context("local Mach-O GOT relocation has no allocated GOT slot")?
                        .get();

                    if seen_got_addresses.insert(got_address) {
                        fixups.push(ChainedFixup {
                            address: got_address,
                            kind: ChainedFixupKind::Rebase { target },
                        });
                    }
                }
            }
        }
    }

    Ok(fixups)
}

fn chained_fixups(layout: &MachOLayout<'_>, output: &[u8]) -> Result<ChainedFixups> {
    let symbols = &layout.format_specific.imported_symbols;
    let got_layout = layout.section_layouts.get(output_section_id::GOT);
    let mut fixups_by_segment = (0..layout.segment_layouts.segments.len())
        .map(|_| Vec::new())
        .collect_vec();

    for (import_index, symbol) in symbols.iter().enumerate() {
        let address = symbol.got_address.get();
        ensure!(
            address >= got_layout.mem_offset
                && address
                    .checked_add(GOT_ENTRY_SIZE)
                    .is_some_and(|end| end <= got_layout.mem_offset + got_layout.mem_size),
            "Mach-O GOT bind at {address:#x} is outside __got"
        );
        let (segment_index, _) = segment_for_address(layout, address, GOT_ENTRY_SIZE)?;
        fixups_by_segment[segment_index].push(ChainedFixup {
            address,
            kind: ChainedFixupKind::Bind { import_index },
        });
    }

    for fixup in local_rebase_fixups(layout, output)? {
        let (segment_index, _) = segment_for_address(layout, fixup.address, GOT_ENTRY_SIZE)?;
        fixups_by_segment[segment_index].push(fixup);
    }

    for fixup in local_got_rebase_fixups(layout)? {
        let (segment_index, _) = segment_for_address(layout, fixup.address, GOT_ENTRY_SIZE)?;
        fixups_by_segment[segment_index].push(fixup);
    }

    let mut segments = Vec::new();
    for (segment_index, fixups) in fixups_by_segment.into_iter().enumerate() {
        if fixups.is_empty() {
            continue;
        }
        let segment = &layout.segment_layouts.segments[segment_index];
        segments.push(plan_segment_chained_fixups(
            segment_index,
            segment.sizes.mem_offset,
            segment.sizes.mem_size,
            fixups,
        )?);
    }

    Ok(ChainedFixups { segments })
}

fn chained_bind_word(ordinal: usize, next: u16) -> Result<u64> {
    ensure!(
        ordinal <= 0x00ff_ffff,
        "Mach-O chained-fixup import ordinal does not fit 24 bits"
    );
    ensure!(
        next <= 0x0fff,
        "Mach-O chained-fixup next value does not fit 12 bits"
    );

    Ok((1u64 << 63) | (u64::from(next) << 51) | ordinal as u64)
}

fn chained_rebase_word(target: u64, image_base: u64, next: u16) -> Result<u64> {
    const TARGET_BITS: u32 = 36;

    ensure!(
        next <= 0x0fff,
        "Mach-O chained-fixup next value does not fit 12 bits"
    );
    let target = target
        .checked_sub(image_base)
        .context("Mach-O chained rebase target is before the image base")?;
    ensure!(
        target < (1u64 << TARGET_BITS),
        "Mach-O chained rebase target does not fit 36 bits"
    );

    // DYLD_CHAINED_PTR_64_OFFSET stores a local target relative to the image base. `high8` is
    // zero because an in-image ARM64 pointer never needs bits above this 36-bit image offset.
    Ok((u64::from(next) << 51) | target)
}

fn write_chained_fixup_pointers(
    layout: &MachOLayout<'_>,
    chained_fixups: &ChainedFixups,
    output: &mut [u8],
) -> Result {
    let image_base = image_base(layout)?;

    for segment in &chained_fixups.segments {
        for (fixup, &next) in segment.fixups.iter().zip(&segment.next_by_fixup) {
            let encoded = match fixup.kind {
                ChainedFixupKind::Bind { import_index } => chained_bind_word(import_index, next)?,
                ChainedFixupKind::Rebase { target } => chained_rebase_word(target, image_base, next)?,
            };
            let file_offset = file_offset_for_address(layout, fixup.address, GOT_ENTRY_SIZE as usize)?;
            output[file_offset..file_offset + GOT_ENTRY_SIZE as usize]
                .copy_from_slice(&encoded.to_le_bytes());
        }
    }

    Ok(())
}

fn write_plt_entries<A: Arch<Platform = MachO>>(
    layout: &MachOLayout<'_>,
    plt: &mut [u8],
) -> Result {
    let plt_layout = layout.section_layouts.get(output_section_id::PLT_GOT);

    for imported_symbol in &layout.format_specific.imported_symbols {
        let Some(stub_address) = imported_symbol.plt_address else {
            continue;
        };

        let offset = stub_address
            .get()
            .checked_sub(plt_layout.mem_offset)
            .ok_or_else(|| error!("STUB entry address is before __stubs"))?
            as usize;
        let end = offset + PLT_ENTRY_SIZE as usize;

        A::write_plt_entry(
            &mut plt[offset..end],
            imported_symbol.got_address.get(),
            stub_address.get(),
        )?;
    }

    Ok(())
}

fn populate_file_header(
    layout: &MachOLayout,
    prelude: &PreludeLayout<MachO>,
    header: &mut FileHeader,
) {
    let load_commands_info = layout.section_layouts.get(LOAD_COMMANDS);

    header.magic.set(BigEndian, MH_CIGAM_64);
    header.cputype.set(LE, CPU_TYPE_ARM64);
    header.cpusubtype.set(LE, CPU_SUBTYPE_ARM64_ALL.into());
    header.filetype.set(
        LE,
        if layout.symbol_db.output_kind.is_shared_object() {
            MH_DYLIB
        } else {
            MH_EXECUTE
        },
    );
    header
        .ncmds
        .set(LE, prelude.format_specific.load_command_count as u32);
    header
        .sizeofcmds
        .set(LE, load_commands_info.file_size as u32);
    let mut flags = macho::MH_DYLDLINK | macho::MH_NOUNDEFS | macho::MH_TWOLEVEL;
    if layout.symbol_db.output_kind.is_executable() {
        flags |= macho::MH_PIE;
    }
    if layout.output_sections.ids_with_info().any(|(section_id, _)| {
        layout.output_sections.will_emit_section(section_id)
            && layout.output_sections.section_flags(section_id).typ()
                == macho::S_THREAD_LOCAL_VARIABLES
    }) {
        flags |= MH_HAS_TLV_DESCRIPTORS;
    }
    header.flags.set(LE, flags);
    header.reserved.set(LE, 0);
}

fn split_segment_command_buffer(
    mut bytes: &mut [u8],
    section_count: usize,
) -> Result<(&mut SegmentCommand, &mut [SectionEntry])> {
    let command = take_mut(&mut bytes)?;
    let (sections, rest) = slice_from_bytes_mut(bytes, section_count)
        .map_err(|_| error!("Invalid segment section allocation"))?;
    ensure!(
        rest.is_empty(),
        "Trailing bytes in segment command allocation"
    );
    Ok((command, sections))
}

fn write_segment_commands(layout: &MachOLayout, load_commands: &mut &mut [u8]) -> Result {
    let load_cmd_err = |()| error!("Invalid LOAD_COMMANDS allocation");
    let pagezero_segment = take_mut(load_commands)?;
    write_segment(
        SegmentName::PAGEZERO,
        macho::VmProt(0),
        pagezero_segment,
        0,
        0,
        0,
        MACHO_START_MEM_ADDRESS,
        0,
        SegmentFlags::default(),
    );

    for segment_layout in &layout.segment_layouts.segments {
        let segment_id = segment_layout.id;
        let segment_def = *layout.program_segments.segment_def(segment_id);

        let segment_sections = get_segment_sections(layout, segment_id);
        let section_count = segment_sections.len();
        let command_size = size_of::<SegmentCommand>() + size_of::<SectionEntry>() * section_count;

        let (segment, sections) = split_segment_command_buffer(
            load_commands
                .split_off_mut(..command_size)
                .ok_or_else(|| load_cmd_err(()))?,
            section_count,
        )?;

        let size = segment_layout.sizes;
        write_segment(
            segment_def.name,
            segment_def.prot,
            segment,
            size.file_offset as u64,
            size.file_size as u64,
            size.mem_offset,
            size.mem_size,
            section_count,
            segment_def.flags,
        );
        write_sections(segment_def.name, sections, &segment_sections);
    }

    Ok(())
}

fn write_segment(
    seg_name: SegmentName,
    prot_flags: object::macho::VmProt,
    segment_cmd: &mut SegmentCommand,
    file_offset: u64,
    file_size: u64,
    mem_offset: u64,
    mem_size: u64,
    section_count: usize,
    flags: macho::SegmentFlags,
) {
    segment_cmd.cmd.set(LE, LC_SEGMENT_64);
    segment_cmd.cmdsize.set(
        LE,
        (size_of::<SegmentCommand>() + size_of::<SectionEntry>() * section_count) as u32,
    );
    segment_cmd.segname = seg_name.into_bytes();
    segment_cmd.fileoff.set(LE, file_offset);
    segment_cmd.filesize.set(LE, file_size);
    segment_cmd.vmaddr.set(LE, mem_offset);
    segment_cmd.vmsize.set(LE, mem_size);
    segment_cmd.maxprot.set(LE, prot_flags);
    segment_cmd.initprot.set(LE, prot_flags);
    segment_cmd.nsects.set(LE, section_count as u32);
    segment_cmd.flags.set(LE, flags);
}

fn write_sections(
    seg_name: SegmentName,
    sections: &mut [SectionEntry],
    segment_sections: &[(
        OutputRecordLayout,
        SectionName<'_>,
        crate::macho::SectionFlags,
    )],
) {
    for (section, (size, section_name, section_flags)) in sections.iter_mut().zip(segment_sections)
    {
        let section_name = section_name.0;

        section.segname = seg_name.into_bytes();
        section.sectname[..section_name.len()].copy_from_slice(section_name);
        section.sectname[section_name.len()..].zero();
        section.addr.set(LE, size.mem_offset);
        section.size.set(LE, size.mem_size);
        section.offset.set(LE, size.file_offset as u32);
        section.align.set(LE, u32::from(size.alignment.exponent));
        section.reloff.set(LE, 0);
        section.nreloc.set(LE, 0);
        section.flags.set(LE, *section_flags);
        section.reserved1.set(LE, 0);
        // TODO: find a better place
        let reserved2 =
            if section_flags.0 & macho::SECTION_TYPE == u32::from(macho::S_SYMBOL_STUBS.0) {
                PLT_ENTRY_SIZE as u32
            } else {
                0
            };
        section.reserved2.set(LE, reserved2);
        section.reserved3.set(LE, 0);
    }
}

fn write_object<'data, A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter,
) -> Result {
    verbose_timing_phase!("Write object", file_id = object.file_id.as_u32());

    let _span = debug_span!("write_file", filename = %object.input).entered();
    let _file_span = layout.args().common().trace_span_for_file(object.file_id);
    for (i, sec) in object.sections.iter().enumerate() {
        match sec {
            SectionSlot::Loaded(sec) => {
                write_object_section::<A>(object, layout, *sec, object::SectionIndex(i), buffers)?;
            }
            _ => (),
        }
    }

    write_symbols(object, buffers, layout, symbol_writer)?;

    if object.owns_thunk_block
        && let Some(addresses) = layout
            .thunk_block_addresses
            .get(object.thunk_block_id.as_usize())
    {
        write_thunks::<A>(addresses, buffers, layout)?;
    }

    Ok(())
}

/// Emit one deterministic ARM64 range-extension island per target in an object-owned thunk
/// block. Layout has already reserved this exact space in the primary `__TEXT,__text` part, so
/// splitting the part buffer here puts an island directly after its owner object's code rather
/// than in the unrelated `__stubs` section.
fn write_thunks<'data, A: Arch<Platform = MachO>>(
    thunk_addresses: &BTreeMap<SymbolId, u64>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
) -> Result {
    if thunk_addresses.is_empty() {
        return Ok(());
    }

    let config = A::thunk_config().expect("Mach-O thunk addresses require a thunk configuration");
    let thunk_size = usize::try_from(config.thunk_size).context("Mach-O thunk size overflows usize")?;

    for (symbol_id, &thunk_address) in thunk_addresses {
        let resolution = layout.merged_symbol_resolution(*symbol_id).with_context(|| {
            format!(
                "No resolution for Mach-O branch island target {}",
                layout.symbol_db.symbol_name_for_display(*symbol_id)
            )
        })?;
        let target_address = resolution.raw_value;
        let thunk = buffers
            .get_mut(config.primary_function_part_id)
            .split_off_mut(..thunk_size)
            .ok_or_else(|| crate::file_writer::insufficient_allocation("Mach-O __text branch island"))?;

        A::write_thunk(thunk_address, target_address, thunk);
    }

    Ok(())
}

fn write_object_section<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout<'data>,
    section: Section,
    section_index: object::SectionIndex,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
) -> Result {
    let out = write_section_raw(object_layout, layout, section, section_index, buffers)?;

    let section_address = object_layout.section_resolutions[section_index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;

    for relocation in crate::macho::paired_relocations(
        object_layout.relocations(section_index)?.relocations,
    ) {
        let relocation = relocation?;
        let input_offset = u64::from(relocation.info.r_address);
        if !relocation_storage_is_live(object_layout, section_index, relocation.info)? {
            continue;
        }
        let Some(output_offset) = object_layout.output_offset_for_input(section_index, input_offset)
        else {
            // Mach-O stores all relocations for a section together. A relocation whose source is
            // in a discarded atom must neither be applied nor create a chained rebase later.
            continue;
        };
        apply_relocation::<A>(
            object_layout,
            section_index,
            section_address,
            output_offset,
            relocation.info,
            relocation.addend,
            layout,
            out,
        )?;
    }

    Ok(())
}

/// A final-atom end label can resolve to an output address, but it cannot be a relocation source:
/// applying an `r_length`-wide field there would write into the next object's allocation. Check
/// the complete field before compacting its input offset.
fn relocation_storage_is_live(
    object: &ObjectLayout<'_, MachO>,
    section_index: object::SectionIndex,
    relocation: RelocationInfo,
) -> Result<bool> {
    let input_offset = u64::from(relocation.r_address);
    let width = 1u64
        .checked_shl(u32::from(relocation.r_length))
        .context("Mach-O relocation width is invalid")?;
    let input_end = input_offset
        .checked_add(width)
        .context("Mach-O relocation source range overflows")?;
    Ok(object.input_range_is_live(section_index, input_offset..input_end))
}

#[inline(always)]
fn apply_relocation<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    source_section_index: object::SectionIndex,
    section_address: u64,
    output_offset: u64,
    rel: RelocationInfo,
    addend: i64,
    layout: &MachOLayout<'data>,
    out: &mut [u8],
) -> Result {
    let place = section_address + output_offset;

    let _span = tracing::trace_span!(
        "relocation",
        address = place,
        address_hex = %HexU64::new(place)
    )
    .entered();

    let rel_info = A::relocation_from_raw(rel)?;
    let (resolution, symbol_index, local_symbol_id) = get_resolution(rel, object_layout, layout)?;
    let flags = layout.flags_for_symbol(local_symbol_id);

    let mask = get_page_mask(rel_info.mask);
    let symbol_plus_addend = resolution.raw_value.wrapping_add(addend as u64);
    let mut value = match rel_info.kind {
        RelocationKind::Absolute => symbol_plus_addend.bitand(mask.symbol_plus_addend),
        RelocationKind::AbsoluteLowPart => symbol_plus_addend.bitand(mask.symbol_plus_addend),
        RelocationKind::Relative => symbol_plus_addend
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::GotRelative => symbol_plus_addend
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::Got => symbol_plus_addend.bitand(mask.symbol_plus_addend),
        _ => todo!(),
    };

    if let Some(tls_data_start) = tlv_descriptor_tls_data_start(
        rel,
        source_section_index,
        symbol_index,
        object_layout,
        layout,
    )? {
        value = tls_storage_offset(resolution.raw_value, tls_data_start)?;
    }

    if let Some(thunked_value) = maybe_get_thunk_for_relocation::<A>(
        object_layout,
        source_section_index,
        layout,
        rel_info,
        local_symbol_id,
        place,
        value,
    )? {
        value = thunked_value;
    }

    tracing::trace!(
            %flags,
            ?rel_info.kind,
            %rel_info.size,
            value,
            value_hex = %HexU64::new(value),
            addend,
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relocation applied");

    let output_offset = usize::try_from(output_offset)
        .context("Mach-O relocation output offset does not fit usize")?;
    let relocation_width = 1usize
        .checked_shl(u32::from(rel.r_length))
        .context("Mach-O relocation width is invalid")?;
    ensure!(
        output_offset
            .checked_add(relocation_width)
            .is_some_and(|end| end <= out.len()),
        "live Mach-O subsection ends inside relocation storage in {}: input offset 0x{:x} maps to output offset 0x{:x}, but {} bytes are required and this object's compacted section has {} bytes",
        object_layout.object.section_display_name(source_section_index),
        rel.r_address,
        output_offset,
        relocation_width,
        out.len(),
    );

    if rel.r_type == object::macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12 {
        rewrite_tlvp_load_as_add(&mut out[output_offset..])?;
    }

    rel_info
        .write_to_buffer(value, &mut out[output_offset..])
        .with_context(|| {
            format!(
                "Failed to apply relocation {} to {}",
                A::rel_type_to_string(rel),
                layout.symbol_debug(local_symbol_id)
            )
        })?;

    Ok(())
}

/// Replaces an out-of-range branch relocation with the assigned nearby island. Allocation is
/// decided after dead stripping, while the writer has the final addresses needed to decide
/// whether a direct `B`/`BL` remains in range.
fn maybe_get_thunk_for_relocation<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    source_section_index: object::SectionIndex,
    layout: &MachOLayout<'data>,
    rel_info: linker_utils::elf::RelocationKindInfo,
    local_symbol_id: SymbolId,
    place: u64,
    value: u64,
) -> Result<Option<u64>> {
    let Some(config) = A::thunk_config() else {
        return Ok(None);
    };
    if !rel_info.thunkable || rel_info.range.contains(value as i64) {
        return Ok(None);
    }

    let canonical_id = layout.symbol_db.definition(local_symbol_id);
    let source_part = object_layout
        .section_part_id(source_section_index, &layout.symbol_db.section_part_ids);
    let thunk_block = if source_part == config.primary_function_part_id {
        object_layout.thunk_block_id
    } else {
        ThunkBlockId::FIRST
    };

    let Some(thunk_address) = layout
        .thunk_block_addresses
        .get(thunk_block.as_usize())
        .and_then(|addresses| addresses.get(&canonical_id))
        .copied()
    else {
        bail!(
            "Mach-O branch relocation out of range by {over} for symbol {symbol}, but no branch island was allocated (part: {part})",
            over = rel_info.range.overrun(value as i64),
            symbol = layout.symbol_db.symbol_name_for_display(local_symbol_id),
            part = layout.output_sections.part_debug(source_part),
        );
    };
    ensure!(
        thunk_address != 0,
        "Mach-O branch island address was not assigned for {}",
        layout.symbol_db.symbol_name_for_display(local_symbol_id)
    );

    let mask = get_page_mask(rel_info.mask);
    let island_value = thunk_address
        .wrapping_add(rel_info.bias)
        .bitand(mask.symbol_plus_addend)
        .wrapping_sub(place.bitand(mask.place));
    ensure!(
        rel_info.range.contains(island_value as i64),
        "allocated Mach-O branch island for {} is still out of range",
        layout.symbol_db.symbol_name_for_display(local_symbol_id)
    );

    tracing::trace!(
        old_value = value,
        new_value = island_value,
        thunk_address,
        "using Mach-O ARM64 branch island"
    );
    Ok(Some(island_value))
}

/// Mach-O assemblers emit an unsigned-immediate `ldr` for a TLVP page-offset relocation. The
/// linker must turn that instruction into `add` before inserting the descriptor's low 12 bits:
/// TLVP computes the address of a `__thread_vars` descriptor, while the following instruction
/// loads and calls the descriptor's bootstrap pointer. Leaving the `ldr` in place dereferences
/// the descriptor address too early.
fn rewrite_tlvp_load_as_add(out: &mut [u8]) -> Result {
    const LDR_X_UNSIGNED_IMMEDIATE: u32 = 0xf940_0000;
    const LDR_X_UNSIGNED_IMMEDIATE_MASK: u32 = 0xffc0_0000;
    const ADD_X_IMMEDIATE: u32 = 0x9100_0000;
    const REGISTER_OPERANDS_MASK: u32 = 0x0000_03ff;

    ensure!(
        out.len() >= size_of::<u32>(),
        "ARM64_RELOC_TLVP_LOAD_PAGEOFF12 is outside of the input section"
    );
    let instruction = u32::from_le_bytes(out[..size_of::<u32>()].try_into().unwrap());
    ensure!(
        instruction & LDR_X_UNSIGNED_IMMEDIATE_MASK == LDR_X_UNSIGNED_IMMEDIATE,
        "ARM64_RELOC_TLVP_LOAD_PAGEOFF12 requires a 64-bit unsigned-immediate LDR, got instruction 0x{instruction:08x}"
    );

    // Both forms encode Xn at bits 5..10 and Xt/Xd at bits 0..5. The immediate is deliberately
    // discarded: it is replaced by the relocation with ADD's unscaled immediate encoding.
    let add = ADD_X_IMMEDIATE | (instruction & REGISTER_OPERANDS_MASK);
    out[..size_of::<u32>()].copy_from_slice(&add.to_le_bytes());
    Ok(())
}

/// A `tlv_descriptor` stores the target's byte offset in the image TLS template, rather than a
/// VM address. This only applies to the data-pointer relocation within
/// `S_THREAD_LOCAL_VARIABLES`; the preceding `__tlv_bootstrap` relocation remains a callable
/// address (or PLT stub).
fn tlv_descriptor_tls_data_start(
    rel: RelocationInfo,
    source_section_index: object::SectionIndex,
    symbol_index: SymbolIndex,
    object_layout: &ObjectLayout<'_, MachO>,
    layout: &MachOLayout<'_>,
) -> Result<Option<u64>> {
    if rel.r_type != object::macho::ARM64_RELOC_UNSIGNED {
        return Ok(None);
    }

    let source = object_layout.object.section(source_section_index)?;
    if source.flags.get(LE).typ() != macho::S_THREAD_LOCAL_VARIABLES {
        return Ok(None);
    }

    let target = object_layout.object.symbol(symbol_index)?;
    let Some(target_section_index) = object_layout.object.symbol_section(target, symbol_index)?
    else {
        return Ok(None);
    };
    let target_section = object_layout.object.section(target_section_index)?;
    if !matches!(
        target_section.flags.get(LE).typ(),
        macho::S_THREAD_LOCAL_REGULAR | macho::S_THREAD_LOCAL_ZEROFILL
    ) {
        return Ok(None);
    }

    layout
        .output_sections
        .ids_with_info()
        .filter(|(section_id, _)| layout.output_sections.will_emit_section(*section_id))
        .filter_map(|(section_id, _)| {
            matches!(
                layout.output_sections.section_flags(section_id).typ(),
                macho::S_THREAD_LOCAL_REGULAR | macho::S_THREAD_LOCAL_ZEROFILL
            )
            .then(|| layout.section_layouts.get(section_id).mem_offset)
        })
        .min()
        .context("TLV descriptor references TLS storage, but the output has no TLS storage section")
        .map(Some)
}

fn tls_storage_offset(symbol_address: u64, tls_data_start: u64) -> Result<u64> {
    symbol_address.checked_sub(tls_data_start).with_context(|| {
        format!(
            "TLV descriptor target address 0x{symbol_address:x} is before TLS storage start 0x{tls_data_start:x}"
        )
    })
}

fn write_section_raw<'out, 'data>(
    object: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout,
    sec: Section,
    section_index: object::SectionIndex,
    buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Result<&'out mut [u8]> {
    let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);
    if layout
        .output_sections
        .has_data_in_file(part_id.output_section_id::<MachO>())
    {
        let section_buffer = buffers.get_mut(part_id);
        let allocation_size = sec.capacity(part_id, &layout.output_sections) as usize;
        if section_buffer.len() < allocation_size {
            bail!(
                "Insufficient space allocated to section `{}`. Tried to take {} bytes, but only {} remain",
                object.object.section_display_name(section_index),
                allocation_size,
                section_buffer.len()
            );
        }
        let out = section_buffer.split_off_mut(..allocation_size).unwrap();
        let object_section = object.object.section(section_index)?;
        let (out, padding) = out.split_at_mut(sec.size as usize);

        if let Some(ranges) = object.live_input_ranges(section_index) {
            let input = object.object.raw_section_data(object_section)?;
            let mut output_offset = 0usize;
            for range in ranges {
                let input_start = usize::try_from(range.start)
                    .context("Mach-O subsection start does not fit usize")?;
                let input_end = usize::try_from(range.end)
                    .context("Mach-O subsection end does not fit usize")?;
                let span_size = input_end
                    .checked_sub(input_start)
                    .context("Mach-O subsection has an invalid range")?;
                let output_end = output_offset
                    .checked_add(span_size)
                    .context("Mach-O subsection output size overflows")?;
                ensure!(
                    output_end <= out.len(),
                    "Mach-O subsection copy exceeds its allocated output section"
                );

                // Zero-fill sections have no backing file data. For a partially backed section,
                // copy the available prefix and explicitly initialise the rest rather than
                // relying on an output-file implementation's initial contents.
                let copied_end = input_end.min(input.len());
                if input_start < copied_end {
                    out[output_offset..output_offset + copied_end - input_start]
                        .copy_from_slice(&input[input_start..copied_end]);
                }
                if copied_end < input_end {
                    out[output_offset + copied_end - input_start..output_end].fill(0);
                }
                output_offset = output_end;
            }
            ensure!(
                output_offset == out.len(),
                "Mach-O live-subsection sizes do not match section allocation"
            );
        } else {
            object.object.copy_section_data(object_section, out)?;
        }
        padding.fill(0);
        Ok(out)
    } else {
        Ok(&mut [])
    }
}

fn get_resolution<'data>(
    rel: RelocationInfo,
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout,
) -> Result<(Resolution<MachO>, SymbolIndex, SymbolId)> {
    let symbol_index = SymbolIndex(rel.r_symbolnum as usize);
    let local_symbol_id = object_layout.symbol_id_range.input_to_id(symbol_index);
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;
    let resolution = layout
        .merged_symbol_resolution(local_symbol_id)
        .or_else(|| {
            section_index.and_then(|section_index| {
                let section_address =
                    object_layout.section_resolutions[section_index.0].address()?;
                Some(Resolution {
                    raw_value: section_address,
                    dynamic_symbol_index: None,
                    flags: ValueFlags::empty(),
                    format_specific: Default::default(),
                })
            })
        })
        .with_context(|| {
            format!(
                "Missing resolution for: {}",
                layout.symbol_debug(local_symbol_id)
            )
        })?;
    Ok((resolution, symbol_index, local_symbol_id))
}

fn write_entry_point_command(layout: &MachOLayout, command: &mut EntryPointCommand) -> Result {
    let entry_name = match layout.symbol_db.entry_point() {
        crate::platform::EntryPoint::Symbol(name) => String::from_utf8_lossy(name),
        crate::platform::EntryPoint::None | crate::platform::EntryPoint::Address(_) => {
            bail!("Mach-O executable entry point must be a symbol")
        }
    };

    let entry_address = layout
        .resolved_entry_symbol_address()?
        .with_context(|| format!("entry symbol `{entry_name}` is not defined"))?;

    let image_base = layout
        .section_layouts
        .get(crate::output_section_id::FILE_HEADER)
        .mem_offset;

    let entry_offset = entry_address
        .checked_sub(image_base)
        .context("entry point is before the Mach-O image base")?;

    command.cmd.set(LE, LC_MAIN);
    command
        .cmdsize
        .set(LE, size_of::<EntryPointCommand>() as u32);
    command.entryoff.set(LE, entry_offset);
    command.stacksize.set(LE, 0);
    Ok(())
}

fn write_build_version_command(layout: &MachOLayout, command: &mut BuildVersionCommand) -> Result {
    let platform_version = layout
        .args()
        .platform_version
        .as_ref()
        .ok_or("platform_version must be set")?;

    command.cmd.set(LE, LC_BUILD_VERSION);
    command
        .cmdsize
        .set(LE, size_of::<BuildVersionCommand>() as u32);
    command.platform.set(LE, PLATFORM_MACOS);
    command
        .minos
        .set(LE, platform_version.minimum_version.get());
    command.sdk.set(LE, platform_version.sdk_version.get());
    command.ntools.set(LE, 0);
    // TODO: We could record Wild's version here, but Mach-O only defines tool IDs
    // for Apple toolchain components, so leave the tools list empty for now.
    Ok(())
}

fn write_uuid_command(command: &mut UuidCommand) {
    command.cmd.set(LE, LC_UUID);
    command.cmdsize.set(LE, size_of::<UuidCommand>() as u32);
    command.uuid.zero();
}

fn write_dylinker_command(command: &mut DylinkerCommand, path_buffer: &mut [u8]) {
    command.cmd.set(LE, LC_LOAD_DYLINKER);
    command.cmdsize.set(
        LE,
        ((size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
            .next_multiple_of(MACHO_COMMAND_ALIGNMENT)) as u32,
    );
    command
        .name
        .offset
        .set(LE, size_of::<DylinkerCommand>() as u32);

    path_buffer[0..DYLINKER_PATH.len()].copy_from_slice(DYLINKER_PATH);
    path_buffer[DYLINKER_PATH.len()..].zero();
}

fn write_dylib_command(
    command: &mut DylibCommand,
    path_buffer: &mut [u8],
    path: &[u8],
    command_type: macho::LoadCommandType,
) {
    command.cmd.set(LE, command_type);
    command
        .cmdsize
        .set(LE, load_dylib_command_size(path) as u32);
    command
        .dylib
        .name
        .offset
        .set(LE, size_of::<DylibCommand>() as u32);
    // TODO
    command.dylib.timestamp.set(LE, 2);
    // TODO
    command
        .dylib
        .current_version
        .set(LE, macho::Version(1356 << 16));
    command
        .dylib
        .compatibility_version
        .set(LE, macho::Version(1 << 16));

    path_buffer[0..path.len()].copy_from_slice(path);
    path_buffer[path.len()..].zero();
}

fn write_rpath_command(command: &mut RpathCommand, path_buffer: &mut [u8], path: &[u8]) {
    command.cmd.set(LE, LC_RPATH);
    command
        .cmdsize
        .set(LE, rpath_command_size(path) as u32);
    command
        .path
        .offset
        .set(LE, size_of::<RpathCommand>() as u32);

    path_buffer[..path.len()].copy_from_slice(path);
    path_buffer[path.len()..].zero();
}

fn write_dyld_chained_fixups_command(layout: &MachOLayout, command: &mut DyldChainedFixupsCommand) {
    let chained_fixup_table = layout
        .section_layouts
        .get(output_section_id::CHAINED_FIXUP_TABLE);

    command.cmd.set(LE, LC_DYLD_CHAINED_FIXUPS);
    command
        .cmdsize
        .set(LE, size_of::<DyldChainedFixupsCommand>() as u32);
    command
        .dataoff
        .set(LE, chained_fixup_table.file_offset as u32);
    command
        .datasize
        .set(LE, chained_fixup_table.file_size as u32);
}

fn write_exports_trie_command(
    layout: &MachOLayout,
    exports_trie: &[u8],
    command: &mut ExportsTrieCommand,
) -> Result {
    let exports_trie_layout = layout.section_layouts.get(output_section_id::EXPORTS_TRIE);

    command.cmd.set(LE, LC_DYLD_EXPORTS_TRIE);
    command
        .cmdsize
        .set(LE, size_of::<ExportsTrieCommand>() as u32);
    command.dataoff.set(
        LE,
        exports_trie_layout
            .file_offset
            .try_into()
            .context("Mach-O exports trie offset exceeds 32 bits")?,
    );
    command.datasize.set(
        LE,
        exports_trie
            .len()
            .try_into()
            .context("Mach-O exports trie size exceeds 32 bits")?,
    );
    Ok(())
}

fn write_symtab_command(layout: &MachOLayout, command: &mut SymtabCommand) {
    let symtab = layout.section_layouts.get(output_section_id::SYMTAB_GLOBAL);
    let strtab = layout.section_layouts.get(output_section_id::STRTAB);

    command.cmd.set(LE, LC_SYMTAB);
    command.cmdsize.set(LE, size_of::<SymtabCommand>() as u32);
    command.symoff.set(LE, symtab.file_offset as u32);
    command
        .nsyms
        .set(LE, (symtab.file_size / size_of::<SymtabEntry>()) as u32);
    command.stroff.set(LE, strtab.file_offset as u32);
    command.strsize.set(LE, strtab.file_size as u32);
}

fn write_code_signature_command(layout: &MachOLayout, command: &mut CodeSignatureCommand) {
    let code_signature = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);

    command.cmd.set(LE, LC_CODE_SIGNATURE);
    command
        .cmdsize
        .set(LE, size_of::<CodeSignatureCommand>() as u32);
    command.dataoff.set(LE, code_signature.file_offset as u32);
    command.datasize.set(LE, code_signature.file_size as u32);
}

fn write_chained_fixup_table(
    layout: &MachOLayout,
    chained_fixups: &ChainedFixups,
    chained_fixup_table: &mut [u8],
) -> Result {
    // The starts-in-image offset is 8-byte aligned while the packed header is 28 bytes. The
    // four-byte wire padding must not retain data from an update-in-place output: it contributes
    // to both the deterministic UUID hash and the code signature.
    chained_fixup_table.fill(0);

    let symbols = &layout.format_specific.imported_symbols;
    let active_segments = &layout.segment_layouts.segments;

    // The __PAGEZERO segment needs to be added manually.
    let segment_count = active_segments.len() + 1;
    ensure!(
        segment_count <= MAX_SEGMENT_COUNT,
        "unexpected number of active segments"
    );
    let starts_in_image_len = size_of::<u32>() * (segment_count + 1);
    let starts_in_segments_len = chained_fixups
        .segments
        .iter()
        .map(|segment| {
            CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE
                + segment.page_starts.len() * size_of::<u16>()
        })
        .sum::<usize>();
    let imports_len = size_of::<u32>() * symbols.len();

    let starts_offset = CHAINED_STARTS_IN_IMAGE_OFFSET;
    // `dyld_chained_import` is a packed u32 record. Segment-start records are only u16 aligned,
    // so a multi-segment table can otherwise leave imports at an invalid unaligned offset.
    let starts_and_segments_len = starts_in_image_len + starts_in_segments_len;
    let imports_offset = (starts_offset + starts_and_segments_len).next_multiple_of(size_of::<u32>());
    let symbols_offset = imports_offset + imports_len;

    let (header, rest) = from_bytes_mut::<ChainedFixupsHeader>(chained_fixup_table)
        .map_err(|_| error!("Invalid chained fixups header allocation"))?;
    let (_, rest) = rest.split_at_mut(starts_offset - size_of::<ChainedFixupsHeader>());
    let (starts_in_image, mut rest) = slice_from_bytes_mut::<U32<Endianness>>(rest, segment_count + 1)
        .map_err(|_| error!("Invalid chained fixups starts allocation"))?;

    // 1) fill up ChainedFixupsHeader
    header.fixups_version.set(LE, 0);
    header.starts_offset.set(LE, starts_offset as u32);
    header.imports_offset.set(LE, imports_offset as u32);
    header.symbols_offset.set(LE, symbols_offset as u32);
    header.imports_count.set(LE, symbols.len() as u32);
    header.imports_format.set(LE, DYLD_CHAINED_IMPORT);
    header.symbols_format.set(LE, 0);

    // 2) Fill `dyld_chained_starts_in_image`: `seg_count` followed by one relative offset for
    // each load command segment. __PAGEZERO occupies index 0, so active segment N uses N + 1.
    starts_in_image[0].set(LE, segment_count as u32);
    starts_in_image[1..].fill(U32::new(LE, 0));

    let starts_and_padding_bytes = rest
        .split_off_mut(..imports_offset - starts_offset - starts_in_image_len)
        .context("Invalid chained fixups segment-start allocation")?;
    let (starts_in_segment_bytes, padding) = starts_and_padding_bytes.split_at_mut(starts_in_segments_len);
    padding.fill(0);
    let (imports, string_pool) = slice_from_bytes_mut::<U32<Endianness>>(rest, symbols.len())
        .map_err(|_| error!("Invalid chained fixups imports allocation"))?;

    // 3) Emit one `dyld_chained_starts_in_segment` record for every segment that contains at
    // least one bind or rebase. The records are variable-sized because each includes all page
    // starts through its final chain page.
    let image_base = image_base(layout)?;
    let mut segment_bytes = starts_in_segment_bytes;
    let mut segment_offset_in_starts = starts_in_image_len;
    for segment in &chained_fixups.segments {
        let starts_in_segment_len = CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE
            + segment.page_starts.len() * size_of::<u16>();
        let bytes = segment_bytes
            .split_off_mut(..starts_in_segment_len)
            .context("Invalid chained fixups segment-start record allocation")?;
        let (starts_in_segment, _) = from_bytes_mut::<ChainedStartsInSegment>(bytes)
            .map_err(|_| error!("Invalid chained fixups starts in segment allocation"))?;

        // Accounts for both seg_count and the synthetic __PAGEZERO segment.
        starts_in_image[segment.segment_index + 2].set(
            LE,
            u32::try_from(segment_offset_in_starts)
                .context("Mach-O chained-fixup segment-start offset exceeds 32 bits")?,
        );
        segment_offset_in_starts += starts_in_segment_len;

        starts_in_segment.size.set(LE, starts_in_segment_len as u32);
        starts_in_segment
            .page_size
            .set(LE, MACHO_PAGE_ALIGNMENT.value() as u16);
        starts_in_segment
            .pointer_format
            .set(LE, DYLD_CHAINED_PTR_64_OFFSET);
        starts_in_segment.segment_offset.set(
            LE,
            segment
                .segment_start
                .checked_sub(image_base)
                .context("Mach-O chained-fixup segment is before __TEXT")?,
        );
        starts_in_segment.max_valid_pointer.set(LE, 0);
        starts_in_segment
            .page_count
            .set(LE, u16::try_from(segment.page_starts.len())?);
        let (page_starts, _) = slice_from_bytes_mut::<U16<Endianness>>(
            &mut bytes[CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE..],
            segment.page_starts.len(),
        )
        .map_err(|_| error!("Invalid chained fixups page starts allocation"))?;
        for (output, start) in page_starts.iter_mut().zip(&segment.page_starts) {
            output.set(LE, *start);
        }
    }

    // 4) fill up imports in the same order used by the GOT bind pointers.
    let sorted_symbols = symbols;
    let mut symbol_offsets = Vec::with_capacity(sorted_symbols.len());
    let mut str_offset = 0;
    for imported_symbol in sorted_symbols {
        let symbol_name = layout
            .symbol_db
            .symbol_name(imported_symbol.symbol_id)
            .unwrap()
            .bytes();
        string_pool[str_offset..str_offset + symbol_name.len()].copy_from_slice(symbol_name);
        string_pool[str_offset + symbol_name.len()] = b'\0';
        symbol_offsets.push(str_offset);
        str_offset += symbol_name.len() + 1;
    }

    // Emit `dyld_chained_import` that is built by 3 pieces:
    // lib_ordinal: 8
    // weak_import: 1
    // name_offset: 23
    for (i, imported_symbol) in sorted_symbols.iter().enumerate() {
        let file_id = layout
            .symbol_db
            .file_id_for_symbol(imported_symbol.symbol_id);

        let dynamic = match layout.file_layout(file_id) {
            FileLayout::StubLibrary(file) => &file.format_specific,
            FileLayout::Dynamic(file) => &file.format_specific,
            _ => {
                bail!("Internal error: Internal symbol refers to non-stub library");
            }
        };

        let lib_ordinal = dynamic.ordinal.get();

        imports[i].set(
            Endianness::Little,
            u32::from(lib_ordinal) | ((symbol_offsets[i] as u32) << 9),
        );
    }

    // Pad a couple of bytes (related to the MAX_SEGMENT_COUNT).
    string_pool[str_offset..].fill(0);

    Ok(())
}

fn write_uuid(layout: &MachOLayout, sized_output: &mut SizedOutput<impl OutputFileData>) -> Result {
    verbose_timing_phase!("Write UUID");

    let hash = blake3::Hasher::new()
        .update_rayon(&sized_output.out)
        .finalize();

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let load_commands = section_buffers.get_mut(output_section_id::LOAD_COMMANDS);

    while !load_commands.is_empty() {
        let header = object::from_bytes::<LoadCommand<Endianness>>(load_commands)
            .map_err(|_| error!("Invalid load command header"))?
            .0;
        let cmd_type = header.cmd.get(LE);
        let cmd_size = header.cmdsize.get(LE) as usize;
        let mut cmd = load_commands
            .split_off_mut(..cmd_size)
            .context("Invalid load command allocation")?;

        if cmd_type == LC_UUID {
            let uuid_cmd = take_mut::<UuidCommand>(&mut cmd)?;
            let uuid_size = uuid_cmd.uuid.len();

            uuid_cmd.uuid.copy_from_slice(&hash.as_bytes()[..uuid_size]);
            // Match lld's UUID Version 3 from RFC 9562.
            uuid_cmd.uuid[6] = (uuid_cmd.uuid[6] & 0x0f) | 0x30;
            uuid_cmd.uuid[8] = (uuid_cmd.uuid[8] & 0x3f) | 0x80;
            return Ok(());
        }
    }

    bail!("Missing LC_UUID");
}

fn write_code_signature_metadata(
    layout: &MachOLayout,
    sized_output: &mut SizedOutput<impl OutputFileData>,
) -> Result {
    verbose_timing_phase!("Write code signature metadata");

    let code_signature_section = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);
    let code_signature_identifier = code_signature_identifier(layout.args());
    let padded_identifier_size = code_signature_padded_identifier_size(layout.args()) as usize;

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let code_signature = section_buffers.get_mut(output_section_id::CODE_SIGNATURE);

    let encoder = CodeSignatureEncoder;
    let code_directory_size = encoder.code_directory_size(CS_SUPPORTSEXECSEG);
    ensure!(
        u64::from(code_directory_size) == CS_CODE_DIRECTORY_SIZE,
        "Unexpected code directory size"
    );

    let text_segment = layout
        .segment_layouts
        .segments
        .iter()
        .find(|segment| layout.program_segments.segment_def(segment.id).name == SegmentName::TEXT)
        .ok_or_else(|| error!("__TEXT segment is mandatory"))?;

    let code_directory = CodeDirectory {
        length: (code_signature_section.file_size - CS_BLOB_HEADERS_SIZE as usize) as u32,
        version: CS_SUPPORTSEXECSEG,
        flags: CS_ADHOC | CS_LINKER_SIGNED,
        hash_offset: code_directory_size + padded_identifier_size as u32,
        ident_offset: code_directory_size,
        n_special_slots: 0,
        n_code_slots: code_signature_section.file_offset.div_ceil(CS_BLOCK_SIZE) as u32,
        code_limit: code_signature_section.file_offset as u64,
        hash_size: CS_HASH_SIZE,
        hash_type: CS_HASHTYPE_SHA256,
        platform: 0,
        page_size: CS_BLOCK_SIZE_EXP,
        scatter_offset: 0,
        team_offset: 0,
        exec_seg_base: text_segment.sizes.file_offset as u64,
        exec_seg_limit: text_segment.sizes.file_size as u64,
        exec_seg_flags: layout
            .symbol_db
            .output_kind
            .is_executable()
            .then_some(CS_EXECSEG_MAIN_BINARY)
            .unwrap_or(macho::CsExecSegFlags(0)),
    };

    let mut rest: &mut [u8] = code_signature;
    encoder.signature_super_blob(&mut rest, code_signature_section.file_size as u32, 1);
    encoder.blob_index(&mut rest, CSSLOT_CODEDIRECTORY, CS_BLOB_HEADERS_SIZE as u32);
    encoder.code_directory(&mut rest, &code_directory);

    let (identifier, hashes) = rest.split_at_mut(padded_identifier_size);
    identifier[..code_signature_identifier.len()].copy_from_slice(code_signature_identifier);
    identifier[code_signature_identifier.len()..].zero();
    hashes.zero();

    Ok(())
}

fn write_code_signature_hashes(
    layout: &MachOLayout,
    sized_output: &mut SizedOutput<impl OutputFileData>,
) -> Result {
    verbose_timing_phase!("Write code signature hashes");

    let code_signature_section = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);
    let calculated_hashes: Vec<_> = sized_output.out[..code_signature_section.file_offset]
        .par_chunks(CS_BLOCK_SIZE)
        .map(Sha256::digest)
        .collect();
    let calculated_hashes = calculated_hashes.into_iter().flatten().collect_vec();

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let code_signature = section_buffers.get_mut(output_section_id::CODE_SIGNATURE);
    let hashes_offset =
        (CS_HEADERS_SIZE + code_signature_padded_identifier_size(layout.args())) as usize;
    let hashes = code_signature
        .get_mut(hashes_offset..)
        .ok_or_else(|| error!("Invalid CODE_SIGNATURE allocation"))?;

    hashes.copy_from_slice(&calculated_hashes);

    // Match lld's workaround for the macOS kernel caching signature-verification
    // data before the final code signature has been written:
    //
    // https://openradar.appspot.com/FB8914231
    sized_output
        .out
        .invalidate(code_signature_section.file_offset + code_signature_section.file_size);

    Ok(())
}

struct MachOSymbolTableWriter {
    next_strtab_offset: u32,
}

impl MachOSymbolTableWriter {
    fn write_str(&mut self, name: &[u8], buffers: &mut OutputSectionPartMap<&mut [u8]>) -> u32 {
        let len_with_terminator = name.len() + 1;
        let offset = self.next_strtab_offset;
        let out = buffers
            .get_mut(part_id::STRTAB)
            .split_off_mut(..len_with_terminator)
            .unwrap();
        out[..name.len()].copy_from_slice(name);
        out[name.len()] = 0;
        self.next_strtab_offset += len_with_terminator as u32;
        offset
    }

    #[inline(always)]
    fn define_symbol(
        &mut self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        name: &[u8],
        section: u8,
        symbol_type: object::macho::SymbolFlags,
        desc: object::macho::SymbolDesc,
        value: u64,
    ) -> Result {
        let entry = self.write_entry(name, buffers)?;
        entry.n_sect = section;
        entry.n_type = symbol_type;
        entry.n_value.set(LE, value);
        entry.n_desc.set(LE, desc);

        Ok(())
    }

    fn write_entry<'out>(
        &mut self,
        name: &[u8],
        buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
    ) -> Result<&'out mut SymtabEntry> {
        let string_offset = self.write_str(name, buffers);
        let entry_bytes = buffers
            .get_mut(part_id::SYMTAB_GLOBAL)
            .split_off_mut(..size_of::<SymtabEntry>())
            .unwrap();
        let entry: &mut SymtabEntry = from_bytes_mut(entry_bytes)
            .map_err(|_| error!("Invalid SYMTAB_GLOBAL entry allocation"))?
            .0;
        entry.n_strx.set(LE, string_offset);
        Ok(entry)
    }
}

fn write_symbols<'data>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter,
) -> Result {
    for ((sym_index, sym), flags) in object
        .object
        .enumerate_symbols()
        .zip(layout.per_symbol_flags.raw_range(object.symbol_id_range))
    {
        let symbol_id = object.symbol_id_range.input_to_id(sym_index);
        if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
            let input_offset = object
                .object
                .symbol_offset_in_section(sym, section_index)?;
            if !object.input_offset_is_live(section_index, input_offset) {
                continue;
            }
        }
        let Some(info) = SymbolCopyInfo::new(
            object.object,
            sym_index,
            sym,
            symbol_id,
            &layout.symbol_db,
            flags.get(),
            &object.sections,
        ) else {
            continue;
        };

        let mut value = 0;
        let (section, symbol_type, desc) =
            if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
                let section_id = match &object.sections[section_index.0] {
                    // String merging computes the symbol resolution through its explicit
                    // input-offset-to-output-offset map. The resulting symbol still belongs to
                    // the same output Mach-O section as an ordinary loaded section.
                    SectionSlot::Loaded(_) | SectionSlot::MergeStrings(_) => object
                        .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                        .output_section_id::<MachO>(),
                    _ => bail!(
                        "Tried to copy a symbol in a section we didn't load. {}",
                        layout.symbol_debug(symbol_id)
                    ),
                };
                let primary_id = layout.output_sections.primary_output_section(section_id);
                let n_type = sym.n_type.with_type(N_SECT);
                let n_sect = macho_section_index(layout, primary_id).with_context(|| {
                    format!(
                        "No Mach-O section index for {} while writing {}",
                        primary_id,
                        layout.symbol_debug(symbol_id)
                    )
                })?;
                let n_desc = sym.n_desc.get(LE);
                (n_sect, n_type, n_desc)
            } else if sym.is_absolute() {
                let n_desc = sym.n_desc.get(LE);
                (0, sym.n_type.with_type(N_ABS), n_desc)
            } else {
                bail!("Attempted to output a Mach-O symtab entry with an unexpected section type")
            };

        if let Some(res) = layout.local_symbol_resolution(symbol_id) {
            value = res.value_for_symbol_table();
        }

        symbol_writer.define_symbol(buffers, info.name, section, symbol_type, desc, value)?;
    }

    Ok(())
}

// TODO: This is inefficient; simplify it once load commands use a table allocator instead of
// being modeled as a section.
fn macho_section_index(layout: &MachOLayout<'_>, section_id: OutputSectionId) -> Result<u8> {
    // The section index is one-based.
    let mut section_idx = 1u8;
    for event in &layout.output_order {
        match event {
            OrderEvent::Section(current)
                if layout.output_sections.will_emit_section(current)
                    && layout
                        .output_sections
                        .identity(current)
                        .is_some_and(|identity| identity.format_specific().is_some()) =>
            {
                if current == section_id {
                    return Ok(section_idx);
                }
                section_idx = section_idx
                    .checked_add(1)
                    .ok_or(error!("Section index out of range (u8)"))?;
            }
            _ => {}
        }
    }

    bail!("cannot find the output section")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct AlignedBytes<const N: usize>([u8; N]);

    #[test]
    fn dylib_install_name_uses_an_id_load_command() {
        let path = b"@rpath/libexample.dylib";
        let mut command_bytes = AlignedBytes([0; size_of::<DylibCommand>()]);
        let command = from_bytes_mut::<DylibCommand>(&mut command_bytes.0).unwrap().0;
        let mut path_buffer =
            vec![0xff; load_dylib_command_size(path) - size_of::<DylibCommand>()];

        write_dylib_command(command, &mut path_buffer, path, LC_ID_DYLIB);

        assert_eq!(command.cmd.get(LE), LC_ID_DYLIB);
        assert_eq!(command.cmdsize.get(LE) as usize, load_dylib_command_size(path));
        assert_eq!(command.dylib.name.offset.get(LE) as usize, size_of::<DylibCommand>());
        assert_eq!(&path_buffer[..path.len()], path);
        assert!(path_buffer[path.len()..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn rpath_load_command_includes_a_nul_terminated_path() {
        let path = b"@loader_path/Frameworks";
        let mut command_bytes = AlignedBytes([0; size_of::<RpathCommand>()]);
        let command = from_bytes_mut::<RpathCommand>(&mut command_bytes.0).unwrap().0;
        let mut path_buffer =
            vec![0xff; rpath_command_size(path) - size_of::<RpathCommand>()];

        write_rpath_command(command, &mut path_buffer, path);

        assert_eq!(command.cmd.get(LE), LC_RPATH);
        assert_eq!(command.cmdsize.get(LE) as usize, rpath_command_size(path));
        assert_eq!(command.path.offset.get(LE) as usize, size_of::<RpathCommand>());
        assert_eq!(&path_buffer[..path.len()], path);
        assert!(path_buffer[path.len()..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn tlvp_pageoff_rewrites_ldr_to_add_preserving_registers() {
        // ldr x5, [x3, #0x40]
        let mut instruction = 0xf940_2065u32.to_le_bytes();

        rewrite_tlvp_load_as_add(&mut instruction).unwrap();

        // add x5, x3, #0; relocation application fills the immediate afterwards.
        assert_eq!(u32::from_le_bytes(instruction), 0x9100_0065);
        AArch64Instruction::Add.write_to_value(0x44, false, &mut instruction);
        assert_eq!(u32::from_le_bytes(instruction), 0x9101_1065);
    }

    #[test]
    fn tlvp_pageoff_rejects_non_ldr_instruction() {
        let mut instruction = 0x9100_0000u32.to_le_bytes();

        let error = rewrite_tlvp_load_as_add(&mut instruction).unwrap_err();

        assert!(error.to_string().contains("unsigned-immediate LDR"));
    }

    #[test]
    fn tlv_descriptor_data_pointer_is_an_offset_within_tls_storage() {
        assert_eq!(tls_storage_offset(0x1_0000_8014, 0x1_0000_8000).unwrap(), 0x14);

        let error = tls_storage_offset(0x1_0000_7ff8, 0x1_0000_8000).unwrap_err();
        assert!(error.to_string().contains("before TLS storage start"));
    }

    #[test]
    fn chained_fixups_start_a_new_chain_on_each_segment_page() {
        let page = MACHO_PAGE_ALIGNMENT.value();
        let plan = plan_segment_chained_fixups(
            3,
            0x1_0000,
            page * 2,
            vec![
                ChainedFixup {
                    address: 0x1_0000 + page - GOT_ENTRY_SIZE,
                    kind: ChainedFixupKind::Bind { import_index: 0 },
                },
                ChainedFixup {
                    address: 0x1_0000 + page + GOT_ENTRY_SIZE,
                    kind: ChainedFixupKind::Rebase {
                        target: 0x1_0000 + 0x40,
                    },
                },
            ],
        )
        .unwrap();

        assert_eq!(plan.segment_index, 3);
        assert_eq!(plan.page_starts, vec![(page - GOT_ENTRY_SIZE) as u16, GOT_ENTRY_SIZE as u16]);
        assert_eq!(plan.next_by_fixup, vec![0, 0]);
    }

    #[test]
    fn chained_rebase_is_image_relative_and_keeps_the_next_delta() {
        let encoded = chained_rebase_word(0x1_0000_03c0, 0x1_0000_0000, 2).unwrap();

        assert_eq!(encoded & ((1 << 36) - 1), 0x3c0);
        assert_eq!((encoded >> 51) & 0x0fff, 2);
        assert_eq!(encoded >> 63, 0);
    }

    #[test]
    fn compact_unwind_regular_page_preserves_personality_and_lsda() {
        let entries = [
            CompactUnwindEntry {
                function_address: MACHO_START_MEM_ADDRESS + 0x100,
                function_length: 0x20,
                encoding: 0x4400_0000,
                personality_address: Some(MACHO_START_MEM_ADDRESS + 0x4000),
                lsda_address: Some(MACHO_START_MEM_ADDRESS + 0x300),
            },
            CompactUnwindEntry {
                function_address: MACHO_START_MEM_ADDRESS + 0x200,
                function_length: 0x10,
                encoding: 0x0400_0000,
                personality_address: None,
                lsda_address: None,
            },
        ];

        let data = serialize_compact_unwind_info(
            &entries,
            &[MACHO_START_MEM_ADDRESS + 0x4000],
        )
        .unwrap();
        let word = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());

        assert_eq!(word(0), 1);
        assert_eq!(word(12), 28);
        assert_eq!(word(16), 1);
        assert_eq!(word(20), 32);
        assert_eq!(word(24), 2);
        assert_eq!(word(28), 0x4000);

        // The first top-level index points to one regular page and its sole LSDA descriptor.
        assert_eq!(word(32), 0x100);
        assert_eq!(word(36), 64);
        assert_eq!(word(40), 56);
        assert_eq!(word(44), 0x210);
        assert_eq!(word(48), 0);
        assert_eq!(word(52), 64);
        assert_eq!(word(56), 0x100);
        assert_eq!(word(60), 0x300);

        assert_eq!(word(64), 2);
        assert_eq!(u16::from_le_bytes(data[68..70].try_into().unwrap()), 8);
        assert_eq!(u16::from_le_bytes(data[70..72].try_into().unwrap()), 2);
        assert_eq!(word(72), 0x100);
        // The final representation assigns personality-table index one in bits 28..29.
        assert_eq!(word(76), 0x5400_0000);
        assert_eq!(word(80), 0x200);
        assert_eq!(word(84), 0x0400_0000);
    }
}
