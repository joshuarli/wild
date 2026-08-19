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
use object::slice_from_bytes_mut;
use object::write::macho::CodeDirectory;
use object::write::macho::CodeSignatureEncoder;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use sha2::Digest;
use sha2::Sha256;
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
    write_got_entries(layout, section_buffers.get_mut(output_section_id::GOT))?;
    write_plt_entries::<A>(layout, section_buffers.get_mut(output_section_id::PLT_GOT))?;
    write_merged_strings(layout, &mut section_buffers);

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
    layout: &MachOLayout<'_>,
    exports_trie: &[u8],
) -> Result {
    verbose_timing_phase!("Write epilogue");
    write_chained_fixup_table(layout, buffers.get_mut(part_id::CHAINED_FIXUP_TABLE))?;
    let out = buffers.get_mut(part_id::EXPORTS_TRIE);
    ensure!(
        exports_trie.len() <= out.len(),
        "Mach-O exports trie exceeded its reserved size"
    );
    out[..exports_trie.len()].copy_from_slice(exports_trie);
    out[exports_trie.len()..].fill(0);

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

/// `DYLD_CHAINED_PTR_64` has one chain start per 16KiB page. The `next` field connects
/// every imported GOT bind in the same page, in four-byte units.
#[derive(Debug, PartialEq, Eq)]
struct GotChainedFixups {
    /// One entry for every `__DATA_CONST` page through the last GOT fixup.
    page_starts: Vec<u16>,
    /// Every GOT slot that dyld must process, in ascending address order.
    fixups: Vec<GotFixup>,
    /// The `next` field for each entry in `fixups`.
    next_by_fixup: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GotFixup {
    address: u64,
    /// The index of the `dyld_chained_import` record for a dynamically imported symbol.
    import_index: usize,
}

fn plan_got_chained_fixups(
    got_start: u64,
    got_size: u64,
    segment_start: u64,
    segment_size: u64,
    mut fixups: Vec<GotFixup>,
) -> Result<GotChainedFixups> {
    const POINTER_STRIDE: u64 = 4;
    const MAX_NEXT: u64 = (1 << 12) - 1;

    let page_size = MACHO_PAGE_ALIGNMENT.value();
    ensure!(
        got_start >= segment_start,
        "__got starts before its __DATA_CONST segment"
    );
    let got_end = got_start
        .checked_add(got_size)
        .ok_or_else(|| error!("__got range overflows the Mach-O address space"))?;
    let segment_end = segment_start
        .checked_add(segment_size)
        .ok_or_else(|| error!("__DATA_CONST range overflows the Mach-O address space"))?;
    ensure!(
        got_end <= segment_end,
        "__got is outside its __DATA_CONST segment"
    );

    if fixups.is_empty() {
        return Ok(GotChainedFixups {
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
                "Mach-O GOT fixups must have distinct addresses: {previous_address:#x} then {address:#x}"
            );
        }
        ensure!(
            address >= got_start && address.checked_add(GOT_ENTRY_SIZE).is_some_and(|end| end <= got_end),
            "Mach-O GOT fixup at {address:#x} is outside __got"
        );
        ensure!(
            address % GOT_ENTRY_SIZE == 0,
            "Mach-O GOT fixup at {address:#x} is not pointer aligned"
        );

        let segment_offset = address - segment_start;
        let page_index = usize::try_from(segment_offset / page_size)
            .map_err(|_| error!("dynamic GOT bind page index does not fit usize"))?;
        let page_offset = segment_offset % page_size;
        locations.push((page_index, page_offset, address));
    }

    let page_count = locations.last().unwrap().0 + 1;
    ensure!(
        page_count <= usize::from(u16::MAX),
        "__DATA_CONST has too many pages for Mach-O chained fixups"
    );
    let mut page_starts = vec![DYLD_CHAINED_PTR_START_NONE; page_count];
    let mut next_by_fixup = vec![0; fixups.len()];

    for (index, &(page_index, page_offset, address)) in locations.iter().enumerate() {
        ensure!(
            page_offset <= u64::from(u16::MAX),
            "Mach-O GOT fixup page offset does not fit chained fixups"
        );

        if index == 0 || locations[index - 1].0 != page_index {
            page_starts[page_index] = page_offset as u16;
            continue;
        }

        let previous_address = locations[index - 1].2;
        let delta = address.checked_sub(previous_address).ok_or_else(|| {
            error!(
                "Mach-O GOT fixups must be sorted by address: {previous_address:#x} then {address:#x}"
            )
        })?;
        ensure!(
            delta % POINTER_STRIDE == 0,
            "Mach-O GOT fixup distance {delta:#x} is not a chained-fixup stride"
        );
        let next = delta / POINTER_STRIDE;
        ensure!(
            next <= MAX_NEXT,
            "Mach-O GOT fixup distance {delta:#x} exceeds the chained-fixup next field"
        );
        next_by_fixup[index - 1] = next as u16;
    }

    Ok(GotChainedFixups {
        page_starts,
        fixups,
        next_by_fixup,
    })
}

fn got_chained_fixups(layout: &MachOLayout<'_>) -> Result<GotChainedFixups> {
    let symbols = &layout.format_specific.imported_symbols;
    let got_layout = layout.section_layouts.get(output_section_id::GOT);

    if symbols.is_empty() {
        return Ok(GotChainedFixups {
            page_starts: Vec::new(),
            fixups: Vec::new(),
            next_by_fixup: Vec::new(),
        });
    }

    let (_, data_const_segment) = layout
        .segment_layouts
        .segments
        .iter()
        .enumerate()
        .find(|(_, segment)| {
            layout.program_segments.segment_def(segment.id).name == SegmentName::DATA_CONST
        })
        .ok_or_else(|| error!("Mach-O GOT fixups require a __DATA_CONST segment"))?;

    let fixups = symbols
        .iter()
        .enumerate()
        .map(|(import_index, symbol)| GotFixup {
            address: symbol.got_address.get(),
            import_index,
        })
        .collect_vec();

    plan_got_chained_fixups(
        got_layout.mem_offset,
        got_layout.mem_size,
        data_const_segment.sizes.mem_offset,
        data_const_segment.sizes.mem_size,
        fixups,
    )
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

fn write_got_entries(layout: &MachOLayout<'_>, got: &mut [u8]) -> Result {
    let got_layout = layout.section_layouts.get(output_section_id::GOT);
    let chained_fixups = got_chained_fixups(layout)?;
    for (fixup, &next) in chained_fixups
        .fixups
        .iter()
        .zip(&chained_fixups.next_by_fixup)
    {
        let offset: usize = fixup
            .address
            .checked_sub(got_layout.mem_offset)
            .ok_or_else(|| error!("GOT entry address is before __got"))?
            .try_into()
            .map_err(|_| error!("GOT entry offset does not fit the output file"))?;
        let end = offset
            .checked_add(GOT_ENTRY_SIZE as usize)
            .ok_or_else(|| error!("GOT entry range overflows the output file"))?;
        ensure!(
            end <= got.len(),
            "GOT entry is outside the allocated __got section"
        );

        /* DYLD_CHAINED_PTR_64 format:
        uint64_t dyld_chained_ptr_64_bind:
          ordinal: 24
          addend: 8 // 0 thru 255
          reserved: 19 // all zeros
          next: 12 // 4-byte stride
          bind: 1 // == 1
        */
        let encoded = chained_bind_word(fixup.import_index, next)?;
        got[offset..end].copy_from_slice(&encoded.to_le_bytes());
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
        apply_relocation::<A>(
            object_layout,
            section_index,
            section_address,
            relocation.info,
            relocation.addend,
            layout,
            out,
        )?;
    }

    Ok(())
}

#[inline(always)]
fn apply_relocation<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    source_section_index: object::SectionIndex,
    section_address: u64,
    rel: RelocationInfo,
    addend: i64,
    layout: &MachOLayout<'data>,
    out: &mut [u8],
) -> Result {
    let offset_in_section = u64::from(rel.r_address);
    let place = section_address + offset_in_section;

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

    tracing::trace!(
            %flags,
            ?rel_info.kind,
            %rel_info.size,
            value,
            value_hex = %HexU64::new(value),
            addend,
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relocation applied");

    if rel.r_type == object::macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12 {
        rewrite_tlvp_load_as_add(&mut out[offset_in_section as usize..])?;
    }

    rel_info
        .write_to_buffer(value, &mut out[offset_in_section as usize..])
        .with_context(|| {
            format!(
                "Failed to apply relocation {} to {}",
                A::rel_type_to_string(rel),
                layout.symbol_debug(local_symbol_id)
            )
        })?;

    Ok(())
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

        let section_size = object.object.section_size(object_section)?;
        let (out, padding) = out.split_at_mut(section_size as usize);
        object.object.copy_section_data(object_section, out)?;
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

fn write_chained_fixup_table(layout: &MachOLayout, chained_fixup_table: &mut [u8]) -> Result {
    // The starts-in-image offset is 8-byte aligned while the packed header is 28 bytes. The
    // four-byte wire padding must not retain data from an update-in-place output: it contributes
    // to both the deterministic UUID hash and the code signature.
    chained_fixup_table.fill(0);

    let symbols = &layout.format_specific.imported_symbols;
    let active_segments = &layout.segment_layouts.segments;
    let chained_fixups = got_chained_fixups(layout)?;

    // The __PAGEZERO segment needs to be added manually.
    let segment_count = active_segments.len() + 1;
    ensure!(
        segment_count <= MAX_SEGMENT_COUNT,
        "unexpected number of active segments"
    );
    let starts_in_image_len = size_of::<u32>() * (segment_count + 1);
    let starts_in_segment_len = CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE
        + chained_fixups.page_starts.len() * size_of::<u16>();
    let imports_len = size_of::<u32>() * symbols.len();

    let starts_offset = CHAINED_STARTS_IN_IMAGE_OFFSET;
    let imports_offset = starts_offset + starts_in_image_len + starts_in_segment_len;
    let symbols_offset = imports_offset + imports_len;

    let (header, rest) = from_bytes_mut::<ChainedFixupsHeader>(chained_fixup_table)
        .map_err(|_| error!("Invalid chained fixups header allocation"))?;
    let (_, rest) = rest.split_at_mut(starts_offset - size_of::<ChainedFixupsHeader>());
    let (starts_in_image, rest) = slice_from_bytes_mut::<U32<Endianness>>(rest, segment_count + 1)
        .map_err(|_| error!("Invalid chained fixups starts allocation"))?;

    // 1) fill up ChainedFixupsHeader
    header.fixups_version.set(LE, 0);
    header.starts_offset.set(LE, starts_offset as u32);
    header.imports_offset.set(LE, imports_offset as u32);
    header.symbols_offset.set(LE, symbols_offset as u32);
    header.imports_count.set(LE, symbols.len() as u32);
    header.imports_format.set(LE, DYLD_CHAINED_IMPORT);
    header.symbols_format.set(LE, 0);

    // 2) fill up dyld_chained_starts_in_image, which is `seg_count` (u32) followed by
    //    `seg_info_offset` ([u32; seg_count]); only __DATA_CONST,__got segment is covered
    starts_in_image[0].set(LE, segment_count as u32);
    starts_in_image[1..].fill(U32::new(LE, 0));

    // If __got has no bind, no starts table is needed.
    if chained_fixups.page_starts.is_empty() {
        rest.zero();
        return Ok(());
    }

    let (data_const_segment_index, data_const_segment) = active_segments
        .iter()
        .enumerate()
        .find(|(_, segment)| {
            layout.program_segments.segment_def(segment.id).name == SegmentName::DATA_CONST
        })
        .ok_or_else(|| error!("non-empty __got requires __DATA_CONST segment"))?;
    let text_segment = active_segments
        .iter()
        .find(|segment| {
            layout.program_segments.segment_def(segment.id).name == SegmentName::TEXT
        })
        .ok_or_else(|| error!("Mach-O chained fixups require a __TEXT segment"))?;

    // Accounts for both seg_count and __PAGEZERO.
    starts_in_image[data_const_segment_index + 2].set(LE, starts_in_image_len as u32);

    let (starts_in_segment_bytes, rest) = rest.split_at_mut(starts_in_segment_len);
    let (starts_in_segment, _) = from_bytes_mut::<ChainedStartsInSegment>(starts_in_segment_bytes)
        .map_err(|_| error!("Invalid chained fixups starts in segment allocation"))?;
    let (imports, string_pool) = slice_from_bytes_mut::<U32<Endianness>>(rest, symbols.len())
        .map_err(|_| error!("Invalid chained fixups imports allocation"))?;

    // 3) fill up DyldChainedStartsInSegment for the __got section
    starts_in_segment.size.set(LE, starts_in_segment_len as u32);
    starts_in_segment
        .page_size
        .set(LE, MACHO_PAGE_ALIGNMENT.value() as u16);
    starts_in_segment
        .pointer_format
        .set(LE, DYLD_CHAINED_PTR_64_OFFSET);
    starts_in_segment
        .segment_offset
        .set(
            LE,
            data_const_segment
                .sizes
                .mem_offset
                .checked_sub(text_segment.sizes.mem_offset)
                .ok_or_else(|| error!("__DATA_CONST is before __TEXT"))?,
        );
    starts_in_segment.max_valid_pointer.set(LE, 0);
    starts_in_segment
        .page_count
        .set(LE, u16::try_from(chained_fixups.page_starts.len())?);
    let (page_starts, _) = slice_from_bytes_mut::<U16<Endianness>>(
        &mut starts_in_segment_bytes[CHAINED_STARTS_IN_SEGMENT_FIXED_SIZE..],
        chained_fixups.page_starts.len(),
    )
    .map_err(|_| error!("Invalid chained fixups page starts allocation"))?;
    for (output, start) in page_starts.iter_mut().zip(&chained_fixups.page_starts) {
        output.set(LE, *start);
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
    fn chained_fixups_start_a_new_chain_on_each_got_page() {
        let page = MACHO_PAGE_ALIGNMENT.value();
        let plan = plan_got_chained_fixups(
            0x1_0000,
            page + 0x10,
            0x1_0000,
            page * 2,
            vec![
                GotFixup {
                    address: 0x1_0000 + page - GOT_ENTRY_SIZE,
                    import_index: 0,
                },
                GotFixup {
                    address: 0x1_0000 + page + GOT_ENTRY_SIZE,
                    import_index: 1,
                },
            ],
        )
        .unwrap();

        assert_eq!(plan.page_starts, vec![(page - GOT_ENTRY_SIZE) as u16, GOT_ENTRY_SIZE as u16]);
        assert_eq!(plan.next_by_fixup, vec![0, 0]);
    }
}
