// TODO
#![allow(unused_variables)]

use crate::bail;
use crate::ensure;
use crate::macho::MachO;
use crate::platform::PreviousRelocationInfo;
use linker_utils::elf::AArch64Instruction;
use linker_utils::elf::AllowedRange;
use linker_utils::elf::PAGE_MASK_4KB;
use linker_utils::elf::PageMask;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::elf::SIZE_4KB;
use linker_utils::elf::Sign;
use std::borrow::Cow;

pub(crate) struct MachOAArch64;

/// Validates the fixed fields of a relocation form that this linker can apply without inspecting
/// another relocation. Mach-O uses `r_length` for the storage width, not the instruction width.
/// Accepting a different value would make the generic writer patch the wrong number of bytes or
/// interpret a non-PC-relative value as PC-relative.
fn validate_standalone_relocation(
    rel: object::macho::RelocationInfo,
    name: &str,
    r_pcrel: bool,
    r_length: u8,
) -> crate::error::Result {
    ensure!(
        rel.r_extern,
        "{name} requires an external-symbol relocation; section relocations are not represented by the Mach-O writer"
    );
    ensure!(
        rel.r_pcrel == r_pcrel,
        "{name} requires r_pcrel={}, got {}",
        u8::from(r_pcrel),
        u8::from(rel.r_pcrel)
    );
    ensure!(
        rel.r_length == r_length,
        "{name} requires r_length={r_length}, got {}",
        rel.r_length
    );
    Ok(())
}

// ADRP+ADD+BR symbol stub template.
const STUB_TEMPLATE: &[u8] = &[
    0x10, 0x00, 0x00, 0x90, // ADRP x16, page(got)
    0x10, 0x02, 0x40, 0xf9, // LDR  x16, [x16, #off]
    0x00, 0x02, 0x1f, 0xd6, // BR   x16
];

// ADRP+ADD+BR range-extension island. Unlike a symbol stub, this reaches the final target
// directly and is placed in the primary `__TEXT,__text` allocation immediately after the object
// which owns the island. Keeping the veneer out of `__stubs` is essential: the stubs section is
// shared with dyld and can be outside the +/-128 MiB branch range.
const THUNK_TEMPLATE: &[u8] = &[
    0x10, 0x00, 0x00, 0x90, // ADRP x16, 0
    0x10, 0x02, 0x00, 0x91, // ADD  x16, x16, #0
    0x00, 0x02, 0x1f, 0xd6, // BR   x16
];

/// ARM64's `B` and `BL` relocations carry a signed, word-scaled 26-bit immediate.
const MIN_BRANCH_RANGE: u64 = 128 * 1024 * 1024;

const _ASSERTS: () = {
    assert!(STUB_TEMPLATE.len() as u64 == crate::macho::PLT_ENTRY_SIZE);
    assert!(THUNK_TEMPLATE.len() % 4 == 0);
};

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {}

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64) {
        todo!()
    }

    fn rel_info(&self) -> linker_utils::elf::RelocationKindInfo {
        todo!()
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        todo!()
    }

    fn next_modifier(&self) -> linker_utils::relaxation::RelocationModifier {
        todo!()
    }

    fn is_mandatory(&self) -> bool {
        todo!()
    }
}

impl crate::platform::Arch for MachOAArch64 {
    type Relaxation = Relaxation;

    type Platform = MachO;
    fn start_memory_address(_output_kind: crate::output_kind::OutputKind) -> u64 {
        crate::macho::MACHO_START_MEM_ADDRESS
    }
    fn arch_identifier() -> <Self::Platform as crate::platform::Platform>::ArchIdentifier {
        todo!()
    }

    fn get_dynamic_relocation_type(
        relocation: linker_utils::elf::DynamicRelocationKind,
    ) -> object::macho::RelocationInfo {
        todo!()
    }

    fn write_plt_entry(
        plt_entry: &mut [u8],
        got_address: u64,
        plt_address: u64,
    ) -> crate::error::Result {
        // TODO: For simplicity, we assume now the PLT entry precedes the GOT entry, so we can
        // make the offset calculation in the unsigned type.
        debug_assert!(plt_address < got_address);

        plt_entry.copy_from_slice(STUB_TEMPLATE);
        let plt_page_address = plt_address & !PAGE_MASK_4KB;
        let offset = got_address.wrapping_sub(plt_page_address);
        ensure!(
            offset < (1 << 32),
            "Mach-O stub is more than 4GiB away from GOT"
        );
        AArch64Instruction::Adr.write_to_value(offset / SIZE_4KB, false, &mut plt_entry[0..4]);
        AArch64Instruction::MachOLow12.write_to_value(
            offset & PAGE_MASK_4KB,
            false,
            &mut plt_entry[4..8],
        );
        Ok(())
    }

    fn relocation_from_raw(
        rel: object::macho::RelocationInfo,
    ) -> crate::error::Result<RelocationKindInfo> {
        let (kind, size, mask, range, alignment) = match rel.r_type {
            object::macho::ARM64_RELOC_UNSIGNED => {
                validate_standalone_relocation(rel, "ARM64_RELOC_UNSIGNED", false, 3)?;
                (
                    RelocationKind::Absolute,
                    RelocationSize::ByteSize(8),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            object::macho::ARM64_RELOC_BRANCH26 => {
                validate_standalone_relocation(rel, "ARM64_RELOC_BRANCH26", true, 2)?;
                (
                    RelocationKind::Relative,
                    RelocationSize::bit_mask_aarch64(2, 28, AArch64Instruction::JumpCall),
                    None,
                    AllowedRange::from_bit_size(28, Sign::Signed),
                    4,
                )
            }
            object::macho::ARM64_RELOC_PAGE21 => {
                validate_standalone_relocation(rel, "ARM64_RELOC_PAGE21", true, 2)?;
                (
                    RelocationKind::Relative,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_PAGEOFF12 => {
                validate_standalone_relocation(rel, "ARM64_RELOC_PAGEOFF12", false, 2)?;
                (
                    RelocationKind::AbsoluteLowPart,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::MachOLow12),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            object::macho::ARM64_RELOC_GOT_LOAD_PAGE21 => {
                validate_standalone_relocation(rel, "ARM64_RELOC_GOT_LOAD_PAGE21", true, 2)?;
                (
                    RelocationKind::GotRelative,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                validate_standalone_relocation(
                    rel,
                    "ARM64_RELOC_GOT_LOAD_PAGEOFF12",
                    false,
                    2,
                )?;
                (
                    RelocationKind::Got,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::MachOLow12),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            object::macho::ARM64_RELOC_POINTER_TO_GOT if rel.r_pcrel => {
                validate_standalone_relocation(rel, "ARM64_RELOC_POINTER_TO_GOT", true, 2)?;
                (
                    RelocationKind::GotRelative,
                    RelocationSize::ByteSize(4),
                    None,
                    AllowedRange::from_byte_size(4, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_POINTER_TO_GOT => {
                validate_standalone_relocation(rel, "ARM64_RELOC_POINTER_TO_GOT", false, 3)?;
                (
                    RelocationKind::Got,
                    RelocationSize::ByteSize(8),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            // Apple specifies these as adjacent relocation pairs. The current Mach-O loader and
            // writer normalize ADDEND with its following primary relocation before reaching this
            // architecture-specific conversion. Seeing it here means that normalization was
            // bypassed, so it cannot be interpreted independently.
            object::macho::ARM64_RELOC_ADDEND => bail!(
                "ARM64_RELOC_ADDEND must be normalized with its following relocation before architecture-specific processing"
            ),
            object::macho::ARM64_RELOC_SUBTRACTOR => bail!(
                "ARM64_RELOC_SUBTRACTOR must be normalized with its following ARM64_RELOC_UNSIGNED before architecture-specific processing"
            ),
            // On Mach-O, a local TLS symbol names its 24-byte `__thread_vars` descriptor rather
            // than a TLS offset. The TLVP instruction pair computes that descriptor's address;
            // the generated code then calls its bootstrap entry. Treat the pair as ordinary
            // page-relative addressing so the writer uses the local descriptor resolution.
            //
            // A descriptor imported from a dylib needs a runtime-bound TLVP slot, which is
            // rejected while processing relocations in `macho::process_relocation`.
            object::macho::ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                validate_standalone_relocation(rel, "ARM64_RELOC_TLVP_LOAD_PAGE21", true, 2)?;
                (
                    RelocationKind::Relative,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                validate_standalone_relocation(
                    rel,
                    "ARM64_RELOC_TLVP_LOAD_PAGEOFF12",
                    false,
                    2,
                )?;
                (
                    RelocationKind::AbsoluteLowPart,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::Add),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            // Authenticated pointers need arm64e signing metadata to be kept in the output
            // pointer. That representation does not exist in the generic Mach-O pipeline.
            object::macho::ARM64_RELOC_AUTHENTICATED_POINTER => bail!(
                "ARM64_RELOC_AUTHENTICATED_POINTER requires arm64e pointer-authentication support, which the relocation writer does not implement"
            ),
            _ => bail!("Unknown relocation: {}", rel.r_type),
        };
        Ok(RelocationKindInfo {
            alignment,
            bias: 0,
            kind,
            mask,
            range,
            size,
            thunkable: rel.r_type == object::macho::ARM64_RELOC_BRANCH26,
        })
    }

    fn rel_type_to_string(info: object::macho::RelocationInfo) -> Cow<'static, str> {
        let r_type = info.r_type;
        if let Some(name) = object::macho::NAMES_ARM64_RELOC.name(r_type) {
            Cow::Borrowed(name)
        } else {
            Cow::Owned(format!("Unknown arm64 relocation type 0x{r_type:x}"))
        }
    }

    fn tp_offset_start(layout: &crate::layout::Layout<Self::Platform>) -> u64 {
        todo!()
    }

    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass> {
        todo!()
    }

    fn merge_eflags(eflags: impl Iterator<Item = u32>) -> crate::error::Result<u32> {
        todo!()
    }

    fn high_part_relocations() -> &'static [object::macho::RelocationInfo] {
        todo!()
    }

    fn thunk_config() -> Option<crate::platform::ThunkConfig> {
        Some(crate::platform::ThunkConfig {
            primary_function_part_id: const {
                crate::macho::output_section_id::TEXT
                    .part_id_with_alignment::<crate::macho::MachO>(
                        crate::alignment::Alignment { exponent: 2 },
                    )
            },
            min_branch_range: MIN_BRANCH_RANGE,
            thunk_size: THUNK_TEMPLATE.len() as u64,
        })
    }

    fn write_thunk(thunk_address: u64, target_address: u64, buf: &mut [u8]) {
        debug_assert_eq!(buf.len(), THUNK_TEMPLATE.len());
        buf.copy_from_slice(THUNK_TEMPLATE);

        // The target can be anywhere in the Mach-O image, but an ADRP page delta itself is still
        // signed 21 bits. Failures would otherwise silently truncate the page displacement.
        let thunk_page = thunk_address & !PAGE_MASK_4KB;
        let target_page = target_address & !PAGE_MASK_4KB;
        let page_diff = (target_page as i64).wrapping_sub(thunk_page as i64);
        let page_count = (page_diff / SIZE_4KB as i64) as u64 & 0x1f_ffff;
        AArch64Instruction::Adr.write_to_value(page_count, false, &mut buf[0..4]);
        AArch64Instruction::Add.write_to_value(
            target_address & PAGE_MASK_4KB,
            false,
            &mut buf[4..8],
        );
    }

    fn get_source_info<'data>(
        object: &<Self::Platform as crate::platform::Platform>::File<'data>,
        relocations: &<Self::Platform as crate::platform::Platform>::RelocationSections,
        section: &<Self::Platform as crate::platform::Platform>::SectionHeader,
        offset_in_section: u64,
    ) -> crate::error::Result<crate::platform::SourceInfo> {
        Ok(crate::platform::SourceInfo(None))
    }

    fn new_relaxation(
        relocation_kind: object::macho::RelocationInfo,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: crate::value_flags::ValueFlags,
        output_kind: crate::output_kind::OutputKind,
        section_flags: <Self::Platform as crate::platform::Platform>::SectionFlags,
        relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
        _sym_addr: u64,
        _section_address: u64,
        _rel_addend: i64,
        _previous_relocation: Option<PreviousRelocationInfo<object::macho::RelocationInfo>>,
    ) -> Option<Self::Relaxation> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch;

    fn relocation(
        r_type: object::macho::RelocationType,
        r_pcrel: bool,
        r_length: u8,
    ) -> object::macho::RelocationInfo {
        object::macho::RelocationInfo {
            r_address: 0,
            r_symbolnum: 0,
            r_pcrel,
            r_length,
            r_extern: true,
            r_type,
        }
    }

    #[test]
    fn pointer_to_got_uses_the_got_address_and_its_abi_width() {
        let pc_relative = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_POINTER_TO_GOT,
            true,
            2,
        ))
        .unwrap();
        assert_eq!(pc_relative.kind, RelocationKind::GotRelative);
        assert_eq!(pc_relative.size, RelocationSize::ByteSize(4));
        assert!(pc_relative.range.contains(i64::from(i32::MIN)));
        assert!(pc_relative.range.contains(i64::from(i32::MAX)));
        assert!(!pc_relative.range.contains(i64::from(i32::MAX) + 1));

        let absolute = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_POINTER_TO_GOT,
            false,
            3,
        ))
        .unwrap();
        assert_eq!(absolute.kind, RelocationKind::Got);
        assert_eq!(absolute.size, RelocationSize::ByteSize(8));
    }

    #[test]
    fn rejects_malformed_branch26_instead_of_writing_the_wrong_instruction() {
        let error = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_BRANCH26,
            false,
            2,
        ))
        .unwrap_err();

        assert!(error.to_string().contains("ARM64_RELOC_BRANCH26"));
    }

    #[test]
    fn branch26_is_marked_thunkable() {
        let relocation = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_BRANCH26,
            true,
            2,
        ))
        .unwrap();

        assert!(relocation.thunkable);
        assert_eq!(MachOAArch64::thunk_config().unwrap().thunk_size, 12);
    }

    #[test]
    fn rejects_an_unpaired_addend_after_macho_normalization() {
        let error = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_ADDEND,
            false,
            2,
        ))
        .unwrap_err();

        assert!(error.to_string().contains("must be normalized"));
    }

    #[test]
    fn rejects_an_unpaired_subtractor_after_macho_normalization() {
        let error = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_SUBTRACTOR,
            false,
            3,
        ))
        .unwrap_err();

        assert!(error.to_string().contains("must be normalized"));
    }

    #[test]
    fn local_tlvp_loads_resolve_the_thread_variable_descriptor_directly() {
        let page = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_TLVP_LOAD_PAGE21,
            true,
            2,
        ))
        .unwrap();
        assert_eq!(page.kind, RelocationKind::Relative);
        assert!(matches!(
            page.mask,
            Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB))
        ));

        let pageoff = MachOAArch64::relocation_from_raw(relocation(
            object::macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
            false,
            2,
        ))
        .unwrap();
        assert_eq!(pageoff.kind, RelocationKind::AbsoluteLowPart);
    }
}
