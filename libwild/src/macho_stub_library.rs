//! Parser for the Text-Based Stub (`.tbd`) library definitions used by Mach-O.
//!
//! This crate currently targets TBD format version 4 and extracts the
//! linker-visible symbol definitions (and weak symbols). To keep parsing
//! simple and efficient, the parser rejects escape sequences and returns
//! `&'data str` slices directly from the input.
//!
//! The parser accepts multi-document YAML TBD files. The first document is
//! treated as the main library. Additional documents are followed through their
//! `reexported-libraries` edges, so an umbrella can reexport another umbrella
//! without flattening every leaf into its root document. SDK stubs can instead
//! put a reexport in a separate TBD file; callers supply the lookup boundary
//! used to extend the same graph in that case.

use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::macho::DylibMetadata;
use crate::macho::DylibVersions;
use serde::Deserialize;
use colosseum::sync::Arena;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

const ARM64_LIB_ARCH: &str = "arm64e-macos";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct TextBasedDefinition<'a> {
    tbd_version: u32,
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    install_name: &'a str,
    #[serde(default)]
    current_version: &'a str,
    #[serde(default)]
    compatibility_version: &'a str,
    #[serde(default)]
    parent_umbrella: Vec<ParentUmbrella<'a>>,
    #[serde(default)]
    reexported_libraries: Vec<ReexportedLibraries<'a>>,
    #[serde(default)]
    exports: Vec<Exports<'a>>,
    #[serde(default)]
    reexports: Vec<Exports<'a>>,
}

impl<'a> TextBasedDefinition<'a> {
    fn all_exports(&self) -> impl Iterator<Item = &Exports<'a>> {
        self.exports.iter().chain(&self.reexports)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ParentUmbrella<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    umbrella: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ReexportedLibraries<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    libraries: Vec<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Exports<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(default)]
    #[serde(borrow)]
    symbols: Vec<&'a str>,
    #[serde(default)]
    #[serde(borrow)]
    weak_symbols: Vec<&'a str>,
    #[serde(default)]
    #[serde(borrow)]
    objc_classes: Vec<&'a str>,
}
// TODO: remove
#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct DefinedStubLibrary<'a> {
    /// Identity and ABI versions the linker must retain in the consumer load command.
    pub(crate) dylib: DylibMetadata<'a>,
    /// Global symbols defined by the library or by any reexported child library.
    pub(crate) symbols: Vec<&'a str>,
    /// Weak symbols defined by the library or by any reexported child library.
    pub(crate) weak_symbols: Vec<&'a str>,
    /// TAPI keeps Objective-C class names separate from ordinary Mach-O symbols. These are
    /// materialized into `symbols` once the input loader has an arena whose lifetime reaches the
    /// symbol database.
    objc_classes: Vec<&'a str>,
}

impl DefinedStubLibrary<'_> {
    pub(crate) fn total_symbols(&self) -> usize {
        self.symbols.len() + self.weak_symbols.len()
    }
}

impl<'data> DefinedStubLibrary<'data> {
    pub(crate) fn materialize_objc_class_symbols(
        &mut self,
        generated_symbol_names: &'data Arena<String>,
    ) {
        for class_name in &self.objc_classes {
            let class_symbol = generated_symbol_names.alloc(format!("_OBJC_CLASS_$_{class_name}"));
            let metaclass_symbol =
                generated_symbol_names.alloc(format!("_OBJC_METACLASS_$_{class_name}"));
            self.symbols.push(class_symbol.as_str());
            self.symbols.push(metaclass_symbol.as_str());
        }
    }
}

#[cfg(test)]
pub fn parse_defined_library<'data>(input: &'data str) -> Result<DefinedStubLibrary<'data>> {
    parse_defined_library_with_external_reexports(input, |install_name| {
        Err(error!(
            "reexported library '{install_name}' is not defined by this TBD document"
        ))
    })
}

/// Parses a TBD root and all ARM64-compatible reexports. `load_external_reexport` is called only
/// when a reexport is not another document in the current file. It must return data whose lifetime
/// is retained by the caller, because the resulting symbol names borrow the TBD text.
pub fn parse_defined_library_with_external_reexports<'data>(
    input: &'data str,
    mut load_external_reexport: impl FnMut(&str) -> Result<&'data str>,
) -> Result<DefinedStubLibrary<'data>> {
    let mut library_definitions = parse_library_definitions(input)?;

    let main_library = library_definitions
        .first()
        .ok_or_else(|| error!("root library must be defined"))?;
    ensure!(
        main_library.targets.contains(&ARM64_LIB_ARCH),
        "Library only supports {targets:?}, but we need {ARM64_LIB_ARCH}",
        targets = main_library.targets,
    );

    let mut defined_library = DefinedStubLibrary {
        dylib: DylibMetadata {
            install_name: main_library.install_name.as_bytes(),
            versions: DylibVersions::tbd(
                main_library.current_version,
                main_library.compatibility_version,
            )?,
        },
        symbols: Vec::new(),
        weak_symbols: Vec::new(),
        objc_classes: Vec::new(),
    };

    let mut libraries_by_install_name = HashMap::new();
    for (index, library) in library_definitions.iter().enumerate() {
        ensure!(
            libraries_by_install_name.insert(library.install_name, index).is_none(),
            "duplicate TBD install-name documents are unsupported"
        );
    }

    // A framework can reexport a nested umbrella, which then describes its own children. Walk
    // only the arm64e-compatible graph reachable from the root: unrelated multi-document entries
    // do not become visible and nested leaves do not need a redundant root-level edge. When an
    // SDK places a child into a separate TBD file (for example libiconv -> libcharset), append its
    // documents to this lookup graph but keep the root's dylib metadata above.
    let mut pending = VecDeque::from([0]);
    let mut visited = HashSet::new();
    while let Some(library_index) = pending.pop_front() {
        let library = &library_definitions[library_index];
        if !visited.insert(library.install_name) {
            continue;
        }
        ensure!(
            library.tbd_version == 4,
            "TBD version 4 expected, got {}",
            library.tbd_version
        );

        for export in library.all_exports() {
            if export.targets.contains(&ARM64_LIB_ARCH) {
                defined_library.symbols.extend(export.symbols.iter());
                defined_library
                    .weak_symbols
                    .extend(export.weak_symbols.iter());
                defined_library.objc_classes.extend(export.objc_classes.iter());
            }
        }

        let reexports: Vec<_> = library
            .reexported_libraries
            .iter()
            .filter(|reexport| reexport.targets.contains(&ARM64_LIB_ARCH))
            .flat_map(|reexport| reexport.libraries.iter().copied())
            .collect();
        for install_name in reexports {
            if let Some(&child_index) = libraries_by_install_name.get(install_name) {
                pending.push_back(child_index);
                continue;
            }

            let external_definitions = parse_library_definitions(load_external_reexport(install_name)?)?;
            let child_external_index = external_definitions
                .iter()
                .position(|library| library.install_name == install_name)
                .ok_or_else(|| {
                    error!(
                        "external TBD for reexported library '{install_name}' does not define that install name"
                    )
                })?;
            let first_external_index = library_definitions.len();
            for external_library in external_definitions {
                let external_index = library_definitions.len();
                ensure!(
                    libraries_by_install_name
                        .insert(external_library.install_name, external_index)
                        .is_none(),
                    "duplicate TBD install-name documents are unsupported"
                );
                library_definitions.push(external_library);
            }
            pending.push_back(first_external_index + child_external_index);
        }
    }

    Ok(defined_library)
}

/// Parses the small, regular TAPI-v4 subset emitted by current Xcode SDKs.
///
/// A large framework stub contains independent symbol lists for several architectures. Serde YAML
/// faithfully builds every one of those lists and we discard the non-ARM64 ones immediately
/// afterwards. The normal Cargo link opens Foundation, CoreFoundation, Security, and libSystem in
/// this form, so avoid allocating the irrelevant lists when the document uses the conventional
/// flow-sequence spelling. This is deliberately a recognizer rather than a second YAML parser:
/// quoted escapes, block sequences, aliases, or any other unfamiliar construct return `None` and
/// keep the complete `serde_yaml` implementation below as the compatibility and diagnostic path.
fn parse_standard_tapi_v4<'data>(input: &'data str) -> Option<Vec<TextBasedDefinition<'data>>> {
    split_tapi_documents(input)
        .map(parse_standard_tapi_document)
        .collect()
}

fn split_tapi_documents(input: &str) -> impl Iterator<Item = &str> {
    let mut document_start = 0;
    let mut documents = Vec::new();

    for (offset, _) in input.match_indices("\n---") {
        let next_document_start = offset + 1;
        documents.push(&input[document_start..next_document_start]);
        document_start = next_document_start;
    }

    documents.push(&input[document_start..]);
    documents.into_iter().filter(|document| !document.trim().is_empty())
}

fn parse_standard_tapi_document<'data>(document: &'data str) -> Option<TextBasedDefinition<'data>> {
    let tbd_version = scalar_value(top_level_value(document, "tbd-version")?)?.parse().ok()?;
    let targets = flow_sequence(top_level_value(document, "targets")?)?;
    let install_name = scalar_value(top_level_value(document, "install-name")?)?;
    let current_version = top_level_value(document, "current-version")
        .and_then(scalar_value)
        .unwrap_or("");
    let compatibility_version = top_level_value(document, "compatibility-version")
        .and_then(scalar_value)
        .unwrap_or("");

    Some(TextBasedDefinition {
        tbd_version,
        targets,
        install_name,
        current_version,
        compatibility_version,
        parent_umbrella: top_level_value(document, "parent-umbrella")
            .map_or(Some(Vec::new()), parse_standard_parent_umbrellas)?,
        reexported_libraries: top_level_value(document, "reexported-libraries")
            .map_or(Some(Vec::new()), parse_standard_reexported_libraries)?,
        exports: top_level_value(document, "exports")
            .map_or(Some(Vec::new()), parse_standard_exports)?,
        reexports: top_level_value(document, "reexports")
            .map_or(Some(Vec::new()), parse_standard_exports)?,
    })
}

/// Returns the part of a top-level YAML field after its colon, through the next top-level field.
/// The standard TAPI spelling keeps every nested list indented, so an unindented key is an
/// unambiguous boundary. Inputs outside that spelling are routed to serde instead.
fn top_level_value<'data>(document: &'data str, wanted: &str) -> Option<&'data str> {
    let mut value_start = None;
    let mut line_start = 0;

    for line in document.split_inclusive('\n') {
        let line_without_newline = line.trim_end_matches(['\n', '\r']);
        let is_top_level = !line_without_newline.starts_with([' ', '\t']);
        if is_top_level {
            if let Some(start) = value_start {
                return Some(&document[start..line_start]);
            }
            if let Some(value) = line_without_newline.strip_prefix(wanted)
                && let Some(value) = value.strip_prefix(':')
            {
                let value_offset = line_without_newline.len() - value.len();
                value_start = Some(line_start + value_offset);
            }
        }
        line_start += line.len();
    }

    value_start.map(|start| &document[start..])
}

fn parse_standard_reexported_libraries<'data>(block: &'data str) -> Option<Vec<ReexportedLibraries<'data>>> {
    standard_list_entries(block)
        .into_iter()
        .map(|entry| {
            let targets = flow_sequence(entry_value(entry, "targets")?)?;
            let libraries = flow_sequence(entry_value(entry, "libraries")?)?;
            Some(ReexportedLibraries { targets, libraries })
        })
        .collect()
}

fn parse_standard_parent_umbrellas<'data>(block: &'data str) -> Option<Vec<ParentUmbrella<'data>>> {
    standard_list_entries(block)
        .into_iter()
        .map(|entry| {
            Some(ParentUmbrella {
                targets: flow_sequence(entry_value(entry, "targets")?)?,
                umbrella: scalar_value(entry_value(entry, "umbrella")?)?,
            })
        })
        .collect()
}

fn parse_standard_exports<'data>(block: &'data str) -> Option<Vec<Exports<'data>>> {
    let mut exports = Vec::new();
    for entry in standard_list_entries(block) {
        let targets = flow_sequence(entry_value(entry, "targets")?)?;
        // The reader only exposes ARM64 symbols. Avoid parsing and allocating the much larger
        // x86_64 lists in SDK stubs; their target predicate would discard them below anyway.
        if !targets.iter().any(|target| *target == ARM64_LIB_ARCH) {
            continue;
        }
        exports.push(Exports {
            targets,
            symbols: optional_flow_sequence(entry_value(entry, "symbols"))?,
            weak_symbols: optional_flow_sequence(entry_value(entry, "weak-symbols"))?,
            objc_classes: optional_flow_sequence(entry_value(entry, "objc-classes"))?,
        });
    }
    Some(exports)
}

/// Splits a conventional TAPI nested sequence into the text after each `-` marker. The marker is
/// intentionally accepted only at an indented line start, keeping ordinary flow-sequence values
/// from being mistaken for YAML entries.
fn standard_list_entries(block: &str) -> Vec<&str> {
    let mut starts = Vec::new();
    let mut line_start = 0;
    for line in block.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.starts_with([' ', '\t'])
            && let Some(entry) = trimmed.trim_start().strip_prefix("- ")
        {
            let entry_offset = trimmed.len() - entry.len();
            starts.push(line_start + entry_offset);
        }
        line_start += line.len();
    }
    let mut entries = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(block.len());
        entries.push(&block[*start..end]);
    }
    entries
}

fn entry_value<'data>(entry: &'data str, wanted: &str) -> Option<&'data str> {
    let mut line_start = 0;
    for line in entry.split_inclusive('\n') {
        let line_without_newline = line.trim_end_matches(['\n', '\r']);
        let trimmed = line_without_newline.trim_start();
        let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if let Some(value) = trimmed.strip_prefix(wanted)
            && let Some(value) = value.strip_prefix(':')
        {
            let value_offset = line_without_newline.len() - value.len();
            return Some(&entry[line_start + value_offset..]);
        }
        line_start += line.len();
    }
    None
}

fn optional_flow_sequence<'data>(value: Option<&'data str>) -> Option<Vec<&'data str>> {
    value.map_or(Some(Vec::new()), flow_sequence)
}

/// Reads the flow-sequence spelling used by the Xcode SDK, returning slices of the original TBD.
/// Quoted strings with YAML escape/doubling rules deliberately decline the fast path so serde
/// retains responsibility for the general grammar.
fn flow_sequence<'data>(value: &'data str) -> Option<Vec<&'data str>> {
    let mut remainder = value.trim_start();
    remainder = remainder.strip_prefix('[')?;
    let mut values = Vec::new();

    loop {
        remainder = remainder.trim_start();
        if remainder.starts_with(']') {
            return Some(values);
        }

        let (item, rest) = if let Some(quoted) = remainder.strip_prefix('\'') {
            let end = quoted.find('\'')?;
            let item = &quoted[..end];
            if quoted[end + 1..].starts_with('\'') {
                return None;
            }
            (item, &quoted[end + 1..])
        } else {
            let end = remainder.find(|byte: char| {
                byte.is_ascii_whitespace() || matches!(byte, ',' | ']')
            })?;
            (&remainder[..end], &remainder[end..])
        };
        if item.is_empty() {
            return None;
        }
        values.push(item);

        remainder = rest.trim_start();
        if let Some(rest) = remainder.strip_prefix(',') {
            remainder = rest;
        } else if !remainder.starts_with(']') {
            return None;
        }
    }
}

fn scalar_value(value: &str) -> Option<&str> {
    let value = value.trim_start();
    if let Some(quoted) = value.strip_prefix('\'') {
        let end = quoted.find('\'')?;
        if quoted[end + 1..].starts_with('\'') {
            return None;
        }
        return Some(&quoted[..end]);
    }
    let end = value
        .find(|byte: char| byte.is_ascii_whitespace() || byte == '#')
        .unwrap_or(value.len());
    Some(&value[..end])
}

fn parse_library_definitions<'data>(input: &'data str) -> Result<Vec<TextBasedDefinition<'data>>> {
    if let Some(definitions) = parse_standard_tapi_v4(input) {
        return Ok(definitions);
    }

    parse_library_definitions_with_serde(input)
}

fn parse_library_definitions_with_serde<'data>(
    input: &'data str,
) -> Result<Vec<TextBasedDefinition<'data>>> {
    Ok(serde_yaml::Deserializer::from_str(input)
        .map(TextBasedDefinition::deserialize)
        .collect::<Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_tbd_is_rejected_before_reexport_traversal() {
        // The reexport graph assumes every document has the TAPI schema fields below. Make a
        // malformed root an input diagnostic, not an invalid partially-initialized library.
        let error = parse_defined_library(
            r"--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos ]
",
        )
        .expect_err("a TBD without an install-name must not parse");

        assert!(error.to_string().contains("install-name"));
    }

    #[test]
    fn fast_path_keeps_only_arm64_export_lists() {
        let input = r"--- !tapi-tbd
tbd-version: 4
targets: [ x86_64-macos, arm64e-macos ]
install-name: '/usr/lib/libFast.tbd'
exports:
  - targets: [ x86_64-macos ]
    symbols: [ _x86_only ]
  - targets: [ arm64e-macos ]
    symbols: [ _arm64 ]
    weak-symbols: [ _arm64_weak ]
    objc-classes: [ FastClass ]
";

        let definitions = parse_standard_tapi_v4(input).expect("standard TAPI should use fast path");
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].exports.len(), 1);
        assert_eq!(definitions[0].exports[0].symbols, ["_arm64"]);

        let mut library = parse_defined_library(input).expect("definition should parse");
        let arena = Arena::new();
        library.materialize_objc_class_symbols(&arena);
        assert_eq!(
            library.symbols,
            ["_arm64", "_OBJC_CLASS_$_FastClass", "_OBJC_METACLASS_$_FastClass"]
        );
        assert_eq!(library.weak_symbols, ["_arm64_weak"]);
    }

    #[test]
    fn nonstandard_yaml_defers_to_serde_parser() {
        let input = r"--- !tapi-tbd
tbd-version: 4
targets:
  - arm64e-macos
install-name: '/usr/lib/libFallback.tbd'
exports:
  - targets:
      - arm64e-macos
    symbols: [ _fallback ]
";

        assert!(parse_standard_tapi_v4(input).is_none());
        let library = parse_defined_library(input).expect("serde fallback should parse block lists");
        assert_eq!(library.symbols, ["_fallback"]);
    }

    #[test]
    fn parse_library_with_reexports() {
        let stub_library = parse_defined_library(
            r"--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64e-macos ]
install-name:    '/usr/lib/libMain.dylib'
current-version: 1.2.3
compatibility-version: 1.1
reexported-libraries:
  - targets:         [ x86_64-macos, arm64e-macos ]
    libraries:       [ '/usr/lib/libA.dylib', '/usr/lib/libB.dylib' ]
exports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _main_arm64 ]
    weak-symbols:    [ _main_weak_arm64 ]
  - targets:         [ x86_64-macos ]
    symbols:         [ _main_x86_64 ]
    weak-symbols:    [ _main_weak_x86_64 ]
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64e-macos ]
install-name:    '/usr/lib/libA.dylib'
current-version: 10
parent-umbrella:
  - targets:         [ x86_64-macos, arm64e-macos ]
    umbrella:        Main
exports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _a_arm64 ]
    weak-symbols:    [ _a_weak_arm64 ]
  - targets:         [ x86_64-macos ]
    symbols:         [ _a_x86_64 ]
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64e-macos ]
install-name:    '/usr/lib/libB.dylib'
current-version: 11
parent-umbrella:
  - targets:         [ x86_64-macos, arm64e-macos ]
    umbrella:        Main
exports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _b_arm64 ]
reexports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _b_exported_arm64 ]
    weak-symbols:    [ _b_weak_exported_arm64 ]
",
        )
        .expect("definition should parse");

        assert_eq!(stub_library.dylib.install_name, b"/usr/lib/libMain.dylib");
        assert_eq!(
            stub_library.dylib.versions,
            DylibVersions::tbd("1.2.3", "1.1").unwrap()
        );
        assert_eq!(
            stub_library.symbols,
            ["_main_arm64", "_a_arm64", "_b_arm64", "_b_exported_arm64"]
        );
        assert_eq!(
            stub_library.weak_symbols,
            [
                "_main_weak_arm64",
                "_a_weak_arm64",
                "_b_weak_exported_arm64"
            ]
        );
    }

    #[test]
    fn parses_versionless_root_and_nested_reexports() {
        let stub_library = parse_defined_library(
            r"--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos ]
install-name: '/usr/lib/libRoot.dylib'
reexported-libraries:
  - targets: [ arm64e-macos ]
    libraries: [ '/usr/lib/libIntermediate.dylib' ]
--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos ]
install-name: '/usr/lib/libIntermediate.dylib'
reexported-libraries:
  - targets: [ arm64e-macos ]
    libraries: [ '/usr/lib/libLeaf.dylib' ]
--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos ]
install-name: '/usr/lib/libLeaf.dylib'
exports:
  - targets: [ arm64e-macos ]
    symbols: [ _nested_leaf ]
",
        )
        .expect("versionless nested definition should parse");

        assert_eq!(stub_library.dylib.install_name, b"/usr/lib/libRoot.dylib");
        assert_eq!(stub_library.dylib.versions, DylibVersions::tbd("", "").unwrap());
        assert_eq!(stub_library.symbols, ["_nested_leaf"]);
    }

    #[test]
    fn parses_reexport_from_separate_tbd_file() {
        let root = r"--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos ]
install-name: '/usr/lib/libRoot.dylib'
reexported-libraries:
  - targets: [ arm64e-macos ]
    libraries: [ '/usr/lib/libChild.1.dylib' ]
exports:
  - targets: [ arm64e-macos ]
    symbols: [ _root ]
";
        let child = r"--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos ]
install-name: '/usr/lib/libChild.1.dylib'
exports:
  - targets: [ arm64e-macos ]
    symbols: [ _child ]
";

        let stub_library = parse_defined_library_with_external_reexports(root, |install_name| {
            assert_eq!(install_name, "/usr/lib/libChild.1.dylib");
            Ok(child)
        })
        .expect("separate reexport should parse");

        assert_eq!(stub_library.dylib.install_name, b"/usr/lib/libRoot.dylib");
        assert_eq!(stub_library.symbols, ["_root", "_child"]);
    }

    #[test]
    fn exposes_objc_class_and_metaclass_symbols() {
        let mut stub_library = parse_defined_library(
            r"--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos ]
install-name: '/usr/lib/libobjc.A.dylib'
exports:
  - targets: [ arm64e-macos ]
    objc-classes: [ NSObject ]
",
        )
        .expect("definition should parse");

        let arena = Arena::new();
        stub_library.materialize_objc_class_symbols(&arena);
        assert_eq!(stub_library.symbols, ["_OBJC_CLASS_$_NSObject", "_OBJC_METACLASS_$_NSObject"]);
    }
}
