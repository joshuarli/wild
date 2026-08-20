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

fn parse_library_definitions<'data>(input: &'data str) -> Result<Vec<TextBasedDefinition<'data>>> {
    Ok(serde_yaml::Deserializer::from_str(input)
        .map(TextBasedDefinition::deserialize)
        .collect::<Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
