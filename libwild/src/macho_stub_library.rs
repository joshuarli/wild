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
//! without flattening every leaf into its root document.

use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::macho::DylibMetadata;
use crate::macho::DylibVersions;
use serde::Deserialize;
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
}

impl DefinedStubLibrary<'_> {
    pub(crate) fn total_symbols(&self) -> usize {
        self.symbols.len() + self.weak_symbols.len()
    }
}

pub fn parse_defined_library<'data>(input: &'data str) -> Result<DefinedStubLibrary<'data>> {
    let library_definitions = serde_yaml::Deserializer::from_str(input)
        .map(TextBasedDefinition::deserialize)
        .collect::<Result<Vec<_>, _>>()?;

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
        symbols: Vec::with_capacity(
            library_definitions
                .iter()
                .flat_map(TextBasedDefinition::all_exports)
                .map(|exp| exp.symbols.len())
                .sum(),
        ),
        weak_symbols: Vec::with_capacity(
            library_definitions
                .iter()
                .flat_map(TextBasedDefinition::all_exports)
                .map(|exp| exp.weak_symbols.len())
                .sum(),
        ),
    };

    let libraries_by_install_name: HashMap<_, _> = library_definitions
        .iter()
        .map(|library| (library.install_name, library))
        .collect();
    ensure!(
        libraries_by_install_name.len() == library_definitions.len(),
        "duplicate TBD install-name documents are unsupported"
    );

    // A framework can reexport a nested umbrella, which then describes its own children. Walk
    // only the arm64e-compatible graph reachable from the root: unrelated multi-document entries
    // do not become visible and nested leaves do not need a redundant root-level edge.
    let mut pending = VecDeque::from([main_library]);
    let mut visited = HashSet::new();
    while let Some(lib) = pending.pop_front() {
        if !visited.insert(lib.install_name) {
            continue;
        }
        ensure!(
            lib.tbd_version == 4,
            "TBD version 4 expected, got {}",
            lib.tbd_version
        );

        for export in lib.all_exports() {
            if export.targets.contains(&ARM64_LIB_ARCH) {
                defined_library.symbols.extend(export.symbols.iter());
                defined_library
                    .weak_symbols
                    .extend(export.weak_symbols.iter());
            }
        }

        for reexport in &lib.reexported_libraries {
            if !reexport.targets.contains(&ARM64_LIB_ARCH) {
                continue;
            }
            for &install_name in &reexport.libraries {
                let child = libraries_by_install_name.get(install_name).ok_or_else(|| {
                    error!(
                        "reexported library '{install_name}' is not defined by this TBD document"
                    )
                })?;
                pending.push_back(*child);
            }
        }
    }

    Ok(defined_library)
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
}
