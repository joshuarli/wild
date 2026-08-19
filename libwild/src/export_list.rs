use crate::error;
use crate::error::Result;
use crate::hash::PreHashed;
use crate::input_data::ScriptData;
use crate::linker_script::skip_comments_and_whitespace;
use crate::symbol::UnversionedSymbolName;
use crate::version_script::MatchRules;
use crate::version_script::SymbolLookupNameWrapper;
use crate::version_script::parse_matcher;
use winnow::BStr;
use winnow::Parser;

#[derive(Debug, Default)]
pub(crate) struct ExportList<'data>(MatchRules<'data>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportListStyle {
    /// GNU-style dynamic-symbol lists use the version-script matcher syntax.
    VersionScript,
    /// Darwin's `-exported_symbols_list` is one symbol matcher per line.
    MachO,
}

impl<'data> ExportList<'data> {
    pub(crate) fn parse(data: ScriptData<'data>) -> Result<Self> {
        parse_export_list
            .parse(BStr::new(data.raw))
            .map_err(|err| error!("Failed to parse symbol export list:\n{err}"))
    }

    pub(crate) fn parse_for_style(data: ScriptData<'data>, style: ExportListStyle) -> Result<Self> {
        match style {
            ExportListStyle::VersionScript => Self::parse(data),
            ExportListStyle::MachO => Self::parse_macho(data),
        }
    }

    pub(crate) fn parse_macho(data: ScriptData<'data>) -> Result<Self> {
        let mut export_list = Self::default();

        for (line_number, line) in data.raw.split(|&byte| byte == b'\n').enumerate() {
            let line = line
                .split(|&byte| byte == b'#')
                .next()
                .unwrap()
                .trim_ascii();
            if line.is_empty() {
                continue;
            }

            let symbol = std::str::from_utf8(line).map_err(|_| {
                error!(
                    "Invalid UTF-8 in Mach-O exported symbol list on line {}",
                    line_number + 1
                )
            })?;
            export_list.add_symbol(symbol, true)?;
        }

        Ok(export_list)
    }

    // Based on Version Script counterpart
    pub(crate) fn contains(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        let mut lookup_name = SymbolLookupNameWrapper::from_name(name);

        if self.0.general.matches_exact(&mut lookup_name, false)
            || self.0.cxx.matches_exact(&mut lookup_name, true)
        {
            return true;
        }

        for &non_star in &[true, false] {
            if self
                .0
                .general
                .matches_glob(&mut lookup_name, non_star, false)
                || self.0.cxx.matches_glob(&mut lookup_name, non_star, true)
            {
                return true;
            }
        }

        if self.0.general.matches_all() || self.0.cxx.matches_all() {
            return true;
        }

        false
    }

    pub(crate) fn add_symbol(&mut self, symbol: &'data str, without_semicolon: bool) -> Result<()> {
        let matcher = parse_matcher(&mut BStr::new(symbol), without_semicolon)?;
        self.0.push(matcher);
        Ok(())
    }
}

fn parse_export_list<'input>(input: &mut &'input BStr) -> winnow::Result<ExportList<'input>> {
    let mut out = ExportList::default();

    skip_comments_and_whitespace(input)?;

    '{'.parse_next(input)?;

    loop {
        skip_comments_and_whitespace(input)?;

        if input.starts_with(b"};") {
            "};".parse_next(input)?;
            skip_comments_and_whitespace(input)?;
            break;
        }

        let matcher = parse_matcher(input, false)?;
        out.0.push(matcher);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input_data::ScriptData;

    #[test]
    fn parse_inline() {
        let data = ScriptData {
            raw: b"{ f*; \"bar\"; extern \"C++\" { baz; qux; }; };",
        };
        let export_list = ExportList::parse(data).unwrap();
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"foo")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"bar")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"baz")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"qux")));
        assert!(!export_list.contains(&UnversionedSymbolName::prehashed(b"not_exported")));
    }

    #[test]
    fn parse_multiline_with_comments() {
        let data = ScriptData {
            raw: b"{
                    # Single line comment
                    foo;
                    \"bar\"; # With a quote

                    /*
                    * And a C-style comment
                    */
                    baz*;

                    extern \"C++\" {
                        qux; # C++ symbol
                    };
                };",
        };
        let export_list = ExportList::parse(data).unwrap();
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"foo")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"bar")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"baz-test")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"qux")));
        assert!(!export_list.contains(&UnversionedSymbolName::prehashed(b"not_exported")));
    }

    #[test]
    fn externs() {
        let data = ScriptData {
            raw: b"{
                    extern \"C\" {
                        foo;
                    };
                    extern \"C++\" {
                        bar;
                    };
                };",
        };
        let export_list = ExportList::parse(data).unwrap();
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"foo")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"bar")));
        assert!(!export_list.contains(&UnversionedSymbolName::prehashed(b"not_exported")));
    }

    #[test]
    fn parse_macho_symbol_list() {
        let data = ScriptData {
            raw: b"\n# Exported C and Rust symbols\n_foo\n_$s4test3bar\n",
        };
        let export_list = ExportList::parse_macho(data).unwrap();

        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"_foo")));
        assert!(export_list.contains(&UnversionedSymbolName::prehashed(b"_$s4test3bar")));
        assert!(!export_list.contains(&UnversionedSymbolName::prehashed(b"_private")));
    }
}
