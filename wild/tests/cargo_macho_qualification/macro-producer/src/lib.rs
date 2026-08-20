use proc_macro::TokenStream;
use std::str::FromStr as _;

#[proc_macro]
pub fn answer(_input: TokenStream) -> TokenStream {
    TokenStream::from_str("40 + 2").expect("the expansion is valid Rust")
}
