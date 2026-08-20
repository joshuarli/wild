fn main() {
    cc::Build::new()
        .cpp(true)
        .file("native.cc")
        .compile("cargo_macho_corpus_native_cpp");
}
