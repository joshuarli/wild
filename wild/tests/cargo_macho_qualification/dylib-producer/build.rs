fn main() {
    println!("cargo:rerun-if-changed=build-marker.txt");
    let marker = std::fs::read_to_string("build-marker.txt")
        .expect("Cargo qualification build marker must be readable");
    println!("cargo:rustc-env=CARGO_MACHO_QUALIFICATION_BUILD_MARKER={}", marker.trim());
}
