fn main() {
    // esp-hal supplies linkall.x for the selected chip. The current
    // esp-generate template adds it from the package build script so it is
    // ordered after any other linker scripts.
    println!("cargo:rustc-link-arg=-Tlinkall.x");
}
