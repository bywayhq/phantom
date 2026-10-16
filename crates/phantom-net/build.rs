fn main() {
    println!("cargo:rerun-if-changed=native/macos_dns.c");
    println!("cargo:rerun-if-changed=native/macos_dns.h");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || std::env::var_os("CARGO_FEATURE_HTTPS_RECORDS").is_none()
    {
        return;
    }
    cc::Build::new()
        .file("native/macos_dns.c")
        .include("native")
        .std("c11")
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .compile("phantom_macos_dns");
    println!("cargo:rustc-link-lib=resolv");
}
