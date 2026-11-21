// On a Mac, builds src/se.swift (the Secure Enclave part) into a static library linked into `keykin`.
use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/se.swift");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib = out.join("libkeykinse.a");
    let target = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64-apple-macosx13.0",
        _ => "x86_64-apple-macosx13.0",
    };
    let ok = Command::new("swiftc")
        .args(["-emit-library", "-static", "-parse-as-library", "-O", "-module-name", "KeykinSE", "-target", target, "-o"])
        .arg(&lib)
        .arg("src/se.swift")
        .status()
        .expect("swiftc (Xcode's command line tools) is needed to build keykin on a Mac");
    assert!(ok.success(), "swiftc failed on src/se.swift");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=keykinse");
    for f in ["CryptoKit", "LocalAuthentication", "Security", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={f}");
    }
    // The Swift runtime, from the toolchain and the system.
    let sdk = String::from_utf8(Command::new("xcrun").args(["--show-sdk-path"]).output().unwrap().stdout).unwrap();
    println!("cargo:rustc-link-search=native={}/usr/lib/swift", sdk.trim());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
