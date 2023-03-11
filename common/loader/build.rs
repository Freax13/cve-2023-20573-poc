use std::{env::current_dir, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root_dir = current_dir().unwrap().join("..").join("..");

    println!(
        "cargo:rerun-if-changed={}",
        root_dir.join("common").display()
    );
    println!("cargo:rerun-if-changed={}", root_dir.join("tee").display());

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root_dir.join("tee"));
    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
    cmd.arg("build").arg("-p").arg("kernel");
    cmd.arg("--target").arg("x86_64-unknown-none");
    cmd.arg("--target-dir").arg(&out_dir);
    cmd.arg("--release");

    let status = cmd.status().expect("failed to run cargo build for kernel");
    assert!(status.success(), "failed to build kernel");

    let path = out_dir
        .join("x86_64-unknown-none")
        .join("release")
        .join("kernel");
    assert!(
        path.exists(),
        "kernel executable does not exist after building"
    );
    println!("cargo:rustc-env=CARGO_BIN_FILE_KERNEL={}", path.display());
}
