use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rustc-rerun-if-changed=../.git/HEAD");
    let output = Command::new("git")
        .args(["rev-parse", "--short=10", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=GIT_HASH={git_hash}");
    tonic_prost_build::configure()
        .build_server(true)
        .compile_protos(
            &[
                "../api/gobgp.proto",
                "../api/attribute.proto",
                "../api/capability.proto",
            ],
            &["../api/", "/usr/include/"],
        )?;
    Ok(())
}
