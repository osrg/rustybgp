fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .compile_protos(
            &[
                "proto/gobgp.proto",
                "proto/attribute.proto",
                "proto/capability.proto",
            ],
            &["proto", "/usr/include/"],
        )?;
    Ok(())
}
