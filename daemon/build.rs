fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_server(true).compile(
        &[
            "../api/gobgp.proto",
            "../api/attribute.proto",
            "../api/capability.proto",
        ],
        &["../api/"],
    )?;
    Ok(())
}
