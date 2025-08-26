fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/auth.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true) // build client for testing
        .compile(&["proto/auth.proto"], &["proto"])?;
    Ok(())
}