fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[
                "../proto/zone.proto",
                "../proto/container.proto",
                "../proto/image.proto",
                "../proto/sandbox.proto",
            ],
            &["../proto"],
        )?;
    Ok(())
}
