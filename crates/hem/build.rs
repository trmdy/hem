fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .build_server(false)
        .build_client(true)
        .compile_protos(&["../../proto/valhall/hem/v1/hem.proto"], &["../../proto"])?;

    println!("cargo:rerun-if-changed=../../proto/valhall/hem/v1/hem.proto");
    Ok(())
}
