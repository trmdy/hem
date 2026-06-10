fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    #[cfg(target_os = "macos")]
    {
        let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
        let info_plist = manifest_dir.join("macos/Info.plist");
        println!(
            "cargo:rustc-link-arg-bin=hemd=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            info_plist.display()
        );
        println!("cargo:rerun-if-changed={}", info_plist.display());
    }

    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/valhall/hem/v1/hem.proto"], &["../../proto"])?;

    println!("cargo:rerun-if-changed=../../proto/valhall/hem/v1/hem.proto");
    Ok(())
}
