// Windows: the daemon admits a pipe client only when it is an elevated
// administrator (or SYSTEM). A release build therefore carries a
// `requireAdministrator` manifest so Windows shows the UAC prompt at launch.
// Debug builds keep the default manifest: Tauri links the manifest into every
// target of the package, and an elevation-requiring unit-test executable
// cannot be started from a normal `cargo test` (OS error 740). Run a debug
// build from an elevated terminal instead.
const ADMIN_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let release = std::env::var("PROFILE")
        .map(|p| p == "release")
        .unwrap_or(false);
    let attrs = if release {
        tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(ADMIN_MANIFEST))
    } else {
        tauri_build::Attributes::new()
    };
    tauri_build::try_build(attrs).expect("failed to run tauri build script");
}
