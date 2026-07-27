use anyhow::Context as _;
use aya_build::{build_ebpf, Toolchain};

fn main() -> anyhow::Result<()> {
    // Construct Package from &str so it matches aya-build 0.2.0 API
    let package: aya_build::Package = "ai-ida-ebpf".into();

    build_ebpf([package], Toolchain::default())
        .context("failed to build eBPF package")?;

    Ok(())
}
