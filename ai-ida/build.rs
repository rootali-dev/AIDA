use anyhow::Context as _;
use aya_build::{build_ebpf, Package, Toolchain};

fn main() -> anyhow::Result<()> {
    let package = Package {
        name: "ai-ida-ebpf",
        root_dir: "../ai-ida-ebpf",
        features: &[],
        no_default_features: false,
    };

    build_ebpf([package], Toolchain::default())
        .context("failed to build eBPF package")?;

    Ok(())
}
