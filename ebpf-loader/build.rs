// SPDX-License-Identifier: GPL-2.0-only\nuse anyhow::Context as _;
use aya_build::{build_ebpf, Package, Toolchain};

fn main() -> anyhow::Result<()> {
    let package = Package {
        name: "kernel-space",
        root_dir: "../kernel-space",
        features: &[],
        no_default_features: false,
    };

    build_ebpf([package], Toolchain::default())
        .context("failed to build eBPF package")?;

    Ok(())
}
