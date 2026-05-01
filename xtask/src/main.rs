//! Workspace task runner. Invoked via `cargo xtask <task>` (alias defined
//! in `.cargo/config.toml`).

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};

mod vm;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let task = args.next();
    let rest: Vec<String> = args.collect();
    let result = match task.as_deref() {
        Some("check-test-infra") => check_test_infra(&rest),
        Some("test-infra-setup") => test_infra_setup(&rest),
        Some("integration") => integration(&rest),
        Some("vm-image") => vm::vm_image(&rest),
        Some("vm-integration") => vm::vm_integration(&rest),
        Some("help") | Some("-h") | Some("--help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("xtask: unknown task `{other}`\n");
            print_usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err:?}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("Usage: cargo xtask <task> [extra args]");
    eprintln!();
    eprintln!("Tasks:");
    eprintln!(
        "  check-test-infra   Diagnose dummy_hcd / ublk / usbmon / fio / tshark availability"
    );
    eprintln!(
        "  test-infra-setup   modprobe (sudo) the kernel modules the integration harness needs"
    );
    eprintln!(
        "  integration        Build the gadget+host CLIs and run the smoo-test-harness suite"
    );
    eprintln!("  vm-image build    Build the baked Fedora VM image used by vm-integration");
    eprintln!("  vm-image download Download the baked Fedora VM image from GHCR with oras");
    eprintln!("  vm-image ref      Print the deterministic GHCR ref for the VM image inputs");
    eprintln!(
        "  vm-integration     Boot a disposable Fedora VM and probe integration-test prerequisites"
    );
}

// ---------- check-test-infra ----------

fn check_test_infra(_extra: &[String]) -> Result<()> {
    let mut fail = 0u32;

    println!("Kernel capabilities:");
    let kernel: &[(&str, &dyn Fn() -> bool)] = &[
        ("configfs mounted at /sys/kernel/config", &|| {
            Path::new("/sys/kernel/config").is_dir()
        }),
        ("libcomposite available", &|| {
            Path::new("/sys/kernel/config/usb_gadget").is_dir() || modinfo_ok("libcomposite")
        }),
        ("usb_f_fs (FunctionFS function)", &|| modinfo_ok("usb_f_fs")),
        ("ublk_drv", &|| {
            Path::new("/dev/ublk-control").exists() || modinfo_ok("ublk_drv")
        }),
        ("usbmon (debugfs or /dev/usbmon*)", &|| {
            Path::new("/sys/kernel/debug/usb/usbmon").is_dir() || any_glob("/dev/usbmon0")
        }),
        ("dummy_hcd module", &|| modinfo_ok("dummy_hcd")),
        ("dummy_hcd LOADED (dummy_udc.0 present)", &|| {
            Path::new("/sys/class/udc/dummy_udc.0").exists()
        }),
    ];
    for (label, check) in kernel {
        report(label, check(), &mut fail);
    }

    println!();
    println!("Userspace tools:");
    let tools = [("tshark", "tshark"), ("dumpcap", "dumpcap"), ("fio", "fio")];
    for (label, bin) in tools {
        report(&format!("{label} on PATH"), which(bin).is_some(), &mut fail);
    }

    println!();
    if fail == 0 {
        println!("All checks passed.");
        return Ok(());
    }

    println!("{fail} check(s) failed.");
    println!(
        "  For kernel modules: try `cargo xtask test-infra-setup` (one-time per boot, requires sudo)."
    );
    println!(
        "  For userspace tools: install via your package manager (e.g. `dnf install wireshark fio`)."
    );
    bail!("{fail} prerequisite(s) missing")
}

fn report(label: &str, ok: bool, fail: &mut u32) {
    if ok {
        println!("  OK      {label}");
    } else {
        println!("  MISSING {label}");
        *fail += 1;
    }
}

fn modinfo_ok(name: &str) -> bool {
    Command::new("modinfo")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn any_glob(path: &str) -> bool {
    // We don't pull in a glob crate; just check the literal path. usbmon0
    // is the conventional first-bus node.
    Path::new(path).exists()
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------- test-infra-setup ----------

fn test_infra_setup(_extra: &[String]) -> Result<()> {
    // Optional modules: built-in (=y) on many kernels, so 'not found' is fine.
    for m in ["configfs", "libcomposite", "usb_f_fs"] {
        let _ = sudo_modprobe(m, &[]);
    }
    // Required: must succeed.
    sudo_modprobe("ublk_drv", &[])?;
    sudo_modprobe("usbmon", &[])?;
    sudo_modprobe("dummy_hcd", &["num_instances=4"])?;
    println!("kernel modules loaded.");
    Ok(())
}

fn sudo_modprobe(module: &str, params: &[&str]) -> Result<()> {
    let mut cmd = Command::new("sudo");
    cmd.arg("modprobe").arg(module);
    for p in params {
        cmd.arg(p);
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawn sudo modprobe {module}"))?;
    if !status.success() {
        bail!("sudo modprobe {module} failed: {status:?}");
    }
    Ok(())
}

// ---------- integration ----------

fn integration(extra: &[String]) -> Result<()> {
    // Build the gadget + host CLIs first so the harness can spawn them.
    run(
        "cargo",
        &[
            "build",
            "--bins",
            "-p",
            "smoo-gadget-cli",
            "-p",
            "smoo-host-cli",
        ],
    )?;

    // Run the test harness under sudo. Fedora's default sudoers has
    // `env_reset` with a narrow `env_keep` allowlist (LANG, DISPLAY, …) that
    // does not include RUST_LOG / SMOO_*, so `sudo -E` alone won't carry our
    // testing env vars through. We forward an explicit set via the `env`
    // shim. PATH is already needed so cargo/rustc can resolve.
    let path = std::env::var("PATH").unwrap_or_default();
    let mut cmd = Command::new("sudo");
    cmd.arg("-E").arg("env").arg(format!("PATH={path}"));
    for var in FORWARDED_ENV_VARS {
        if let Ok(val) = std::env::var(var) {
            cmd.arg(format!("{var}={val}"));
        }
    }
    cmd.arg("cargo")
        .arg("test")
        .arg("-p")
        .arg("smoo-test-harness")
        .arg("--")
        .arg("--test-threads=1")
        .arg("--nocapture");
    for a in extra {
        cmd.arg(a);
    }

    let status = cmd.status().with_context(|| format!("spawn {cmd:?}"))?;
    if !status.success() {
        bail!("integration tests failed: {status:?}");
    }
    Ok(())
}

/// Env vars forwarded through the sudo wrapper. RUST_LOG steers tracing in
/// every spawned smoo binary; RUST_BACKTRACE is useful when something panics;
/// SMOO_FULL_PCAP toggles the test-harness's full-payload capture
/// opt-in (see `crates/smoo-test-harness/src/scenario.rs`); SMOO_GADGET_PATH /
/// SMOO_HOST_PATH let contributors point the harness at custom-built CLI
/// binaries (see `binary_path` in `crates/smoo-test-harness/src/fixture.rs`).
const FORWARDED_ENV_VARS: &[&str] = &[
    "RUST_LOG",
    "RUST_BACKTRACE",
    "SMOO_FULL_PCAP",
    "SMOO_GADGET_PATH",
    "SMOO_HOST_PATH",
];

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    let status = cmd
        .status()
        .with_context(|| format!("spawn {prog} {args:?}"))?;
    if !status.success() {
        bail!("{prog} {args:?} failed: {status:?}");
    }
    Ok(())
}
