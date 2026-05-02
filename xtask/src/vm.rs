use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};

const FEDORA_BASE_IMAGE_URL: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2";
const FEDORA_BASE_IMAGE_NAME: &str = "Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2";
const FEDORA_BASE_IMAGE_SHA256: &str =
    "846574c8a97cd2d8dc1f231062d73107cc85cbbbda56335e264a46e3a6c8ab2f";
const INTEGRATION_IMAGE_NAME: &str = "smoo-integration-vm.qcow2";
const INTEGRATION_IMAGE_SHA256_NAME: &str = "smoo-integration-vm.qcow2.sha256";
const INTEGRATION_IMAGE_MANIFEST_NAME: &str = "smoo-integration-vm.manifest.json";
const DEFAULT_OCI_IMAGE_REPOSITORY: &str = "ghcr.io/samcday/smoo-integration-vm";
const VM_IMAGE_SETUP_SCRIPT: &str = "tools/vm-image/guest-setup.sh";
const RUNTIME_SSH_USER: &str = "smoo";
const BAKE_SSH_USER: &str = "root";
const DEFAULT_BOOT_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_GUEST_PROBE_TIMEOUT: Duration = Duration::from_secs(900);
const DEFAULT_GUEST_HARNESS_TIMEOUT: Duration = Duration::from_secs(1800);
const DEFAULT_IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(1800);
const QMP_TIMEOUT: Duration = Duration::from_secs(30);
const GUEST_PAYLOAD_DIR: &str = "/tmp/smoo-vm-payload";
const GUEST_TARGET_DIR: &str = "/tmp/smoo-vm-target";

#[derive(Clone)]
struct BaseImage {
    path: PathBuf,
    url: String,
    sha256: String,
}

struct VmImageSpec {
    base_url: String,
    base_sha256: String,
    setup_script: String,
    setup_script_sha256: String,
    input_sha256: String,
    oci_ref: String,
}

struct HarnessTestBinary {
    name: String,
    executable: PathBuf,
}

struct HarnessPayload {
    local_dir: PathBuf,
    tests: Vec<String>,
}

pub fn vm_image(extra: &[String]) -> Result<()> {
    let Some((task, rest)) = extra.split_first() else {
        bail!("usage: cargo xtask vm-image <build|download>");
    };
    match task.as_str() {
        "build" => vm_image_build(rest),
        "download" => vm_image_download(rest),
        "ref" => vm_image_ref(rest),
        other => bail!("unknown vm-image task `{other}`; expected `build`, `download`, or `ref`"),
    }
}

fn vm_image_ref(extra: &[String]) -> Result<()> {
    if !extra.is_empty() {
        bail!("vm-image ref does not accept extra args yet");
    }
    let workspace = env::current_dir().context("resolve workspace directory")?;
    println!("{}", vm_image_spec(&workspace)?.oci_ref);
    Ok(())
}

fn vm_image_build(extra: &[String]) -> Result<()> {
    if !extra.is_empty() {
        bail!("vm-image build does not accept extra args yet");
    }

    let started = unix_time_secs();
    let workspace = env::current_dir().context("resolve workspace directory")?;
    let run_dir = create_run_dir(&workspace, "vm-image-build", started)?;
    let keep_requested = env_flag("SMOO_VM_KEEP", false);
    let accel = env::var("SMOO_VM_ACCEL").unwrap_or_else(|_| "kvm".to_string());
    let boot_timeout = env_duration("SMOO_VM_BOOT_TIMEOUT_SECS", DEFAULT_BOOT_TIMEOUT)?;
    let image_build_timeout = env_duration(
        "SMOO_VM_IMAGE_BUILD_TIMEOUT_SECS",
        DEFAULT_IMAGE_BUILD_TIMEOUT,
    )?;
    let output_image = default_integration_image_path(&workspace);
    let spec = vm_image_spec(&workspace)?;

    println!("vm-image build run dir: {}", run_dir.display());
    println!("vm-image build accelerator: {accel}");
    println!("vm-image output: {}", output_image.display());
    println!("vm-image OCI ref: {}", spec.oci_ref);

    let mut failure: Option<String> = None;
    let mut qemu: Option<Child> = None;
    let mut qmp: Option<QmpClient> = None;
    let mut ssh_port: Option<u16> = None;
    let mut overlay_for_finalize: Option<PathBuf> = None;
    let mut base_for_finalize: Option<BaseImage> = None;

    let result = (|| -> Result<()> {
        ensure_host_prereqs(&accel)?;
        ensure_tool("curl")?;
        ensure_tool("sha256sum")?;

        let base = resolve_fedora_base_image(&workspace, &spec)?;
        let overlay = run_dir.join("bake-overlay.qcow2");
        create_overlay(&base.path, &overlay)?;
        overlay_for_finalize = Some(overlay.clone());
        base_for_finalize = Some(base);

        let ssh_key = run_dir.join("id_ed25519");
        generate_ssh_key(&ssh_key)?;
        let seed = create_seed_image(&run_dir, &ssh_key, BAKE_SSH_USER)?;
        let port = allocate_local_port()?;
        ssh_port = Some(port);

        qemu = Some(spawn_qemu(&run_dir, &overlay, &seed, port, &accel)?);
        let qmp_path = run_dir.join("qmp.sock");
        let qemu_ref = qemu.as_mut().expect("qemu child just spawned");
        let mut qmp_client = QmpClient::connect(&qmp_path, &run_dir.join("qmp.log"), qemu_ref)?;
        qmp_client.negotiate()?;
        qmp_client.ensure_kvm_enabled(&accel)?;
        qmp = Some(qmp_client);

        wait_for_ssh(
            port,
            &ssh_key,
            BAKE_SSH_USER,
            boot_timeout,
            qemu.as_mut().unwrap(),
        )?;
        run_guest_script(
            "guest image setup",
            "guest-image-setup.stdout.log",
            "guest-image-setup.stderr.log",
            port,
            &ssh_key,
            BAKE_SSH_USER,
            &run_dir,
            &spec.setup_script,
            image_build_timeout,
        )?;
        Ok(())
    })();

    if let Err(err) = &result {
        failure = Some(format!("{err:#}"));
    }

    if failure.is_some()
        && let (Some(port), ssh_key) = (ssh_port, run_dir.join("id_ed25519"))
        && ssh_key.exists()
    {
        collect_guest_logs(port, &ssh_key, BAKE_SSH_USER, &run_dir);
    }

    let shutdown_result = shutdown_qemu(qmp.as_mut(), qemu.as_mut(), &run_dir);
    if failure.is_none()
        && let Err(err) = &shutdown_result
    {
        failure = Some(format!("{err:#}"));
    }

    let finalize_result = if failure.is_none() {
        let overlay = overlay_for_finalize
            .as_ref()
            .context("bake overlay path missing after successful image setup")?;
        let base = base_for_finalize
            .as_ref()
            .context("base image metadata missing after successful image setup")?;
        finalize_baked_image(&workspace, overlay, &output_image, base, &spec)
    } else {
        Ok(())
    };
    if failure.is_none()
        && let Err(err) = &finalize_result
    {
        failure = Some(format!("{err:#}"));
    }

    let keep_run_dir = keep_requested || failure.is_some();
    if keep_run_dir {
        println!("vm-image build artifacts retained at {}", run_dir.display());
    } else if let Err(err) = fs::remove_dir_all(&run_dir) {
        eprintln!(
            "vm-image build: failed to remove run dir {}: {err}",
            run_dir.display()
        );
    }

    result?;
    shutdown_result?;
    finalize_result?;
    println!("vm-image ready: {}", output_image.display());
    Ok(())
}

fn vm_image_download(extra: &[String]) -> Result<()> {
    if !extra.is_empty() {
        bail!("vm-image download does not accept extra args yet");
    }

    ensure_tool("oras")?;
    ensure_tool("sha256sum")?;
    let workspace = env::current_dir().context("resolve workspace directory")?;
    let image_dir = integration_image_dir(&workspace);
    fs::create_dir_all(&image_dir).with_context(|| format!("mkdir {}", image_dir.display()))?;
    let spec = vm_image_spec(&workspace)?;
    let image_ref = env::var("SMOO_VM_IMAGE_REF").unwrap_or_else(|_| spec.oci_ref.clone());
    let tmp_dir = image_dir.join(format!(
        ".oras-download-{}-{}",
        unix_time_secs(),
        std::process::id()
    ));
    fs::create_dir_all(&tmp_dir).with_context(|| format!("mkdir {}", tmp_dir.display()))?;

    println!("pulling VM image artifact: {image_ref}");
    let pull_result = run_checked(
        Command::new("oras")
            .arg("pull")
            .arg(&image_ref)
            .arg("--output")
            .arg(&tmp_dir),
        "pull VM image OCI artifact",
    );
    if let Err(err) = pull_result {
        let _ = fs::remove_dir_all(&tmp_dir);
        return Err(err);
    }

    let downloaded_image = tmp_dir.join(INTEGRATION_IMAGE_NAME);
    let downloaded_sha = tmp_dir.join(INTEGRATION_IMAGE_SHA256_NAME);
    let downloaded_manifest = tmp_dir.join(INTEGRATION_IMAGE_MANIFEST_NAME);
    if !downloaded_image.exists() {
        let _ = fs::remove_dir_all(&tmp_dir);
        bail!(
            "OCI artifact did not contain {INTEGRATION_IMAGE_NAME}; refusing to guess image name"
        );
    }
    if !downloaded_sha.exists() {
        let _ = fs::remove_dir_all(&tmp_dir);
        bail!(
            "OCI artifact did not contain {INTEGRATION_IMAGE_SHA256_NAME}; refusing unverified image"
        );
    }
    let expected = read_sha256_file(&downloaded_sha)?;
    verify_sha256(&downloaded_image, &expected)?;

    move_file_replace(
        &downloaded_image,
        &default_integration_image_path(&workspace),
    )?;
    move_file_replace(
        &downloaded_sha,
        &default_integration_image_sha256_path(&workspace),
    )?;
    if downloaded_manifest.exists() {
        move_file_replace(
            &downloaded_manifest,
            &default_integration_image_manifest_path(&workspace),
        )?;
    }
    fs::remove_dir_all(&tmp_dir).with_context(|| format!("remove {}", tmp_dir.display()))?;
    println!(
        "vm-image downloaded: {}",
        default_integration_image_path(&workspace).display()
    );
    Ok(())
}

pub fn vm_integration(extra: &[String]) -> Result<()> {
    if !extra.is_empty() {
        bail!("vm-integration does not accept extra args yet");
    }

    let started = unix_time_secs();
    let workspace = env::current_dir().context("resolve workspace directory")?;
    let run_dir = create_run_dir(&workspace, "vm-integration", started)?;

    let keep_requested = env_flag("SMOO_VM_KEEP", false);
    let accel = env::var("SMOO_VM_ACCEL").unwrap_or_else(|_| "kvm".to_string());
    let boot_timeout = env_duration("SMOO_VM_BOOT_TIMEOUT_SECS", DEFAULT_BOOT_TIMEOUT)?;
    let guest_probe_timeout = env_duration(
        "SMOO_VM_GUEST_PROBE_TIMEOUT_SECS",
        DEFAULT_GUEST_PROBE_TIMEOUT,
    )?;
    let guest_harness_timeout = env_duration(
        "SMOO_VM_GUEST_HARNESS_TIMEOUT_SECS",
        DEFAULT_GUEST_HARNESS_TIMEOUT,
    )?;

    println!("vm-integration run dir: {}", run_dir.display());
    println!("vm-integration accelerator: {accel}");

    let mut failure: Option<String> = None;
    let mut qemu: Option<Child> = None;
    let mut qmp: Option<QmpClient> = None;
    let mut ssh_port: Option<u16> = None;
    let mut image_for_metadata = String::new();

    let result = (|| -> Result<()> {
        ensure_host_prereqs(&accel)?;
        let payload = build_harness_payload(&workspace, &run_dir)?;

        let image = resolve_integration_image(&workspace)?;
        image_for_metadata = image.display().to_string();
        let overlay = run_dir.join("overlay.qcow2");
        create_overlay(&image, &overlay)?;

        let ssh_key = run_dir.join("id_ed25519");
        generate_ssh_key(&ssh_key)?;
        let seed = create_seed_image(&run_dir, &ssh_key, RUNTIME_SSH_USER)?;
        let port = allocate_local_port()?;
        ssh_port = Some(port);

        qemu = Some(spawn_qemu(&run_dir, &overlay, &seed, port, &accel)?);
        let qmp_path = run_dir.join("qmp.sock");
        let qemu_ref = qemu.as_mut().expect("qemu child just spawned");
        let mut qmp_client = QmpClient::connect(&qmp_path, &run_dir.join("qmp.log"), qemu_ref)?;
        qmp_client.negotiate()?;
        qmp_client.ensure_kvm_enabled(&accel)?;
        qmp = Some(qmp_client);

        wait_for_ssh(
            port,
            &ssh_key,
            RUNTIME_SSH_USER,
            boot_timeout,
            qemu.as_mut().unwrap(),
        )?;
        run_guest_probe(port, &ssh_key, &run_dir, guest_probe_timeout)?;
        stage_harness_payload(port, &ssh_key, &run_dir, &payload)?;
        run_guest_harness(
            port,
            &ssh_key,
            &run_dir,
            &payload.tests,
            guest_harness_timeout,
        )?;
        Ok(())
    })();

    if let Err(err) = &result {
        failure = Some(format!("{err:#}"));
    }

    if let (Some(port), ssh_key) = (ssh_port, run_dir.join("id_ed25519"))
        && ssh_key.exists()
    {
        collect_guest_test_artifacts(port, &ssh_key, RUNTIME_SSH_USER, &run_dir);
        collect_guest_logs(port, &ssh_key, RUNTIME_SSH_USER, &run_dir);
    }

    let shutdown_result = shutdown_qemu(qmp.as_mut(), qemu.as_mut(), &run_dir);
    if failure.is_none()
        && let Err(err) = &shutdown_result
    {
        failure = Some(format!("{err:#}"));
    }

    let finished = unix_time_secs();
    write_run_metadata(
        &run_dir,
        &image_for_metadata,
        &accel,
        ssh_port,
        started,
        finished,
        failure.as_deref(),
    )?;

    let keep_run_dir = keep_requested || failure.is_some();
    if keep_run_dir {
        println!("vm-integration artifacts retained at {}", run_dir.display());
    } else if let Err(err) = fs::remove_dir_all(&run_dir) {
        eprintln!(
            "vm-integration: failed to remove run dir {}: {err}",
            run_dir.display()
        );
    }

    result?;
    shutdown_result?;
    println!("vm-integration harness passed");
    Ok(())
}

fn build_harness_payload(workspace: &Path, run_dir: &Path) -> Result<HarnessPayload> {
    ensure_tool("cargo")?;
    ensure_tool("scp")?;

    let host_target_dir = workspace.join("target/vm-harness-target");
    fs::create_dir_all(&host_target_dir)
        .with_context(|| format!("mkdir {}", host_target_dir.display()))?;

    println!("building smoo CLI binaries for guest harness");
    run_checked(
        Command::new("cargo")
            .args([
                "build",
                "--bins",
                "-p",
                "smoo-gadget-cli",
                "-p",
                "smoo-host-cli",
            ])
            .env("CARGO_TARGET_DIR", &host_target_dir),
        "build smoo CLI binaries",
    )?;

    println!("building smoo-test-harness test binaries for guest harness");
    let tests = build_harness_test_binaries(&host_target_dir)?;

    let payload_dir = run_dir.join("payload");
    let bin_dir = payload_dir.join("bin");
    let tests_dir = payload_dir.join("tests");
    let tools_dir = payload_dir.join("tools");
    fs::create_dir_all(&bin_dir).with_context(|| format!("mkdir {}", bin_dir.display()))?;
    fs::create_dir_all(&tests_dir).with_context(|| format!("mkdir {}", tests_dir.display()))?;
    fs::create_dir_all(&tools_dir).with_context(|| format!("mkdir {}", tools_dir.display()))?;

    let target_debug_dir = host_target_dir.join("debug");
    copy_executable(
        &target_debug_dir.join("smoo-gadget"),
        &bin_dir.join("smoo-gadget"),
    )?;
    copy_executable(
        &target_debug_dir.join("smoo-host"),
        &bin_dir.join("smoo-host"),
    )?;
    copy_regular_file(
        &workspace.join("tools/wireshark/smoo.lua"),
        &tools_dir.join("smoo.lua"),
    )?;

    let mut test_names = Vec::new();
    for test in tests {
        copy_executable(&test.executable, &tests_dir.join(&test.name))?;
        test_names.push(test.name);
    }

    println!("guest harness tests: {}", test_names.join(", "));
    Ok(HarnessPayload {
        local_dir: payload_dir,
        tests: test_names,
    })
}

fn build_harness_test_binaries(host_target_dir: &Path) -> Result<Vec<HarnessTestBinary>> {
    let output = run_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "smoo-test-harness",
                "--tests",
                "--no-run",
                "--message-format=json",
            ])
            .env("CARGO_TARGET_DIR", host_target_dir),
        "build smoo-test-harness test binaries",
    )?;

    let mut tests = Vec::new();
    for line in output.lines() {
        if !line.contains(r#""reason":"compiler-artifact""#) || !line.contains(r#""kind":["test"]"#)
        {
            continue;
        }
        let name = extract_json_string_field(line, "name")
            .with_context(|| format!("parse test target name from cargo JSON: {line}"))?;
        let executable = extract_json_string_field(line, "executable")
            .with_context(|| format!("parse test executable from cargo JSON for {name}"))?;
        tests.push(HarnessTestBinary {
            name,
            executable: PathBuf::from(executable),
        });
    }

    for expected in crate::STABLE_HARNESS_TESTS {
        if !tests.iter().any(|test| test.name == *expected) {
            bail!("missing smoo-test-harness test binary: {expected}");
        }
    }

    let mut skipped = Vec::new();
    tests.retain(|test| {
        let included = crate::STABLE_HARNESS_TESTS.contains(&test.name.as_str());
        if !included {
            skipped.push(test.name.clone());
        }
        included
    });
    if !skipped.is_empty() {
        println!(
            "skipping VM harness tests outside stable set: {}",
            skipped.join(", ")
        );
    }

    tests.sort_by(|a, b| {
        harness_test_rank(&a.name)
            .cmp(&harness_test_rank(&b.name))
            .then_with(|| a.name.cmp(&b.name))
    });
    tests.dedup_by(|a, b| a.name == b.name);
    if tests.is_empty() {
        bail!("cargo did not report any smoo-test-harness integration test binaries");
    }
    Ok(tests)
}

fn harness_test_rank(name: &str) -> u8 {
    crate::STABLE_HARNESS_TESTS
        .iter()
        .position(|test| *test == name)
        .unwrap_or(crate::STABLE_HARNESS_TESTS.len()) as u8
}

fn stage_harness_payload(
    port: u16,
    key: &Path,
    run_dir: &Path,
    payload: &HarnessPayload,
) -> Result<()> {
    let prep_script = format!(
        r#"set -euxo pipefail
rm -rf {payload_dir} {target_dir}
mkdir -p {payload_dir} {target_dir}
"#,
        payload_dir = shell_quote(GUEST_PAYLOAD_DIR),
        target_dir = shell_quote(GUEST_TARGET_DIR),
    );
    run_guest_script(
        "prepare guest harness payload directory",
        "guest-payload-prep.stdout.log",
        "guest-payload-prep.stderr.log",
        port,
        key,
        RUNTIME_SSH_USER,
        run_dir,
        &prep_script,
        Duration::from_secs(60),
    )?;

    println!("copying guest harness payload to {GUEST_PAYLOAD_DIR}");
    run_checked(
        scp_command(port, key)
            .arg("-r")
            .arg(payload.local_dir.join("."))
            .arg(format!("{RUNTIME_SSH_USER}@127.0.0.1:{GUEST_PAYLOAD_DIR}/")),
        "copy guest harness payload",
    )
}

fn run_guest_harness(
    port: u16,
    key: &Path,
    run_dir: &Path,
    tests: &[String],
    timeout: Duration,
) -> Result<()> {
    let script = guest_harness_script(tests);
    run_guest_script(
        "guest harness tests",
        "guest-harness.stdout.log",
        "guest-harness.stderr.log",
        port,
        key,
        RUNTIME_SSH_USER,
        run_dir,
        &script,
        timeout,
    )
}

fn guest_harness_script(test_names: &[String]) -> String {
    let tests = test_names
        .iter()
        .map(|name| shell_quote(name))
        .collect::<Vec<_>>()
        .join(" ");
    let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info,smoo_test_harness=debug".into());
    let rust_backtrace = env::var("RUST_BACKTRACE").unwrap_or_else(|_| "1".into());
    let full_pcap_export = env::var("SMOO_FULL_PCAP")
        .ok()
        .map(|value| format!("export SMOO_FULL_PCAP={}\n", shell_quote(&value)))
        .unwrap_or_default();

    format!(
        r#"set -euxo pipefail
payload={payload_dir}
target_dir={target_dir}
export PATH="$payload/bin:$PATH"
export CARGO_TARGET_DIR="$target_dir"
export SMOO_GADGET_PATH="$payload/bin/smoo-gadget"
export SMOO_HOST_PATH="$payload/bin/smoo-host"
export SMOO_WIRESHARK_LUA="$payload/tools/smoo.lua"
export RUST_LOG={rust_log}
export RUST_BACKTRACE={rust_backtrace}
{full_pcap_export}

rm -rf "$CARGO_TARGET_DIR"
mkdir -p "$CARGO_TARGET_DIR"
chmod -R a+rX "$payload"

cleanup_artifacts() {{
    if test -d "$CARGO_TARGET_DIR/integration-artifacts"; then
        sudo chown -R "$(id -u):$(id -g)" "$CARGO_TARGET_DIR/integration-artifacts" || true
    fi
}}
trap cleanup_artifacts EXIT

sudo_env=(
    "PATH=$PATH"
    "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
    "SMOO_GADGET_PATH=$SMOO_GADGET_PATH"
    "SMOO_HOST_PATH=$SMOO_HOST_PATH"
    "SMOO_WIRESHARK_LUA=$SMOO_WIRESHARK_LUA"
    "RUST_LOG=$RUST_LOG"
    "RUST_BACKTRACE=$RUST_BACKTRACE"
)
if [[ -n "${{SMOO_FULL_PCAP+x}}" ]]; then
    sudo_env+=("SMOO_FULL_PCAP=$SMOO_FULL_PCAP")
fi

sudo -E env "${{sudo_env[@]}}" bash -lc 'set -euxo pipefail
modprobe configfs || true
modprobe libcomposite
modprobe usb_f_fs
modprobe ublk_drv
modprobe usbmon
modprobe dummy_hcd num_instances=4
mountpoint -q /sys/kernel/config || mount -t configfs configfs /sys/kernel/config
mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug
'

test -x "$SMOO_GADGET_PATH"
test -x "$SMOO_HOST_PATH"
test -f "$SMOO_WIRESHARK_LUA"

tests=({tests})
for test_name in "${{tests[@]}}"; do
    test_path="$payload/tests/$test_name"
    test -x "$test_path"
    echo "running smoo VM harness test: $test_name"
    sudo -E env "${{sudo_env[@]}}" "$test_path" --include-ignored --test-threads=1 --nocapture
done

echo "smoo VM harness tests OK"
"#,
        payload_dir = shell_quote(GUEST_PAYLOAD_DIR),
        target_dir = shell_quote(GUEST_TARGET_DIR),
        rust_log = shell_quote(&rust_log),
        rust_backtrace = shell_quote(&rust_backtrace),
        full_pcap_export = full_pcap_export,
        tests = tests,
    )
}

fn collect_guest_test_artifacts(port: u16, key: &Path, ssh_user: &str, run_dir: &Path) {
    if let Err(err) = try_collect_guest_test_artifacts(port, key, ssh_user, run_dir) {
        eprintln!("vm-integration: failed to collect guest integration artifacts: {err:#}");
    }
}

fn try_collect_guest_test_artifacts(
    port: u16,
    key: &Path,
    ssh_user: &str,
    run_dir: &Path,
) -> Result<()> {
    let remote = format!("{GUEST_TARGET_DIR}/integration-artifacts");
    let probe = format!("test -d {}", shell_quote(&remote));
    if !ssh_status(port, key, ssh_user, &probe)?.success() {
        return Ok(());
    }

    let dest = run_dir.join("guest-integration-artifacts");
    if dest.exists() {
        fs::remove_dir_all(&dest).with_context(|| format!("remove {}", dest.display()))?;
    }
    let status = scp_command(port, key)
        .arg("-r")
        .arg(format!("{ssh_user}@127.0.0.1:{remote}"))
        .arg(&dest)
        .status()
        .context("spawn scp for guest integration artifacts")?;
    if !status.success() {
        bail!("scp guest integration artifacts failed: {status:?}");
    }

    println!("guest integration artifacts copied to {}", dest.display());
    Ok(())
}

fn copy_regular_file(src: &Path, dst: &Path) -> Result<()> {
    if !src.is_file() {
        bail!("{} is not a regular file", src.display());
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::copy(src, dst).with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

fn copy_executable(src: &Path, dst: &Path) -> Result<()> {
    copy_regular_file(src, dst)?;
    let mut permissions = fs::metadata(dst)
        .with_context(|| format!("stat {}", dst.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(dst, permissions).with_context(|| format!("chmod +x {}", dst.display()))?;
    Ok(())
}

fn extract_json_string_field(line: &str, field: &str) -> Option<String> {
    let needle = format!(r#""{field}":"#);
    let (_, after) = line.split_once(&needle)?;
    let mut chars = after.trim_start().chars();
    if chars.next()? != '"' {
        return None;
    }

    let mut value = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            match ch {
                '"' | '\\' | '/' => value.push(ch),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                other => value.push(other),
            }
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn shell_quote(value: &str) -> String {
    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn ensure_host_prereqs(accel: &str) -> Result<()> {
    for tool in ["qemu-system-x86_64", "qemu-img", "ssh", "ssh-keygen"] {
        ensure_tool(tool)?;
    }
    if !has_tool("cloud-localds") && !has_tool("mkisofs") && !has_tool("xorriso") {
        bail!("missing seed-image tool: install cloud-localds/cloud-utils, mkisofs, or xorriso");
    }
    if accel == "kvm" {
        let kvm = Path::new("/dev/kvm");
        if !kvm.exists() {
            bail!(
                "/dev/kvm is missing; enable KVM on the host or set SMOO_VM_ACCEL=tcg for a slow smoke test"
            );
        }
        OpenOptions::new().read(true).write(true).open(kvm).with_context(|| {
            "open /dev/kvm read-write; install tools/udev/99-smoo-kvm.rules or add this user to the kvm group"
        })?;
    } else if accel != "tcg" {
        bail!("SMOO_VM_ACCEL must be `kvm` or `tcg`, got `{accel}`");
    }
    Ok(())
}

fn create_run_dir(workspace: &Path, name: &str, started: u64) -> Result<PathBuf> {
    let run_dir = workspace.join("target/vm-runs").join(format!(
        "{}-{}-{}",
        name,
        started,
        std::process::id()
    ));
    fs::create_dir_all(&run_dir).with_context(|| format!("mkdir {}", run_dir.display()))?;
    Ok(run_dir)
}

fn integration_image_dir(workspace: &Path) -> PathBuf {
    workspace.join("target/vm-images")
}

fn fedora_base_image_dir(workspace: &Path) -> PathBuf {
    integration_image_dir(workspace)
}

fn default_integration_image_path(workspace: &Path) -> PathBuf {
    integration_image_dir(workspace).join(INTEGRATION_IMAGE_NAME)
}

fn default_integration_image_sha256_path(workspace: &Path) -> PathBuf {
    integration_image_dir(workspace).join(INTEGRATION_IMAGE_SHA256_NAME)
}

fn default_integration_image_manifest_path(workspace: &Path) -> PathBuf {
    integration_image_dir(workspace).join(INTEGRATION_IMAGE_MANIFEST_NAME)
}

fn vm_image_spec(workspace: &Path) -> Result<VmImageSpec> {
    ensure_tool("sha256sum")?;
    let base_url =
        env::var("SMOO_VM_BASE_IMAGE_URL").unwrap_or_else(|_| FEDORA_BASE_IMAGE_URL.to_string());
    let base_sha256 = env::var("SMOO_VM_BASE_IMAGE_SHA256")
        .unwrap_or_else(|_| FEDORA_BASE_IMAGE_SHA256.to_string());
    let setup_script_path = workspace.join(VM_IMAGE_SETUP_SCRIPT);
    let setup_script = fs::read_to_string(&setup_script_path)
        .with_context(|| format!("read {}", setup_script_path.display()))?;
    let setup_script_sha256 = sha256_bytes(setup_script.as_bytes())?;

    let mut input = Vec::new();
    input.extend_from_slice(b"base-image-url\0");
    input.extend_from_slice(base_url.as_bytes());
    input.extend_from_slice(b"\0base-image-sha256\0");
    input.extend_from_slice(base_sha256.as_bytes());
    input.extend_from_slice(b"\0guest-setup-sha256\0");
    input.extend_from_slice(setup_script_sha256.as_bytes());
    let input_sha256 = sha256_bytes(&input)?;
    let repository = env::var("SMOO_VM_IMAGE_REPOSITORY")
        .unwrap_or_else(|_| DEFAULT_OCI_IMAGE_REPOSITORY.to_string());
    let oci_ref = format!("{repository}:{input_sha256}");

    Ok(VmImageSpec {
        base_url,
        base_sha256,
        setup_script,
        setup_script_sha256,
        input_sha256,
        oci_ref,
    })
}

fn verify_default_image_manifest(workspace: &Path, spec: &VmImageSpec) -> Result<()> {
    let manifest = default_integration_image_manifest_path(workspace);
    if !manifest.exists() {
        bail!(
            "default VM image manifest {} does not exist; rebuild or download {}",
            manifest.display(),
            spec.oci_ref,
        );
    }
    let contents =
        fs::read_to_string(&manifest).with_context(|| format!("read {}", manifest.display()))?;
    let expected_input = format!(r#""input_sha256": "{}""#, spec.input_sha256);
    if !contents.contains(&expected_input) {
        bail!(
            "default VM image manifest {} does not match {}; run `cargo xtask vm-image build` or `cargo xtask vm-image download`",
            manifest.display(),
            spec.oci_ref,
        );
    }
    Ok(())
}

fn resolve_integration_image(workspace: &Path) -> Result<PathBuf> {
    if let Ok(path) = env::var("SMOO_VM_IMAGE") {
        let image = PathBuf::from(path);
        if !image.exists() {
            bail!("SMOO_VM_IMAGE={} does not exist", image.display());
        }
        return Ok(image);
    }

    let spec = vm_image_spec(workspace)?;
    let image = default_integration_image_path(workspace);
    if image.exists() {
        verify_default_image_manifest(workspace, &spec)?;
        return Ok(image);
    }

    bail!(
        "default VM image {} does not exist for {}; run `cargo xtask vm-image build` or `cargo xtask vm-image download`, or set SMOO_VM_IMAGE=/path/to/image.qcow2",
        image.display(),
        spec.oci_ref,
    )
}

fn resolve_fedora_base_image(workspace: &Path, spec: &VmImageSpec) -> Result<BaseImage> {
    let image_dir = fedora_base_image_dir(workspace);
    fs::create_dir_all(&image_dir).with_context(|| format!("mkdir {}", image_dir.display()))?;
    let image = image_dir.join(FEDORA_BASE_IMAGE_NAME);
    if image.exists() {
        verify_sha256(&image, &spec.base_sha256)?;
        return Ok(BaseImage {
            path: image,
            url: spec.base_url.clone(),
            sha256: spec.base_sha256.clone(),
        });
    }

    let tmp = image.with_extension("qcow2.tmp");
    println!("downloading Fedora cloud image: {}", spec.base_url);
    run_checked(
        Command::new("curl")
            .arg("-L")
            .arg("--fail")
            .arg("--retry")
            .arg("5")
            .arg("--output")
            .arg(&tmp)
            .arg(&spec.base_url),
        "download Fedora cloud image",
    )?;
    fs::rename(&tmp, &image).with_context(|| {
        format!(
            "rename downloaded image {} -> {}",
            tmp.display(),
            image.display()
        )
    })?;
    verify_sha256(&image, &spec.base_sha256)?;
    Ok(BaseImage {
        path: image,
        url: spec.base_url.clone(),
        sha256: spec.base_sha256.clone(),
    })
}

fn create_overlay(base: &Path, overlay: &Path) -> Result<()> {
    run_checked(
        Command::new("qemu-img")
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg("-F")
            .arg("qcow2")
            .arg("-b")
            .arg(base)
            .arg(overlay),
        "create disposable VM overlay",
    )
}

fn finalize_baked_image(
    workspace: &Path,
    overlay: &Path,
    output: &Path,
    base: &BaseImage,
    spec: &VmImageSpec,
) -> Result<()> {
    let image_dir = output
        .parent()
        .context("baked image output path has no parent")?;
    fs::create_dir_all(image_dir).with_context(|| format!("mkdir {}", image_dir.display()))?;

    let tmp_image = image_dir.join(format!(".{INTEGRATION_IMAGE_NAME}.tmp"));
    let tmp_sha = image_dir.join(format!(".{INTEGRATION_IMAGE_SHA256_NAME}.tmp"));
    let tmp_manifest = image_dir.join(format!(".{INTEGRATION_IMAGE_MANIFEST_NAME}.tmp"));
    remove_if_exists(&tmp_image)?;
    remove_if_exists(&tmp_sha)?;
    remove_if_exists(&tmp_manifest)?;

    println!("converting baked overlay to {}", output.display());
    run_checked(
        Command::new("qemu-img")
            .arg("convert")
            .arg("-f")
            .arg("qcow2")
            .arg("-O")
            .arg("qcow2")
            .arg("-c")
            .arg(overlay)
            .arg(&tmp_image),
        "convert baked VM image",
    )?;

    let image_sha = sha256_file(&tmp_image)?;
    fs::write(&tmp_sha, format!("{image_sha}  {INTEGRATION_IMAGE_NAME}\n"))
        .with_context(|| format!("write {}", tmp_sha.display()))?;
    fs::write(
        &tmp_manifest,
        format!(
            concat!(
                "{{\n",
                "  \"image\": \"{}\",\n",
                "  \"sha256\": \"{}\",\n",
                "  \"base_image_url\": \"{}\",\n",
                "  \"base_image_sha256\": \"{}\",\n",
                "  \"setup_script\": \"{}\",\n",
                "  \"setup_script_sha256\": \"{}\",\n",
                "  \"input_sha256\": \"{}\",\n",
                "  \"oci_ref\": \"{}\",\n",
                "  \"built_at_unix\": {}\n",
                "}}\n"
            ),
            json_escape(INTEGRATION_IMAGE_NAME),
            json_escape(&image_sha),
            json_escape(&base.url),
            json_escape(&base.sha256),
            json_escape(VM_IMAGE_SETUP_SCRIPT),
            json_escape(&spec.setup_script_sha256),
            json_escape(&spec.input_sha256),
            json_escape(&spec.oci_ref),
            unix_time_secs(),
        ),
    )
    .with_context(|| format!("write {}", tmp_manifest.display()))?;

    move_file_replace(&tmp_image, output)?;
    move_file_replace(&tmp_sha, &default_integration_image_sha256_path(workspace))?;
    move_file_replace(
        &tmp_manifest,
        &default_integration_image_manifest_path(workspace),
    )?;
    println!("vm-image sha256: {image_sha}");
    Ok(())
}

fn generate_ssh_key(path: &Path) -> Result<()> {
    run_checked(
        Command::new("ssh-keygen")
            .arg("-q")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(path),
        "generate ephemeral SSH key",
    )
}

fn create_seed_image(run_dir: &Path, ssh_key: &Path, ssh_user: &str) -> Result<PathBuf> {
    let public_key_path = ssh_key.with_extension("pub");
    let public_key = fs::read_to_string(&public_key_path)
        .with_context(|| format!("read {}", public_key_path.display()))?;
    let seed_dir = run_dir.join("seed");
    fs::create_dir_all(&seed_dir).with_context(|| format!("mkdir {}", seed_dir.display()))?;

    fs::write(
        seed_dir.join("user-data"),
        seed_user_data(ssh_user, &public_key),
    )
    .context("write cloud-init user-data")?;
    fs::write(
        seed_dir.join("meta-data"),
        format!(
            "instance-id: smoo-{}\nlocal-hostname: smoo-vm\n",
            unix_time_secs()
        ),
    )
    .context("write cloud-init meta-data")?;

    let seed = run_dir.join("seed.iso");
    if has_tool("cloud-localds") {
        run_checked(
            Command::new("cloud-localds")
                .arg(&seed)
                .arg(seed_dir.join("user-data"))
                .arg(seed_dir.join("meta-data")),
            "create cloud-init seed image",
        )?;
    } else {
        let iso_tool = if has_tool("mkisofs") {
            "mkisofs"
        } else {
            "xorriso"
        };
        if iso_tool == "mkisofs" {
            run_checked(
                Command::new("mkisofs")
                    .arg("-quiet")
                    .arg("-output")
                    .arg(&seed)
                    .arg("-volid")
                    .arg("cidata")
                    .arg("-joliet")
                    .arg("-rock")
                    .arg("-graft-points")
                    .arg(format!(
                        "user-data={}",
                        seed_dir.join("user-data").display()
                    ))
                    .arg(format!(
                        "meta-data={}",
                        seed_dir.join("meta-data").display()
                    )),
                "create NoCloud seed ISO",
            )?;
        } else {
            run_checked(
                Command::new("xorriso")
                    .arg("-as")
                    .arg("mkisofs")
                    .arg("-quiet")
                    .arg("-output")
                    .arg(&seed)
                    .arg("-volid")
                    .arg("cidata")
                    .arg("-joliet")
                    .arg("-rock")
                    .arg("-graft-points")
                    .arg(format!(
                        "user-data={}",
                        seed_dir.join("user-data").display()
                    ))
                    .arg(format!(
                        "meta-data={}",
                        seed_dir.join("meta-data").display()
                    )),
                "create NoCloud seed ISO",
            )?;
        }
    }
    Ok(seed)
}

fn seed_user_data(ssh_user: &str, public_key: &str) -> String {
    if ssh_user == "root" {
        return format!(
            r#"#cloud-config
users:
  - default
  - name: root
    ssh_authorized_keys:
      - {public_key}
ssh_pwauth: false
disable_root: false
runcmd:
  - [systemctl, enable, --now, sshd]
  - [sh, -lc, "echo smoo-vm-ready >/run/smoo-vm-ready"]
"#
        );
    }

    format!(
        r#"#cloud-config
users:
  - default
  - name: {ssh_user}
    groups: [wheel]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    ssh_authorized_keys:
      - {public_key}
ssh_pwauth: false
disable_root: false
runcmd:
  - [systemctl, enable, --now, sshd]
  - [sh, -lc, "echo smoo-vm-ready >/run/smoo-vm-ready"]
"#
    )
}

fn allocate_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral localhost port")?;
    Ok(listener.local_addr()?.port())
}

fn spawn_qemu(
    run_dir: &Path,
    overlay: &Path,
    seed: &Path,
    ssh_port: u16,
    accel: &str,
) -> Result<Child> {
    let stdout = File::create(run_dir.join("qemu.stdout.log")).context("create qemu stdout log")?;
    let stderr = File::create(run_dir.join("qemu.stderr.log")).context("create qemu stderr log")?;
    let qmp = run_dir.join("qmp.sock");
    let serial = run_dir.join("serial.log");

    let child = Command::new("qemu-system-x86_64")
        .arg("-machine")
        .arg(format!("q35,accel={accel}"))
        .arg("-cpu")
        .arg(if accel == "kvm" { "host" } else { "max" })
        .arg("-smp")
        .arg("4")
        .arg("-m")
        .arg("4096")
        .arg("-drive")
        .arg(format!("if=virtio,file={},format=qcow2", overlay.display()))
        .arg("-drive")
        .arg(format!(
            "if=virtio,file={},format=raw,readonly=on",
            seed.display()
        ))
        .arg("-nic")
        .arg(format!(
            "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{ssh_port}-:22"
        ))
        .arg("-qmp")
        .arg(format!("unix:{},server=on,wait=off", qmp.display()))
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-device")
        .arg("virtio-rng-pci")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("spawn qemu-system-x86_64")?;
    Ok(child)
}

fn wait_for_ssh(
    port: u16,
    key: &Path,
    ssh_user: &str,
    timeout: Duration,
    qemu: &mut Child,
) -> Result<()> {
    println!("waiting for guest SSH on localhost:{port} as {ssh_user}");
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = qemu.try_wait().context("poll qemu status")? {
            bail!("qemu exited before SSH became ready: {status:?}");
        }
        if ssh_status(port, key, ssh_user, "true")?.success() {
            println!("guest SSH ready on localhost:{port}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out after {timeout:?} waiting for guest SSH");
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn run_guest_probe(port: u16, key: &Path, run_dir: &Path, timeout: Duration) -> Result<()> {
    let script = guest_probe_script();
    run_guest_script(
        "guest probe",
        "guest-probe.stdout.log",
        "guest-probe.stderr.log",
        port,
        key,
        RUNTIME_SSH_USER,
        run_dir,
        &script,
        timeout,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_guest_script(
    label: &str,
    stdout_name: &str,
    stderr_name: &str,
    port: u16,
    key: &Path,
    ssh_user: &str,
    run_dir: &Path,
    script: &str,
    timeout: Duration,
) -> Result<()> {
    let stdout_path = run_dir.join(stdout_name);
    let stderr_path = run_dir.join(stderr_name);
    println!(
        "running {label}; streaming output (logs: {}, {})",
        stdout_path.display(),
        stderr_path.display()
    );
    let mut child = ssh_command(port, key, ssh_user, "bash -s")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {label} over SSH"))?;
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("{label} stdout missing"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("{label} stderr missing"))?;
    let stdout_tee = spawn_output_tee(stdout, stdout_path.clone(), false);
    let stderr_tee = spawn_output_tee(stderr, stderr_path.clone(), true);
    child
        .stdin
        .take()
        .with_context(|| format!("{label} stdin missing"))?
        .write_all(script.as_bytes())
        .with_context(|| format!("write {label} script to SSH stdin"))?;

    let status = wait_child(&mut child, timeout).with_context(|| label.to_string());
    join_output_tee(stdout_tee, &format!("{label} stdout"))?;
    join_output_tee(stderr_tee, &format!("{label} stderr"))?;
    let status = status?;
    if !status.success() {
        bail!(
            "{label} failed with {status:?}; see {} and {}",
            stdout_path.display(),
            stderr_path.display()
        );
    }
    Ok(())
}

fn spawn_output_tee<R>(mut src: R, path: PathBuf, stderr: bool) -> JoinHandle<Result<()>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
        let mut buf = [0u8; 8192];
        loop {
            let n = src
                .read(&mut buf)
                .with_context(|| format!("read guest output for {}", path.display()))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])
                .with_context(|| format!("write {}", path.display()))?;
            if stderr {
                let mut sink = std::io::stderr().lock();
                sink.write_all(&buf[..n]).context("write stderr")?;
                sink.flush().context("flush stderr")?;
            } else {
                let mut sink = std::io::stdout().lock();
                sink.write_all(&buf[..n]).context("write stdout")?;
                sink.flush().context("flush stdout")?;
            }
        }
        file.flush()
            .with_context(|| format!("flush {}", path.display()))?;
        Ok(())
    })
}

fn join_output_tee(handle: JoinHandle<Result<()>>, label: &str) -> Result<()> {
    handle
        .join()
        .map_err(|_| anyhow!("{label} tee thread panicked"))??;
    Ok(())
}

fn guest_probe_script() -> String {
    r#"set -euxo pipefail
echo "hello from smoo vm-integration guest"
cat /etc/os-release
uname -a

echo "probing smoo kernel modules"
sudo modprobe configfs || true
sudo modprobe libcomposite
sudo modprobe usb_f_fs
sudo modprobe ublk_drv
sudo modprobe usbmon
sudo modprobe dummy_hcd num_instances=4

sudo mountpoint -q /sys/kernel/config || sudo mount -t configfs configfs /sys/kernel/config
sudo mountpoint -q /sys/kernel/debug || sudo mount -t debugfs debugfs /sys/kernel/debug

test -d /sys/kernel/config/usb_gadget
test -e /dev/ublk-control
test -e /sys/class/udc/dummy_udc.0
if ! test -d /sys/kernel/debug/usb/usbmon && ! test -e /dev/usbmon0; then
    echo "usbmon interface missing"
    exit 1
fi

missing_packages=()
command -v fio >/dev/null || missing_packages+=(fio)
if ! command -v dumpcap >/dev/null || ! command -v tshark >/dev/null; then
    missing_packages+=(wireshark-cli)
fi
if ! fio --enghelp=libaio >/dev/null 2>&1; then
    missing_packages+=(fio-engine-libaio)
fi

if test "${#missing_packages[@]}" -gt 0; then
    echo "missing userspace packages: ${missing_packages[*]}"
    exit 1
fi

for tool in fio dumpcap tshark; do
    command -v "$tool"
done

echo "smoo vm-integration guest probe OK"
"#
    .to_string()
}

fn collect_guest_logs(port: u16, key: &Path, ssh_user: &str, run_dir: &Path) {
    let logs = [
        ("guest-dmesg.txt", "sudo dmesg"),
        ("guest-journal.txt", "sudo journalctl -b --no-pager"),
    ];
    for (file_name, remote_cmd) in logs {
        let path = run_dir.join(file_name);
        let Ok(file) = File::create(&path) else {
            continue;
        };
        let _ = ssh_command(port, key, ssh_user, remote_cmd)
            .stdout(Stdio::from(file))
            .stderr(Stdio::null())
            .status();
    }
}

fn shutdown_qemu(
    mut qmp: Option<&mut QmpClient>,
    qemu: Option<&mut Child>,
    run_dir: &Path,
) -> Result<()> {
    let Some(qemu) = qemu else {
        return Ok(());
    };
    if let Some(status) = qemu.try_wait().context("poll qemu before shutdown")? {
        if status.success() {
            return Ok(());
        }
        bail!("qemu exited unsuccessfully: {status:?}");
    }

    if let Some(qmp) = qmp.as_mut() {
        let _ = qmp.execute("system_powerdown");
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = qemu.try_wait().context("poll qemu shutdown")? {
            if status.success() {
                return Ok(());
            }
            bail!("qemu exited unsuccessfully during shutdown: {status:?}");
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }

    eprintln!(
        "vm-integration: guest did not power down, asking QEMU to quit (artifacts: {})",
        run_dir.display()
    );
    if let Some(qmp) = qmp.as_mut() {
        let _ = qmp.execute("quit");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = qemu.try_wait().context("poll qemu after quit")? {
            if status.success() {
                return Ok(());
            }
            bail!("qemu exited unsuccessfully after quit: {status:?}");
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }

    eprintln!(
        "vm-integration: qmp quit did not exit qemu, sending SIGKILL (artifacts: {})",
        run_dir.display()
    );
    let _ = qemu.kill();
    let status = qemu.wait().context("wait for qemu after kill")?;
    if status.success() {
        Ok(())
    } else {
        bail!("qemu required forced termination: {status:?}")
    }
}

struct QmpClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    log: File,
    next_id: u64,
}

impl QmpClient {
    fn connect(path: &Path, log_path: &Path, qemu: &mut Child) -> Result<Self> {
        let deadline = Instant::now() + QMP_TIMEOUT;
        let stream = loop {
            if let Some(status) = qemu.try_wait().context("poll qemu before QMP connect")? {
                bail!("qemu exited before QMP became ready: {status:?}");
            }
            match UnixStream::connect(path) {
                Ok(stream) => break stream,
                Err(err) if Instant::now() < deadline => {
                    let _ = err;
                    thread::sleep(Duration::from_millis(100));
                }
                Err(err) => {
                    return Err(err).with_context(|| format!("connect QMP {}", path.display()));
                }
            }
        };
        stream
            .set_read_timeout(Some(QMP_TIMEOUT))
            .context("set QMP read timeout")?;
        stream
            .set_write_timeout(Some(QMP_TIMEOUT))
            .context("set QMP write timeout")?;
        let writer = stream.try_clone().context("clone QMP stream")?;
        let log =
            File::create(log_path).with_context(|| format!("create {}", log_path.display()))?;
        let mut client = Self {
            reader: BufReader::new(stream),
            writer,
            log,
            next_id: 1,
        };
        let greeting = client.read_qmp_line("QMP greeting")?;
        if !greeting.contains("QMP") {
            bail!("unexpected QMP greeting: {greeting}");
        }
        Ok(client)
    }

    fn negotiate(&mut self) -> Result<()> {
        let response = self.execute_raw(r#"{"execute":"qmp_capabilities","id":"caps"}"#, "caps")?;
        if !response.contains("\"return\"") {
            bail!("qmp_capabilities failed: {response}");
        }
        Ok(())
    }

    fn ensure_kvm_enabled(&mut self, accel: &str) -> Result<()> {
        if accel != "kvm" {
            return Ok(());
        }
        let response =
            self.execute_raw(r#"{"execute":"query-kvm","id":"query-kvm"}"#, "query-kvm")?;
        if !json_bool_field(&response, "enabled") {
            bail!("QMP query-kvm did not report enabled=true: {response}");
        }
        Ok(())
    }

    fn execute(&mut self, command: &str) -> Result<String> {
        let id = format!("cmd-{}", self.next_id);
        self.next_id += 1;
        self.execute_raw(&format!(r#"{{"execute":"{command}","id":"{id}"}}"#), &id)
    }

    fn execute_raw(&mut self, json: &str, id: &str) -> Result<String> {
        writeln!(self.log, "> {json}").ok();
        writeln!(self.writer, "{json}").context("write QMP command")?;
        self.writer.flush().context("flush QMP command")?;
        loop {
            let line = self.read_qmp_line("QMP response")?;
            if json_id_matches(&line, id) {
                return Ok(line);
            }
        }
    }

    fn read_qmp_line(&mut self, context: &str) -> Result<String> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .with_context(|| context.to_string())?;
        if n == 0 {
            bail!("QMP socket closed while reading {context}");
        }
        let line = line.trim_end().to_string();
        writeln!(self.log, "< {line}").ok();
        Ok(line)
    }
}

fn json_id_matches(line: &str, id: &str) -> bool {
    line.contains(&format!(r#""id":"{id}""#)) || line.contains(&format!(r#""id": "{id}""#))
}

fn json_bool_field(line: &str, field: &str) -> bool {
    line.contains(&format!(r#""{field}":true"#)) || line.contains(&format!(r#""{field}": true"#))
}

fn ssh_status(port: u16, key: &Path, ssh_user: &str, remote_cmd: &str) -> Result<ExitStatus> {
    ssh_command(port, key, ssh_user, remote_cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("run SSH readiness command")
}

fn ssh_command(port: u16, key: &Path, ssh_user: &str, remote_cmd: &str) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.arg("-i")
        .arg(key)
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg(format!("{ssh_user}@127.0.0.1"))
        .arg(remote_cmd);
    cmd
}

fn scp_command(port: u16, key: &Path) -> Command {
    let mut cmd = Command::new("scp");
    cmd.arg("-i")
        .arg(key)
        .arg("-P")
        .arg(port.to_string())
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR");
    cmd
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("poll child")? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out after {timeout:?}");
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn sha256_bytes(input: &[u8]) -> Result<String> {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn sha256sum")?;
    child
        .stdin
        .take()
        .context("sha256sum stdin missing")?
        .write_all(input)
        .context("write sha256sum stdin")?;
    let output = child.wait_with_output().context("wait for sha256sum")?;
    if !output.status.success() {
        bail!(
            "sha256sum failed: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout)
        .context("decode sha256sum stdout")?
        .split_whitespace()
        .next()
        .map(str::to_string)
        .context("parse sha256sum stdout")
}

fn sha256_file(path: &Path) -> Result<String> {
    let output = run_output(
        Command::new("sha256sum").arg(path),
        &format!("sha256sum {}", path.display()),
    )?;
    output
        .split_whitespace()
        .next()
        .map(str::to_string)
        .with_context(|| format!("parse sha256sum output for {}", path.display()))
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    if actual != expected {
        bail!(
            "sha256 mismatch for {}: expected {expected}, got {actual}",
            path.display()
        );
    }
    Ok(())
}

fn read_sha256_file(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    contents
        .split_whitespace()
        .next()
        .map(str::to_string)
        .with_context(|| format!("parse {}", path.display()))
}

fn move_file_replace(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    remove_if_exists(to)?;
    fs::rename(from, to).with_context(|| format!("rename {} -> {}", from.display(), to.display()))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawn {label}"))?;
    if !status.success() {
        bail!("{label} failed: {status:?}");
    }
    Ok(())
}

fn run_output(cmd: &mut Command, label: &str) -> Result<String> {
    let output = cmd.output().with_context(|| format!("spawn {label}"))?;
    if !output.status.success() {
        bail!(
            "{label} failed: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).with_context(|| format!("decode stdout from {label}"))
}

fn ensure_tool(name: &str) -> Result<()> {
    if has_tool(name) {
        Ok(())
    } else {
        bail!("missing host tool `{name}` on PATH")
    }
}

fn has_tool(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(name).is_file())
}

fn env_flag(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"),
        Err(_) => default,
    }
}

fn env_duration(name: &str, default: Duration) -> Result<Duration> {
    match env::var(name) {
        Ok(value) => {
            Ok(Duration::from_secs(value.parse::<u64>().with_context(
                || format!("parse {name}={value:?} as seconds"),
            )?))
        }
        Err(_) => Ok(default),
    }
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_run_metadata(
    run_dir: &Path,
    image: &str,
    accel: &str,
    ssh_port: Option<u16>,
    started: u64,
    finished: u64,
    failure: Option<&str>,
) -> Result<()> {
    let status = if failure.is_some() {
        "failed"
    } else {
        "passed"
    };
    let failure_json = failure
        .map(|s| format!("\"{}\"", json_escape(s)))
        .unwrap_or_else(|| "null".to_string());
    let ssh_port_json = ssh_port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "null".to_string());
    let json = format!(
        concat!(
            "{{\n",
            "  \"status\": \"{}\",\n",
            "  \"image\": \"{}\",\n",
            "  \"accelerator\": \"{}\",\n",
            "  \"ssh_port\": {},\n",
            "  \"started_at_unix\": {},\n",
            "  \"finished_at_unix\": {},\n",
            "  \"failure\": {}\n",
            "}}\n"
        ),
        status,
        json_escape(image),
        json_escape(accel),
        ssh_port_json,
        started,
        finished,
        failure_json,
    );
    fs::write(run_dir.join("vm-run.json"), json).context("write vm-run.json")
}

fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            _ => vec![ch],
        })
        .collect()
}
