use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

const RETRY_DELAYS_SECS: &[u64] = &[0, 60, 900, 1800];

#[derive(Clone)]
struct LocalPackage {
    name: String,
    version: String,
    manifest_path: PathBuf,
    dependencies: BTreeSet<String>,
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn bump(extra: &[String]) -> Result<()> {
    let [version] = extra else {
        bail!("usage: cargo xtask bump <version>");
    };

    if has_legacy_rc_suffix(version) {
        bail!(
            "Unsupported RC format '{version}'. Use canonical semver '-rc.N' (for example: 0.0.1-rc.1)."
        );
    }

    let cargo_version = version.as_str();
    let mut package_version = version.clone();
    let mut debian_version = version.clone();
    if let Some((base, rc)) = parse_canonical_rc(version) {
        package_version = format!("{base}_rc{rc}");
        debian_version = format!("{base}~rc{rc}");
    }

    println!("Bumping smoo to {version}");

    update_cargo_toml(Path::new("Cargo.toml"), cargo_version)?;
    replace_prefixed_line(
        Path::new("smoo.spec"),
        "Version:",
        &format!("Version:        {package_version}"),
    )?;
    replace_matching_line(
        Path::new("APKBUILD"),
        |line| line.starts_with("pkgver=") && line.ends_with("_git"),
        &format!("pkgver={package_version}_git"),
        "APKBUILD pkgver=*_git line",
    )?;
    replace_first_line(
        Path::new("debian/changelog"),
        &format!("smoo ({debian_version}) UNRELEASED; urgency=medium"),
    )?;

    run_checked(
        Command::new("cargo").arg("update").arg("--workspace"),
        "cargo update --workspace",
    )?;

    println!("Done. Files updated:");
    println!("  Cargo.toml");
    println!("  smoo.spec");
    println!("  APKBUILD");
    println!("  debian/changelog");
    println!();
    println!("Next steps:");
    println!("  1. Review changes: git diff");
    println!("  2. Commit: git commit -am 'v{version}'");
    println!("  3. Tag: git tag v{version}");
    println!("  4. Push: git push && git push --tags");
    Ok(())
}

pub fn publish_dry_run(extra: &[String]) -> Result<()> {
    if !extra.is_empty() {
        bail!("publish-dry-run does not accept extra args yet");
    }

    let packages = load_publishable_packages()?;
    let order = publish_order(&packages, "publish-dry-run")?;

    for package in order {
        let patch_file = write_patch_config(&packages, &package)?;
        println!("==> cargo package -p {package} --locked");
        run_checked(
            Command::new("cargo")
                .arg("package")
                .arg("-p")
                .arg(&package)
                .arg("--locked")
                .arg("--config")
                .arg(patch_file.path()),
            &format!("cargo package -p {package} --locked"),
        )?;
    }

    Ok(())
}

pub fn publish(extra: &[String]) -> Result<()> {
    if !extra.is_empty() {
        bail!("publish does not accept extra args yet");
    }

    let packages = load_publishable_packages()?;
    let order = publish_order(&packages, "publish")?;

    for package_name in order {
        let package_version = packages
            .get(&package_name)
            .map(|package| package.version.as_str())
            .ok_or_else(|| anyhow!("publish order referenced unknown package {package_name}"))?;

        if is_already_published(&package_name, package_version) {
            println!("Skipping {package_name}@{package_version}: already published on crates.io.");
            continue;
        }

        let mut package_done = false;
        for (attempt_idx, delay) in RETRY_DELAYS_SECS.iter().enumerate() {
            let attempt = attempt_idx + 1;
            let total_attempts = RETRY_DELAYS_SECS.len();

            if *delay > 0 {
                println!(
                    "Waiting {delay}s before retrying {package_name}@{package_version} (attempt {attempt}/{total_attempts})"
                );
                thread::sleep(Duration::from_secs(*delay));
            }

            println!(
                "==> cargo publish -p {package_name} --locked (attempt {attempt}/{total_attempts})"
            );
            let attempt_result = run_publish_attempt(&package_name)?;
            attempt_result.print();

            if attempt_result.status.success() {
                package_done = true;
                break;
            }

            if is_already_published(&package_name, package_version) {
                println!(
                    "Detected {package_name}@{package_version} on crates.io after failed publish attempt; continuing."
                );
                package_done = true;
                break;
            }

            match classify_publish_failure(&attempt_result.combined_log()) {
                PublishFailure::AlreadyPublished => {
                    println!(
                        "Skipping {package_name}@{package_version}: already published on crates.io."
                    );
                    package_done = true;
                    break;
                }
                PublishFailure::Transient if attempt < total_attempts => {
                    println!(
                        "Transient publish failure for {package_name}@{package_version}; retrying."
                    );
                }
                _ => {
                    bail!(
                        "Publish failed for {package_name}@{package_version}: {:?}",
                        attempt_result.status
                    );
                }
            }
        }

        if !package_done {
            bail!(
                "Publish failed for {package_name}@{package_version} after {} attempts.",
                RETRY_DELAYS_SECS.len()
            );
        }
    }

    Ok(())
}

fn has_legacy_rc_suffix(version: &str) -> bool {
    let Some((_, rc)) = version.rsplit_once("_rc") else {
        return false;
    };
    !rc.is_empty() && rc.bytes().all(|b| b.is_ascii_digit())
}

fn parse_canonical_rc(version: &str) -> Option<(&str, &str)> {
    let (base, rc) = version.split_once("-rc.")?;
    if rc.is_empty() || !rc.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut parts = base.split('.');
    for _ in 0..3 {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    if parts.next().is_some() {
        return None;
    }
    Some((base, rc))
}

fn update_cargo_toml(path: &Path, version: &str) -> Result<()> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let had_trailing_newline = contents.ends_with('\n');
    let mut workspace_versions = 0usize;
    let mut workspace_dependency_versions = 0usize;
    let mut lines = Vec::new();

    for line in contents.lines() {
        if line.starts_with("version = \"") {
            workspace_versions += 1;
            lines.push(format!("version = \"{version}\""));
            continue;
        }

        if let Some(updated) = update_smoo_workspace_dependency_version(line, version) {
            workspace_dependency_versions += 1;
            lines.push(updated);
            continue;
        }

        lines.push(line.to_string());
    }

    if workspace_versions == 0 {
        bail!(
            "{} did not contain a workspace version line",
            path.display()
        );
    }
    if workspace_dependency_versions == 0 {
        bail!(
            "{} did not contain smoo workspace dependency version pins",
            path.display()
        );
    }

    write_lines(path, lines, had_trailing_newline)
}

fn update_smoo_workspace_dependency_version(line: &str, version: &str) -> Option<String> {
    if !line.starts_with("smoo-") {
        return None;
    }

    let marker = ", version = \"";
    let value_start = line.find(marker)? + marker.len();
    let value_end = value_start + line[value_start..].find('"')?;

    let mut updated = String::with_capacity(line.len() + version.len());
    updated.push_str(&line[..value_start]);
    updated.push_str(version);
    updated.push_str(&line[value_end..]);
    Some(updated)
}

fn replace_prefixed_line(path: &Path, prefix: &str, replacement: &str) -> Result<()> {
    replace_matching_line(
        path,
        |line| line.starts_with(prefix),
        replacement,
        &format!("{prefix} line"),
    )
}

fn replace_matching_line(
    path: &Path,
    predicate: impl Fn(&str) -> bool,
    replacement: &str,
    label: &str,
) -> Result<()> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let had_trailing_newline = contents.ends_with('\n');
    let mut replaced = 0usize;
    let mut lines = Vec::new();

    for line in contents.lines() {
        if predicate(line) {
            replaced += 1;
            lines.push(replacement.to_string());
        } else {
            lines.push(line.to_string());
        }
    }

    if replaced == 0 {
        bail!("{} did not contain {label}", path.display());
    }

    write_lines(path, lines, had_trailing_newline)
}

fn replace_first_line(path: &Path, replacement: &str) -> Result<()> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let had_trailing_newline = contents.ends_with('\n');
    let mut lines: Vec<String> = contents.lines().map(str::to_string).collect();
    let Some(first) = lines.first_mut() else {
        bail!("{} is empty", path.display());
    };
    *first = replacement.to_string();
    write_lines(path, lines, had_trailing_newline)
}

fn write_lines(path: &Path, lines: Vec<String>, trailing_newline: bool) -> Result<()> {
    let mut contents = lines.join("\n");
    if trailing_newline {
        contents.push('\n');
    }
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn load_publishable_packages() -> Result<BTreeMap<String, LocalPackage>> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .output()
        .context("spawn cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let metadata: Value = serde_json::from_slice(&output.stdout).context("parse cargo metadata")?;
    let workspace_root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .context("cargo metadata missing workspace_root")?;
    let package_values = metadata
        .get("packages")
        .and_then(Value::as_array)
        .context("cargo metadata missing packages array")?;

    let mut raw_packages = BTreeMap::new();
    let mut local_names = BTreeSet::new();
    for package in package_values {
        let name = json_string(package, "name")?.to_string();
        raw_packages.insert(name.clone(), package.clone());

        if !is_publishable_local_package(package, &workspace_root)? {
            continue;
        }
        local_names.insert(name);
    }

    let mut packages = BTreeMap::new();
    for name in &local_names {
        let package = raw_packages
            .get(name)
            .ok_or_else(|| anyhow!("metadata package disappeared: {name}"))?;
        let version = json_string(package, "version")?.to_string();
        let manifest_path = PathBuf::from(json_string(package, "manifest_path")?);
        let mut dependencies = BTreeSet::new();

        for dependency in package
            .get("dependencies")
            .and_then(Value::as_array)
            .context("cargo metadata package missing dependencies array")?
        {
            if !dependency_kind_affects_publish_order(dependency) {
                continue;
            }
            let dependency_name = json_string(dependency, "name")?;
            if local_names.contains(dependency_name) {
                dependencies.insert(dependency_name.to_string());
            }
        }

        packages.insert(
            name.clone(),
            LocalPackage {
                name: name.clone(),
                version,
                manifest_path,
                dependencies,
            },
        );
    }

    Ok(packages)
}

fn is_publishable_local_package(package: &Value, workspace_root: &Path) -> Result<bool> {
    if !package.get("source").is_none_or(Value::is_null) {
        return Ok(false);
    }
    if package
        .get("publish")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Ok(false);
    }

    let manifest_path = PathBuf::from(json_string(package, "manifest_path")?);
    Ok(manifest_path.starts_with(workspace_root))
}

fn dependency_kind_affects_publish_order(dependency: &Value) -> bool {
    match dependency.get("kind") {
        None | Some(Value::Null) => true,
        Some(Value::String(kind)) if kind == "build" => true,
        _ => false,
    }
}

fn publish_order(packages: &BTreeMap<String, LocalPackage>, label: &str) -> Result<Vec<String>> {
    let mut indegree = BTreeMap::new();
    let mut reverse: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (name, package) in packages {
        indegree.insert(name.clone(), package.dependencies.len());
        reverse.entry(name.clone()).or_default();
        for dependency in &package.dependencies {
            reverse
                .entry(dependency.clone())
                .or_default()
                .insert(name.clone());
        }
    }

    let mut queue: VecDeque<String> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(name, _)| name.clone())
        .collect();
    let mut order = Vec::new();

    while let Some(name) = queue.pop_front() {
        order.push(name.clone());
        for dependent in reverse.get(&name).into_iter().flatten() {
            let degree = indegree.get_mut(dependent).ok_or_else(|| {
                anyhow!("reverse dependency referenced unknown package {dependent}")
            })?;
            *degree -= 1;
            if *degree == 0 {
                queue.push_back(dependent.clone());
            }
        }
    }

    if order.len() != packages.len() {
        bail!("{label} aborted: local publish graph has a cycle");
    }

    Ok(order)
}

fn write_patch_config(
    packages: &BTreeMap<String, LocalPackage>,
    current_package: &str,
) -> Result<TempFile> {
    let needed = transitive_local_dependencies(packages, current_package)?;
    let mut contents = String::from("[patch.crates-io]\n");
    for name in needed {
        let package = packages
            .get(&name)
            .ok_or_else(|| anyhow!("patch config referenced unknown package {name}"))?;
        let manifest_dir = package.manifest_path.parent().ok_or_else(|| {
            anyhow!(
                "{} has no parent directory",
                package.manifest_path.display()
            )
        })?;
        contents.push_str(&format!(
            "{} = {{ path = \"{}\" }}\n",
            package.name,
            toml_escape(&manifest_dir.to_string_lossy())
        ));
    }

    write_temp_file(&format!("smoo-patch-{current_package}"), &contents)
}

fn transitive_local_dependencies(
    packages: &BTreeMap<String, LocalPackage>,
    current_package: &str,
) -> Result<BTreeSet<String>> {
    let current = packages
        .get(current_package)
        .ok_or_else(|| anyhow!("package {current_package:?} is not a local publishable package"))?;
    let mut needed = BTreeSet::new();
    let mut stack: Vec<String> = current.dependencies.iter().cloned().collect();

    while let Some(name) = stack.pop() {
        if !needed.insert(name.clone()) {
            continue;
        }
        let package = packages
            .get(&name)
            .ok_or_else(|| anyhow!("dependency graph referenced unknown package {name}"))?;
        stack.extend(package.dependencies.iter().cloned());
    }

    Ok(needed)
}

fn run_publish_attempt(package_name: &str) -> Result<PublishAttempt> {
    let output = Command::new("cargo")
        .arg("publish")
        .arg("-p")
        .arg(package_name)
        .arg("--locked")
        .output()
        .with_context(|| format!("spawn cargo publish -p {package_name} --locked"))?;
    Ok(PublishAttempt {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

struct PublishAttempt {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl PublishAttempt {
    fn print(&self) {
        let _ = std::io::stdout().write_all(&self.stdout);
        let _ = std::io::stderr().write_all(&self.stderr);
    }

    fn combined_log(&self) -> String {
        let mut log = String::from_utf8_lossy(&self.stdout).into_owned();
        log.push_str(&String::from_utf8_lossy(&self.stderr));
        log
    }
}

fn is_already_published(package_name: &str, package_version: &str) -> bool {
    let url = format!("https://crates.io/api/v1/crates/{package_name}/{package_version}");
    let output = Command::new("curl")
        .arg("-L")
        .arg("-sS")
        .arg("--max-time")
        .arg("20")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg(&url)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let http_code = String::from_utf8_lossy(&output.stdout);
            match http_code.trim() {
                "200" => true,
                "404" => false,
                code => {
                    eprintln!(
                        "warning: crates.io lookup for {package_name}@{package_version} returned HTTP {code}; continuing with publish attempt"
                    );
                    false
                }
            }
        }
        Ok(output) => {
            eprintln!(
                "warning: crates.io lookup for {package_name}@{package_version} failed ({:?}): {}; continuing with publish attempt",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
        Err(error) => {
            eprintln!(
                "warning: crates.io lookup for {package_name}@{package_version} failed ({error}); continuing with publish attempt"
            );
            false
        }
    }
}

enum PublishFailure {
    AlreadyPublished,
    Transient,
    Permanent,
}

fn classify_publish_failure(log: &str) -> PublishFailure {
    let lower = log.to_ascii_lowercase();

    if lower.contains("already exists on crates.io index") {
        return PublishFailure::AlreadyPublished;
    }

    let transient_patterns = [
        "status 429",
        "too many requests",
        "timed out",
        "timeout",
        "spurious network error",
        "connection reset",
        "connection refused",
        "temporary failure",
        "not yet available at registry",
    ];
    if transient_patterns
        .iter()
        .any(|pattern| lower.contains(pattern))
        || contains_status_5xx(&lower)
        || (lower.contains("no matching package named `") && lower.contains("` found"))
    {
        return PublishFailure::Transient;
    }

    PublishFailure::Permanent
}

fn contains_status_5xx(text: &str) -> bool {
    let mut rest = text;
    while let Some(index) = rest.find("status ") {
        let after = &rest[index + "status ".len()..];
        let code = after.as_bytes();
        if code.len() >= 3
            && code[0] == b'5'
            && code[1].is_ascii_digit()
            && code[2].is_ascii_digit()
        {
            return true;
        }
        rest = after;
    }
    false
}

fn write_temp_file(prefix: &str, contents: &str) -> Result<TempFile> {
    for attempt in 0..100u32 {
        let path = std::env::temp_dir().join(format!(
            "{}-{}-{}-{attempt}.toml",
            sanitize_path_component(prefix),
            std::process::id(),
            unix_time_nanos()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())
                    .with_context(|| format!("write {}", path.display()))?;
                return Ok(TempFile { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
        }
    }
    bail!("failed to create temporary patch config after 100 attempts")
}

fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '-',
        })
        .collect()
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("cargo metadata missing string field {field}"))
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<()> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("spawn {label}"))?;
    if !status.success() {
        bail!("{label} failed: {status:?}");
    }
    Ok(())
}

fn unix_time_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
