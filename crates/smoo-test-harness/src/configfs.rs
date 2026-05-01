//! Per-test configfs gadget directory + FunctionFS mount + UDC binding.
//!
//! Owns kernel-side state for a single scenario. Created via [`GadgetConfigFs::create`]
//! before the gadget binary is spawned (sets up the FunctionFS dir so the
//! gadget can open ep0 and write descriptors). UDC binding is deferred to
//! [`GadgetConfigFs::bind_udc`], which the harness calls only after the
//! gadget has logged its readiness signal.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use nix::mount::{MsFlags, mount, umount};

use crate::dummy_hcd::Slot;

const CONFIGFS_USB_GADGET: &str = "/sys/kernel/config/usb_gadget";
const FFS_MOUNT_PARENT: &str = "/tmp";

pub struct GadgetConfigFs {
    pub gadget_dir: PathBuf,
    pub ffs_mount_dir: PathBuf,
    pub ffs_instance: String,
    pub udc_name: String,
    pub config_link: PathBuf,
    udc_bound: AtomicBool,
    teardown_done: AtomicBool,
}

impl GadgetConfigFs {
    /// Build the gadget tree and mount FunctionFS, but do NOT bind the UDC.
    /// The gadget process must open ep0 and write descriptors first; call
    /// [`Self::bind_udc`] afterwards.
    pub fn create(slot: &Slot) -> Result<Self> {
        let gadget_dir = Path::new(CONFIGFS_USB_GADGET).join(&slot.gadget_name);
        let ffs_mount_dir = Path::new(FFS_MOUNT_PARENT).join(format!("smoo-ffs-{}", slot.udc_idx));
        let config_link = gadget_dir
            .join("configs/c.1")
            .join(format!("ffs.{}", slot.ffs_instance));

        // Best-effort cleanup of any leaked state from a prior crashed run.
        try_remove_existing(&gadget_dir, &ffs_mount_dir);

        fs::create_dir_all(&gadget_dir)
            .with_context(|| format!("mkdir {}", gadget_dir.display()))?;

        let g = GadgetConfigFs {
            gadget_dir: gadget_dir.clone(),
            ffs_mount_dir: ffs_mount_dir.clone(),
            ffs_instance: slot.ffs_instance.clone(),
            udc_name: slot.udc_name(),
            config_link: config_link.clone(),
            udc_bound: AtomicBool::new(false),
            teardown_done: AtomicBool::new(false),
        };

        // Tree creation. From this point, any failure must roll back via Drop.
        if let Err(err) = g.populate(slot) {
            tracing::warn!(error = ?err, "configfs gadget populate failed; tearing down");
            g.teardown();
            return Err(err);
        }
        Ok(g)
    }

    fn populate(&self, slot: &Slot) -> Result<()> {
        let gd = &self.gadget_dir;

        write_sys(&gd.join("idVendor"), &format!("0x{:04x}", slot.vid))?;
        write_sys(&gd.join("idProduct"), &format!("0x{:04x}", slot.pid))?;
        write_sys(&gd.join("bcdDevice"), "0x0001")?;
        write_sys(&gd.join("bcdUSB"), "0x0200")?;

        let strings = gd.join("strings/0x409");
        fs::create_dir_all(&strings).with_context(|| format!("mkdir {}", strings.display()))?;
        write_sys(&strings.join("manufacturer"), "smoo-test")?;
        write_sys(&strings.join("product"), "smoo gadget (test)")?;
        write_sys(
            &strings.join("serialnumber"),
            &format!("test-{}", slot.udc_idx),
        )?;

        let cfg = gd.join("configs/c.1");
        fs::create_dir_all(&cfg).with_context(|| format!("mkdir {}", cfg.display()))?;
        let cfg_strings = cfg.join("strings/0x409");
        fs::create_dir_all(&cfg_strings)
            .with_context(|| format!("mkdir {}", cfg_strings.display()))?;
        write_sys(&cfg_strings.join("configuration"), "smoo test config")?;
        write_sys(&cfg.join("MaxPower"), "100")?;

        let func = gd.join(format!("functions/ffs.{}", slot.ffs_instance));
        fs::create_dir_all(&func).with_context(|| format!("mkdir {}", func.display()))?;

        fs::create_dir_all(&self.ffs_mount_dir)
            .with_context(|| format!("mkdir {}", self.ffs_mount_dir.display()))?;

        mount(
            Some(slot.ffs_instance.as_str()),
            &self.ffs_mount_dir,
            Some("functionfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "mount -t functionfs {} {}",
                slot.ffs_instance,
                self.ffs_mount_dir.display()
            )
        })?;

        symlink(&func, &self.config_link).with_context(|| {
            format!(
                "symlink {} -> {}",
                self.config_link.display(),
                func.display()
            )
        })?;

        Ok(())
    }

    /// Write the UDC name to the gadget's `UDC` file. The composite framework
    /// will issue BIND/ENABLE on ep0 of the gadget process. Call only after the
    /// gadget has finished writing descriptors.
    pub fn bind_udc(&self) -> Result<()> {
        if self.udc_bound.load(Ordering::Acquire) {
            bail!("udc already bound");
        }
        write_sys(&self.gadget_dir.join("UDC"), &self.udc_name)
            .with_context(|| format!("bind UDC={}", self.udc_name))?;
        self.udc_bound.store(true, Ordering::Release);
        Ok(())
    }

    pub fn unbind_udc(&self) {
        if self.udc_bound.swap(false, Ordering::AcqRel) {
            // empty string clears UDC binding
            if let Err(err) = write_sys(&self.gadget_dir.join("UDC"), "") {
                tracing::warn!(error = ?err, gadget = %self.gadget_dir.display(), "UDC unbind failed");
            }
        }
    }

    fn teardown(&self) {
        if self.teardown_done.swap(true, Ordering::AcqRel) {
            return;
        }
        self.unbind_udc();

        // Remove the symlink first to break the function-config association.
        if self.config_link.symlink_metadata().is_ok()
            && let Err(err) = fs::remove_file(&self.config_link)
        {
            tracing::warn!(error = ?err, path = %self.config_link.display(), "rm config link failed");
        }

        // umount the FunctionFS instance.
        if self.ffs_mount_dir.exists()
            && let Err(err) = umount(&self.ffs_mount_dir)
        {
            tracing::warn!(error = ?err, path = %self.ffs_mount_dir.display(), "umount FunctionFS failed");
        }

        // Now rmdir the function instance.
        let func = self
            .gadget_dir
            .join(format!("functions/ffs.{}", self.ffs_instance));
        if func.exists()
            && let Err(err) = fs::remove_dir(&func)
        {
            tracing::warn!(error = ?err, path = %func.display(), "rmdir function failed");
        }

        // configs/c.1/strings/0x409, then configs/c.1
        let cfg = self.gadget_dir.join("configs/c.1");
        let cfg_strings = cfg.join("strings/0x409");
        for d in [&cfg_strings, &cfg] {
            if d.exists()
                && let Err(err) = fs::remove_dir(d)
            {
                tracing::warn!(error = ?err, path = %d.display(), "rmdir config dir failed");
            }
        }

        // strings/0x409
        let strings = self.gadget_dir.join("strings/0x409");
        if strings.exists()
            && let Err(err) = fs::remove_dir(&strings)
        {
            tracing::warn!(error = ?err, path = %strings.display(), "rmdir strings failed");
        }

        // gadget dir itself
        if self.gadget_dir.exists()
            && let Err(err) = fs::remove_dir(&self.gadget_dir)
        {
            tracing::warn!(error = ?err, path = %self.gadget_dir.display(), "rmdir gadget failed");
        }

        // ffs mount directory (now empty)
        if self.ffs_mount_dir.exists()
            && let Err(err) = fs::remove_dir(&self.ffs_mount_dir)
        {
            tracing::warn!(error = ?err, path = %self.ffs_mount_dir.display(), "rmdir ffs mount failed");
        }
    }
}

impl Drop for GadgetConfigFs {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn write_sys(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("write {}", path.display()))
}

/// Attempt to remove a leaked gadget directory + ffs mount from a prior run.
/// Best-effort; ignores all errors and just logs.
fn try_remove_existing(gadget_dir: &Path, ffs_mount: &Path) {
    if !gadget_dir.exists() && !ffs_mount.exists() {
        return;
    }
    tracing::info!(
        gadget = %gadget_dir.display(),
        ffs = %ffs_mount.display(),
        "leaked configfs/ffs state from prior run; cleaning"
    );
    // Unbind UDC if bound
    let _ = fs::write(gadget_dir.join("UDC"), "");
    // Try to remove all symlinks under configs/c.1/
    if let Ok(rd) = fs::read_dir(gadget_dir.join("configs/c.1")) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                let _ = fs::remove_file(&p);
            }
        }
    }
    // Best-effort umount
    if ffs_mount.exists() {
        let _ = umount(ffs_mount);
    }
    // Recursive rmdir of gadget dir contents (configfs is shallow)
    let _ = recursive_rmdir(gadget_dir);
    let _ = fs::remove_dir(ffs_mount);
}

fn recursive_rmdir(dir: &Path) -> std::io::Result<()> {
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let _ = recursive_rmdir(&p);
            } else if p
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                let _ = fs::remove_file(&p);
            }
        }
    }
    fs::remove_dir(dir)
}
