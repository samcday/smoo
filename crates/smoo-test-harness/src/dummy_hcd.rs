//! Slot allocator + sysfs probing for `dummy_hcd` instances.
//!
//! `dummy_hcd` (loaded with `num=N`) creates N pairs of
//! `dummy_hcd.<i>` / `dummy_udc.<i>`. Binding a gadget to `dummy_udc.<i>`
//! makes the device visible on the bus owned by `dummy_hcd.<i>`. Each test
//! reserves one index via the [`SlotPool`].

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};

/// Default number of `dummy_hcd` instances expected. Matches `cargo xtask
/// test-infra-setup` (`modprobe dummy_hcd num=4`).
pub const DEFAULT_NUM_INSTANCES: u32 = 4;

/// VID handed to every gadget the harness creates. The PID varies by slot so
/// concurrent tests don't collide on USB device discovery.
pub const HARNESS_VID: u16 = 0xCAFE;

/// PID base. Final PID = `HARNESS_PID_BASE + slot_idx`.
pub const HARNESS_PID_BASE: u16 = 0xB000;

/// A reserved dummy_hcd/dummy_udc index plus the parameters derived from it.
/// Returned to the pool on drop.
pub struct Slot {
    pub udc_idx: u32,
    pub bus_id: u32,
    pub vid: u16,
    pub pid: u16,
    pub gadget_name: String,
    pub ffs_instance: String,
    pool: Arc<Mutex<SlotPool>>,
}

impl Slot {
    pub fn udc_name(&self) -> String {
        format!("dummy_udc.{}", self.udc_idx)
    }

    pub fn hcd_name(&self) -> String {
        format!("dummy_hcd.{}", self.udc_idx)
    }
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("udc_idx", &self.udc_idx)
            .field("bus_id", &self.bus_id)
            .field("vid", &format_args!("0x{:04x}", self.vid))
            .field("pid", &format_args!("0x{:04x}", self.pid))
            .field("gadget_name", &self.gadget_name)
            .field("ffs_instance", &self.ffs_instance)
            .finish()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.pool
            .lock()
            .expect("slot pool mutex poisoned")
            .release(self.udc_idx);
    }
}

#[derive(Debug)]
pub struct SlotPool {
    in_use: Vec<bool>,
    next: usize,
}

impl SlotPool {
    pub fn new(size: u32) -> Self {
        Self {
            in_use: vec![false; size as usize],
            next: 0,
        }
    }

    pub fn try_take(&mut self) -> Option<u32> {
        if self.in_use.is_empty() {
            return None;
        }

        for _ in 0..self.in_use.len() {
            let idx = self.next;
            self.next = (self.next + 1) % self.in_use.len();
            if !self.in_use[idx] {
                self.in_use[idx] = true;
                return Some(idx as u32);
            }
        }
        None
    }

    fn release(&mut self, idx: u32) {
        if let Some(slot) = self.in_use.get_mut(idx as usize) {
            *slot = false;
        }
    }
}

fn lock_pool(pool: &Mutex<SlotPool>) -> std::sync::MutexGuard<'_, SlotPool> {
    pool.lock().expect("slot pool mutex poisoned")
}

/// Reserve one slot from the pool. Verifies that `dummy_udc.<idx>` and the
/// matching HCD bus are present before returning; releases on probe failure.
pub fn allocate_slot(pool: &Arc<Mutex<SlotPool>>) -> Result<Slot> {
    let idx = lock_pool(pool)
        .try_take()
        .ok_or_else(|| anyhow::anyhow!("no free dummy_hcd slot — increase dummy_hcd num?"))?;

    if !udc_present(idx) {
        lock_pool(pool).release(idx);
        bail!("dummy_udc.{idx} not present in /sys/class/udc — is dummy_hcd loaded?");
    }
    let bus_id = match bus_for_hcd(idx) {
        Ok(bus) => bus,
        Err(err) => {
            lock_pool(pool).release(idx);
            return Err(err.context(format!("resolve bus for dummy_hcd.{idx}")));
        }
    };

    Ok(Slot {
        udc_idx: idx,
        bus_id,
        vid: HARNESS_VID,
        pid: HARNESS_PID_BASE + idx as u16,
        gadget_name: format!("g_smoo_test_{idx}"),
        ffs_instance: format!("smoo_test_{idx}"),
        pool: Arc::clone(pool),
    })
}

/// True if `/sys/class/udc/dummy_udc.<idx>` exists.
pub fn udc_present(idx: u32) -> bool {
    Path::new(&format!("/sys/class/udc/dummy_udc.{idx}")).exists()
}

/// Resolve the USB bus number assigned to `dummy_hcd.<idx>`.
///
/// The HCD platform device under sysfs has a child directory named `usb<bus>`;
/// reading the directory gives us the bus number to pass to `usbmon`.
pub fn bus_for_hcd(idx: u32) -> Result<u32> {
    let dir = format!("/sys/devices/platform/dummy_hcd.{idx}");
    let entries =
        fs::read_dir(&dir).with_context(|| format!("read {dir} (is dummy_hcd loaded?)"))?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(rest) = name.strip_prefix("usb")
            && let Ok(bus) = rest.parse::<u32>()
        {
            return Ok(bus);
        }
    }
    bail!("no usb<bus> child under {dir}; gadget may not be bound yet");
}

/// Probe of the kernel state required by the harness. Returns the number of
/// available `dummy_hcd` controller pairs usable by the slot pool.
pub fn probe_kernel() -> Result<u32> {
    let need_dirs: &[&str] = &["/sys/kernel/config/usb_gadget", "/sys/class/udc"];
    for dir in need_dirs {
        if !Path::new(dir).is_dir() {
            bail!(
                "{dir} not present — load configfs+libcomposite (try `cargo xtask test-infra-setup`)"
            );
        }
    }
    if !udc_present(0) {
        bail!("dummy_udc.0 not present — `modprobe dummy_hcd num={DEFAULT_NUM_INSTANCES}` first");
    }
    if !Path::new("/dev/ublk-control").exists() {
        bail!("/dev/ublk-control missing — `modprobe ublk_drv`");
    }
    let usbmon_ok =
        Path::new("/sys/kernel/debug/usb/usbmon").is_dir() || Path::new("/dev/usbmon0").exists();
    if !usbmon_ok {
        bail!(
            "no usbmon interface — mount debugfs (sudo mount -t debugfs none /sys/kernel/debug) and `modprobe usbmon`"
        );
    }
    Ok(available_slot_count())
}

fn available_slot_count() -> u32 {
    (0..DEFAULT_NUM_INSTANCES)
        .take_while(|idx| udc_present(*idx))
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_try_take_and_release() {
        let mut pool = SlotPool::new(2);
        assert_eq!(pool.try_take(), Some(0));
        assert_eq!(pool.try_take(), Some(1));
        assert_eq!(pool.try_take(), None);
        pool.release(0);
        assert_eq!(pool.try_take(), Some(0));
    }

    #[test]
    fn pool_rotates_after_release() {
        let mut pool = SlotPool::new(3);
        assert_eq!(pool.try_take(), Some(0));
        pool.release(0);
        assert_eq!(pool.try_take(), Some(1));
        pool.release(1);
        assert_eq!(pool.try_take(), Some(2));
        pool.release(2);
        assert_eq!(pool.try_take(), Some(0));
    }
}
