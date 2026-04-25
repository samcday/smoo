//! Integration test harness for smoo.
//!
//! Spawns the real `smoo-gadget` and `smoo-host` binaries as child processes
//! against a per-test `dummy_hcd` UDC↔HCD loopback, with a `usbmon` packet
//! capture running for the duration. Each scenario is a `#[tokio::test]`;
//! fixtures clean up via RAII.
//!
//! Linux-only — non-Linux targets get an empty crate.
//!
//! Top-level entry point: [`scenario::ScenarioBuilder`].

#![cfg(target_os = "linux")]

pub mod artifacts;
pub mod capture;
pub mod configfs;
pub mod dummy_hcd;
pub mod fixture;
pub mod process;
pub mod scenario;
pub mod verify;

pub use artifacts::{ArtifactBundle, ExitInfo, Metadata, OpMixSer};
pub use capture::CaptureSession;
pub use dummy_hcd::Slot;
pub use fixture::{
    GadgetFixture, GadgetOpts, HostFixture, HostOpts, HostSourceSpec, KernelFixture,
};
pub use scenario::{ExportSpec, RunningScenario, ScenarioBuilder, ScenarioResult};
pub use verify::block_pattern::BlockPatternVerifier;
pub use verify::pcap::{OpMix, PcapAssertions};
