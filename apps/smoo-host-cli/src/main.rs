use anyhow::{anyhow, Context, Result};
use clap::{ArgGroup, Parser};
use rusb::{Direction, TransferType, UsbContext};
use smoo_host_blocksources::{DeviceBlockSource, FileBlockSource};
use smoo_host_core::{BlockSource, BlockSourceResult, HostErrorKind, SmooHost};
use smoo_host_rusb::{RusbTransport, RusbTransportConfig};
use std::{path::PathBuf, time::Duration};
use tokio::signal;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "smoo-host-cli")]
#[command(about = "Host shim for smoo gadgets", long_about = None)]
#[command(group = ArgGroup::new("backing").args(["file", "device"]).required(true))]
struct Args {
    /// USB vendor ID of the gadget
    #[arg(long, default_value_t = 0xDEAD)]
    vendor_id: u16,
    /// USB product ID of the gadget
    #[arg(long, default_value_t = 0xBEEF)]
    product_id: u16,
    /// Optional disk image backing file
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Optional block device backing file
    #[arg(long, value_name = "PATH")]
    device: Option<PathBuf>,
    /// Logical block size exposed through the gadget (bytes)
    #[arg(long, default_value_t = 512)]
    block_size: u32,
    /// USB interface number that carries the FunctionFS endpoints
    #[arg(long, default_value_t = 0)]
    interface: u8,
    /// Control/interrupt transfer timeout in milliseconds
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
}

enum HostSource {
    File(FileBlockSource),
    Device(DeviceBlockSource),
}

#[async_trait::async_trait]
impl BlockSource for HostSource {
    fn block_size(&self) -> u32 {
        match self {
            HostSource::File(inner) => inner.block_size(),
            HostSource::Device(inner) => inner.block_size(),
        }
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        match self {
            HostSource::File(inner) => inner.total_blocks().await,
            HostSource::Device(inner) => inner.total_blocks().await,
        }
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.read_blocks(lba, buf).await,
            HostSource::Device(inner) => inner.read_blocks(lba, buf).await,
        }
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.write_blocks(lba, buf).await,
            HostSource::Device(inner) => inner.write_blocks(lba, buf).await,
        }
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.flush().await,
            HostSource::Device(inner) => inner.flush().await,
        }
    }

    async fn discard(&self, lba: u64, num_blocks: u32) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.discard(lba, num_blocks).await,
            HostSource::Device(inner) => inner.discard(lba, num_blocks).await,
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    let source = open_source(&args).await.context("open block source")?;
    let handle = open_device(&args).context("open usb device")?;
    let (interrupt_in, interrupt_out) =
        infer_interrupt_endpoints(&handle, args.interface).context("discover endpoints")?;
    let transport_config = RusbTransportConfig {
        interface: args.interface,
        interrupt_in,
        interrupt_out,
        timeout: Duration::from_millis(args.timeout_ms),
    };
    let transport = RusbTransport::new(handle, transport_config).context("init transport")?;
    let mut host = SmooHost::new(transport, source);
    let ident = host.setup().await.context("ident handshake")?;
    info!(
        major = ident.major,
        minor = ident.minor,
        "connected to smoo gadget"
    );

    loop {
        tokio::select! {
            res = host.run_once() => {
                match res {
                    Ok(()) => {}
                    Err(err) => match err.kind() {
                        HostErrorKind::Unsupported | HostErrorKind::InvalidRequest => {
                            warn!(error = %err, "request handling failed");
                        }
                        _ => return Err(anyhow!(err.to_string())),
                    },
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutdown requested");
                break;
            }
        }
    }

    Ok(())
}

async fn open_source(args: &Args) -> Result<HostSource> {
    let block_size = args.block_size;
    match (&args.file, &args.device) {
        (Some(path), None) => Ok(HostSource::File(
            FileBlockSource::open(path, block_size).await?,
        )),
        (None, Some(path)) => Ok(HostSource::Device(
            DeviceBlockSource::open(path, block_size).await?,
        )),
        _ => unreachable!("clap enforces mutually exclusive arguments"),
    }
}

fn open_device(args: &Args) -> Result<rusb::DeviceHandle<rusb::Context>> {
    let context = rusb::Context::new().context("init libusb context")?;
    let handle = context
        .open_device_with_vid_pid(args.vendor_id, args.product_id)
        .ok_or_else(|| {
            anyhow!(
                "device {:04x}:{:04x} not found",
                args.vendor_id,
                args.product_id
            )
        })?;
    handle
        .set_auto_detach_kernel_driver(true)
        .context("enable auto-detach")?;
    Ok(handle)
}

fn infer_interrupt_endpoints<T: UsbContext>(
    handle: &rusb::DeviceHandle<T>,
    interface: u8,
) -> Result<(u8, u8)> {
    let config = handle
        .device()
        .active_config_descriptor()
        .context("read active config descriptor")?;
    for intf in config.interfaces() {
        for desc in intf.descriptors() {
            if desc.interface_number() != interface {
                continue;
            }
            let mut in_ep = None;
            let mut out_ep = None;
            for ep in desc.endpoint_descriptors() {
                if ep.transfer_type() != TransferType::Interrupt {
                    continue;
                }
                match ep.direction() {
                    Direction::In => in_ep = Some(ep.address()),
                    Direction::Out => out_ep = Some(ep.address()),
                }
            }
            if let (Some(in_addr), Some(out_addr)) = (in_ep, out_ep) {
                return Ok((in_addr, out_addr));
            }
        }
    }
    Err(anyhow!(
        "interrupt endpoints not found for interface {}",
        interface
    ))
}
