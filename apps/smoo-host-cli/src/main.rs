use anyhow::{anyhow, Context, Result};
use clap::{ArgGroup, Parser};
use rusb::{Direction, TransferType, UsbContext};
use smoo_host_blocksources::{DeviceBlockSource, FileBlockSource};
use smoo_host_core::{BlockSource, BlockSourceResult, HostErrorKind, SmooHost};
use smoo_host_rusb::{ConfigExportsV0Payload, RusbTransport, RusbTransportConfig};
use std::{path::PathBuf, time::Duration};
use tokio::signal;
use tracing::{debug, info, warn};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;

#[derive(Debug, Parser)]
#[command(name = "smoo-host-cli")]
#[command(
    about = "Host shim for smoo gadgets",
    long_about = "Host shim for smoo gadgets. By default all visible USB devices are scanned and the first interface matching the vendor triple 0xFF/0x53/0x4D is selected."
)]
#[command(group = ArgGroup::new("backing").args(["file", "device"]).required(true))]
struct Args {
    /// Optional USB vendor ID filter (hex). Defaults to all vendors.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    vendor_id: Option<u16>,
    /// Optional USB product ID filter (hex). Defaults to all products.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    product_id: Option<u16>,
    /// Optional disk image backing file
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Optional block device backing file
    #[arg(long, value_name = "PATH")]
    device: Option<PathBuf>,
    /// Logical block size exposed through the gadget (bytes)
    #[arg(long, default_value_t = 512)]
    block_size: u32,
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
    let block_size = source.block_size();
    let size_bytes = match source.total_blocks().await {
        Ok(blocks) => blocks.checked_mul(block_size as u64).unwrap_or(0),
        Err(err) => {
            warn!(error = %err, "determine total blocks failed; advertising dynamic size");
            0
        }
    };
    let (handle, interface) = discover_device(&args).context("discover usb device")?;
    let endpoints = infer_interface_endpoints(&handle, interface).context("discover endpoints")?;
    let transport_config = RusbTransportConfig {
        interface,
        interrupt_in: endpoints.interrupt_in,
        interrupt_out: endpoints.interrupt_out,
        bulk_in: endpoints.bulk_in,
        bulk_out: endpoints.bulk_out,
        timeout: Duration::from_millis(args.timeout_ms),
    };
    let mut transport = RusbTransport::new(handle, transport_config).context("init transport")?;
    let ident = transport
        .ensure_ident()
        .await
        .context("IDENT control transfer")?;
    debug!(
        major = ident.major,
        minor = ident.minor,
        "gadget IDENT response"
    );
    let config_payload = ConfigExportsV0Payload::single_export(block_size, size_bytes);
    transport
        .send_config_exports_v0(&config_payload)
        .await
        .context("CONFIG_EXPORTS control transfer")?;
    info!(
        block_size = block_size,
        size_bytes = size_bytes,
        "configured gadget export"
    );
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

fn discover_device(args: &Args) -> Result<(rusb::DeviceHandle<rusb::Context>, u8)> {
    let context = rusb::Context::new().context("init libusb context")?;
    let devices = context.devices().context("enumerate usb devices")?;
    info!(
        vendor_filter = args.vendor_id.map(|v| format!("{:#06x}", v)),
        product_filter = args.product_id.map(|p| format!("{:#06x}", p)),
        "scanning USB devices for smoo gadget"
    );
    for device in devices.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(desc) => desc,
            Err(err) => {
                warn!(error = %err, "read device descriptor failed");
                continue;
            }
        };
        if let Some(vendor) = args.vendor_id {
            if device_desc.vendor_id() != vendor {
                debug!(
                    vid = format_args!("{:#06x}", device_desc.vendor_id()),
                    pid = format_args!("{:#06x}", device_desc.product_id()),
                    "skipping device due to vendor filter"
                );
                continue;
            }
        } else {
            debug!(
                vid = format_args!("{:#06x}", device_desc.vendor_id()),
                pid = format_args!("{:#06x}", device_desc.product_id()),
                "examining usb device"
            );
        }
        if let Some(product) = args.product_id {
            if device_desc.product_id() != product {
                debug!("skipping device due to product filter");
                continue;
            }
        }
        for cfg_idx in 0..device_desc.num_configurations() {
            let config = match device.config_descriptor(cfg_idx) {
                Ok(cfg) => cfg,
                Err(err) => {
                    warn!(error = %err, config = cfg_idx, "read config descriptor failed");
                    continue;
                }
            };
            for interface in config.interfaces() {
                for desc in interface.descriptors() {
                    let iface_num = desc.interface_number();
                    if desc.class_code() == SMOO_INTERFACE_CLASS
                        && desc.sub_class_code() == SMOO_INTERFACE_SUBCLASS
                        && desc.protocol_code() == SMOO_INTERFACE_PROTOCOL
                    {
                        let handle = match device.open() {
                            Ok(handle) => handle,
                            Err(err) => {
                                warn!(error = %err, "failed to open matching usb device");
                                continue;
                            }
                        };
                        handle
                            .set_auto_detach_kernel_driver(true)
                            .context("enable auto-detach")?;
                        info!(
                            vid = format_args!("{:#06x}", device_desc.vendor_id()),
                            pid = format_args!("{:#06x}", device_desc.product_id()),
                            interface = iface_num,
                            "selected smoo-compatible interface"
                        );
                        return Ok((handle, iface_num));
                    }
                }
            }
        }
    }
    Err(anyhow!(
        "No smoo-compatible USB devices found{}.",
        if args.vendor_id.is_some() || args.product_id.is_some() {
            " (after applying filters)"
        } else {
            ""
        }
    ))
}

struct InterfaceEndpoints {
    interrupt_in: u8,
    interrupt_out: u8,
    bulk_in: u8,
    bulk_out: u8,
}

#[derive(Default)]
struct EndpointBuilder {
    interrupt_in: Option<u8>,
    interrupt_out: Option<u8>,
    bulk_in: Option<u8>,
    bulk_out: Option<u8>,
}

impl EndpointBuilder {
    fn record(&mut self, ep: &rusb::EndpointDescriptor) {
        match (ep.transfer_type(), ep.direction()) {
            (TransferType::Interrupt, Direction::In) if self.interrupt_in.is_none() => {
                self.interrupt_in = Some(ep.address());
            }
            (TransferType::Interrupt, Direction::Out) if self.interrupt_out.is_none() => {
                self.interrupt_out = Some(ep.address());
            }
            (TransferType::Bulk, Direction::In) if self.bulk_in.is_none() => {
                self.bulk_in = Some(ep.address());
            }
            (TransferType::Bulk, Direction::Out) if self.bulk_out.is_none() => {
                self.bulk_out = Some(ep.address());
            }
            _ => {}
        }
    }

    fn finish(self) -> Option<InterfaceEndpoints> {
        let (Some(interrupt_in), Some(interrupt_out), Some(bulk_in), Some(bulk_out)) = (
            self.interrupt_in,
            self.interrupt_out,
            self.bulk_in,
            self.bulk_out,
        ) else {
            return None;
        };
        Some(InterfaceEndpoints {
            interrupt_in,
            interrupt_out,
            bulk_in,
            bulk_out,
        })
    }
}

fn infer_interface_endpoints<T: UsbContext>(
    handle: &rusb::DeviceHandle<T>,
    interface: u8,
) -> Result<InterfaceEndpoints> {
    let config = handle
        .device()
        .active_config_descriptor()
        .context("read active config descriptor")?;
    for intf in config.interfaces() {
        for desc in intf.descriptors() {
            if desc.interface_number() != interface {
                continue;
            }
            let mut builder = EndpointBuilder::default();
            for ep in desc.endpoint_descriptors() {
                builder.record(&ep);
            }
            if let Some(endpoints) = builder.finish() {
                return Ok(endpoints);
            }
        }
    }
    Err(anyhow!(
        "required endpoints not found for interface {}",
        interface
    ))
}

fn parse_hex_u16(s: &str) -> Result<u16, std::num::ParseIntError> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16)
}
