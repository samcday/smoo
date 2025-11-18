use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use smoo_gadget_core::{DmaHeap, FunctionfsEndpoints, GadgetConfig, SmooGadget};
use smoo_gadget_ublk::{SmooUblk, SmooUblkDevice, UblkBuffer, UblkIoRequest, UblkOp};
use smoo_proto::{Ident, OpCode, Request, Response};
use std::{
    fs::File,
    io,
    io::Write,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    path::PathBuf,
};
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::prelude::*;
use usb_gadget::{
    function::custom::{Custom, Endpoint, EndpointDirection, Interface, TransferType},
    Class, Config, Gadget, Id, RegGadget, Strings,
};

const SMOO_CLASS: u8 = 0xFF;
const SMOO_SUBCLASS: u8 = 0x53;
const SMOO_PROTOCOL: u8 = 0x4D;

#[derive(Debug, Parser)]
#[command(name = "smoo-gadget-cli")]
#[command(about = "Expose a smoo gadget backed by FunctionFS + ublk", long_about = None)]
struct Args {
    /// USB vendor ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xDEAD", value_parser = parse_hex_u16)]
    vendor_id: u16,
    /// USB product ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xBEEF", value_parser = parse_hex_u16)]
    product_id: u16,
    /// Number of ublk queues to configure.
    #[arg(long, default_value_t = 1)]
    queue_count: u16,
    /// Depth of each ublk queue.
    #[arg(long, default_value_t = 16)]
    queue_depth: u16,
    /// Logical block size presented to the kernel (bytes).
    #[arg(long, default_value_t = 512)]
    block_size: u32,
    /// Logical block count to expose.
    #[arg(long, value_name = "BLOCKS")]
    blocks: u64,
    /// Disable the DMA-BUF fast path even if the kernel advertises support.
    #[arg(long)]
    no_dma_buf: bool,
    /// DMA-HEAP to allocate from when DMA-BUF mode is enabled.
    #[arg(long, value_enum, default_value_t = DmaHeapSelection::System)]
    dma_heap: DmaHeapSelection,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DmaHeapSelection {
    System,
    Cma,
    Reserved,
}

impl From<DmaHeapSelection> for DmaHeap {
    fn from(value: DmaHeapSelection) -> Self {
        match value {
            DmaHeapSelection::System => DmaHeap::System,
            DmaHeapSelection::Cma => DmaHeap::Cma,
            DmaHeapSelection::Reserved => DmaHeap::Reserved,
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    ensure!(
        args.block_size.is_power_of_two(),
        "block size must be a power-of-two"
    );
    let block_count = usize::try_from(args.blocks).context("block count exceeds usize")?;

    usb_gadget::remove_all().context("remove existing USB gadgets")?;
    let (endpoints, _gadget_guard) = setup_functionfs(&args).context("setup FunctionFS")?;

    let mut ublk = SmooUblk::new().context("init ublk")?;
    let block_size = args.block_size as usize;
    let max_io_bytes = SmooUblk::max_io_bytes_hint(block_size, args.queue_depth)
        .context("compute max io bytes")?;
    let device = ublk
        .setup_device(block_size, block_count, args.queue_count, args.queue_depth)
        .await
        .context("setup ublk device")?;
    ensure!(
        device.max_io_bytes() == max_io_bytes,
        "device max io bytes changed during setup"
    );

    let ident = Ident::new(0, 1);
    let dma_heap = if args.no_dma_buf {
        None
    } else {
        Some(args.dma_heap.into())
    };
    let gadget_config = GadgetConfig::new(
        ident,
        args.queue_count,
        args.queue_depth,
        max_io_bytes,
        dma_heap,
    );
    let mut gadget = SmooGadget::new(endpoints, gadget_config).context("init smoo gadget core")?;
    enum SetupAwait {
        Configured,
        Interrupted,
    }
    let setup_outcome = {
        #[allow(unused_mut)]
        let mut setup_fut = gadget.setup();
        tokio::pin!(setup_fut);
        #[allow(unused_mut)]
        let mut setup_shutdown = signal::ctrl_c();
        tokio::pin!(setup_shutdown);
        tokio::select! {
            res = &mut setup_fut => {
                res.context("complete FunctionFS setup")?;
                SetupAwait::Configured
            }
            res = &mut setup_shutdown => {
                if let Err(err) = res {
                    warn!(error = ?err, "ctrl-c listener failed during FunctionFS setup");
                }
                SetupAwait::Interrupted
            }
        }
    };

    if matches!(setup_outcome, SetupAwait::Interrupted) {
        info!("shutdown requested before host completed ident exchange");
        ublk.stop_dev(device, true)
            .await
            .context("stop ublk device after interrupted setup")?;
        return Ok(());
    }
    info!(
        ident_major = ident.major,
        ident_minor = ident.minor,
        queues = args.queue_count,
        depth = args.queue_depth,
        "smoo gadget initialized"
    );

    run_event_loop(&mut ublk, device, gadget, args.block_size as usize).await
}

async fn run_event_loop(
    ublk: &mut SmooUblk,
    device: SmooUblkDevice,
    mut gadget: SmooGadget,
    block_size: usize,
) -> Result<()> {
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    let mut io_error = None;
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received");
                break;
            }
            req = device.next_io() => {
                let req = match req {
                    Ok(req) => req,
                    Err(err) => {
                        io_error = Some(err.context("receive ublk io"));
                        break;
                    }
                };
                if let Err(err) = handle_request(&mut gadget, &device, req, block_size).await {
                    io_error = Some(err);
                    break;
                }
            }
        }
    }

    info!("stopping ublk device");
    ublk.stop_dev(device, true)
        .await
        .context("stop ublk device")?;
    if let Some(err) = io_error {
        Err(err)
    } else {
        Ok(())
    }
}

async fn handle_request(
    gadget: &mut SmooGadget,
    device: &SmooUblkDevice,
    req: UblkIoRequest,
    block_size: usize,
) -> Result<()> {
    let req_len = match request_byte_len(&req, block_size) {
        Ok(len) => len,
        Err(err) => {
            let errno = errno_from_io(&err);
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                errno = errno,
                ?req.op,
                "invalid request length: {err}"
            );
            device
                .complete_io(req, -errno)
                .context("complete invalid request")?;
            return Ok(());
        }
    };

    let opcode = match opcode_from_ublk(req.op) {
        Some(op) => op,
        None => {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                op = ?req.op,
                "unsupported ublk opcode"
            );
            device
                .complete_io(req, -libc::EOPNOTSUPP)
                .context("complete unsupported opcode")?;
            return Ok(());
        }
    };

    let mut payload: Option<UblkBuffer<'_>> = None;
    let result = async {
        if matches!(opcode, OpCode::Read | OpCode::Write) && req_len > 0 {
            let capacity = device.buffer_len();
            if req_len > capacity {
                warn!(
                    queue = req.queue_id,
                    tag = req.tag,
                    req_bytes = req_len,
                    buf_cap = capacity,
                    "request exceeds buffer capacity"
                );
                device
                    .complete_io(req, -libc::EINVAL)
                    .context("complete oversized request")?;
                return Ok(());
            }
            payload = Some(
                device
                    .checkout_buffer(req.queue_id, req.tag)
                    .context("checkout bulk buffer")?,
            );
        }

        let byte_len = u32::try_from(req_len).context("request length exceeds protocol limit")?;
        let proto_req = Request::new(opcode, req.sector, byte_len, 0);
        gadget
            .send_request(proto_req)
            .await
            .context("send smoo request")?;

        if opcode == OpCode::Read && req_len > 0 {
            if let Some(buf) = payload.as_mut() {
                gadget
                    .read_bulk_buffer(&mut buf.as_mut_slice()[..req_len])
                    .await
                    .context("read bulk payload")?;
            }
        } else if opcode == OpCode::Write && req_len > 0 {
            if let Some(buf) = payload.as_mut() {
                gadget
                    .write_bulk_buffer(&mut buf.as_mut_slice()[..req_len])
                    .await
                    .context("write bulk payload")?;
            }
        }

        let response = gadget.read_response().await.context("read smoo response")?;

        let status = response_status(&response, req_len)?;
        if status >= 0 && status as usize != req_len {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                expected = req_len,
                reported = status,
                "response byte count mismatch"
            );
        }
        device
            .complete_io(req, status)
            .context("complete ublk request")?;
        Ok(())
    }
    .await;

    result
}

fn opcode_from_ublk(op: UblkOp) -> Option<OpCode> {
    match op {
        UblkOp::Read => Some(OpCode::Read),
        UblkOp::Write => Some(OpCode::Write),
        UblkOp::Flush => Some(OpCode::Flush),
        UblkOp::Discard => Some(OpCode::Discard),
        UblkOp::Unknown(_) => None,
    }
}

fn response_status(resp: &Response, expected_len: usize) -> Result<i32> {
    if resp.flags != 0 {
        let errno = i32::try_from(resp.flags).unwrap_or(libc::EIO);
        return Ok(-errno);
    }
    let len = resp.byte_len as usize;
    i32::try_from(len)
        .or_else(|_| i32::try_from(expected_len))
        .map_err(|_| anyhow!("response length exceeds i32"))
}

fn request_byte_len(req: &UblkIoRequest, block_size: usize) -> io::Result<usize> {
    let sectors = usize::try_from(req.num_sectors)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sector count overflow"))?;
    sectors
        .checked_mul(block_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request byte length overflow"))
}

fn errno_from_io(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or_else(|| match err.kind() {
        io::ErrorKind::Unsupported => libc::EOPNOTSUPP,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::UnexpectedEof => libc::EIO,
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        _ => libc::EIO,
    })
}

struct GadgetGuard {
    #[allow(dead_code)]
    custom: Custom,
    #[allow(dead_code)]
    registration: RegGadget,
}

fn setup_functionfs(args: &Args) -> Result<(FunctionfsEndpoints, GadgetGuard)> {
    let mut builder = Custom::builder().with_interface(
        Interface::new(Class::vendor_specific(SMOO_SUBCLASS, SMOO_PROTOCOL), "smoo")
            .with_endpoint(interrupt_in_ep())
            .with_endpoint(interrupt_out_ep())
            .with_endpoint(bulk_in_ep())
            .with_endpoint(bulk_out_ep()),
    );
    builder.ffs_no_init = true;
    let (ffs_descs, ffs_strings) = builder.ffs_descriptors_and_strings()?;
    let (mut custom, handle) = builder.build();

    let klass = Class::new(SMOO_CLASS, SMOO_SUBCLASS, SMOO_PROTOCOL);
    let id = Id::new(args.vendor_id, args.product_id);
    let strings = Strings::new("smoo", "smoo gadget", "0001");
    let udc = usb_gadget::default_udc().context("locate UDC")?;
    let gadget =
        Gadget::new(klass, id, strings).with_config(Config::new("config").with_function(handle));
    let reg = gadget.register().context("register gadget")?;

    let ffs_dir = custom.ffs_dir().context("resolve FunctionFS dir")?;
    let mut ep0 = File::options()
        .read(true)
        .write(true)
        .open(ffs_dir.join("ep0"))
        .context("open ep0")?;
    ep0.write_all(&ffs_descs).context("write descriptors")?;
    ep0.write_all(&ffs_strings).context("write strings")?;

    reg.bind(Some(&udc)).context("bind gadget to UDC")?;

    let interrupt_in = open_endpoint_fd(ffs_dir.join("ep1")).context("open interrupt IN")?;
    let interrupt_out = open_endpoint_fd(ffs_dir.join("ep2")).context("open interrupt OUT")?;
    let bulk_in = open_endpoint_fd(ffs_dir.join("ep3")).context("open bulk IN")?;
    let bulk_out = open_endpoint_fd(ffs_dir.join("ep4")).context("open bulk OUT")?;
    let endpoints = FunctionfsEndpoints::new(
        to_owned_fd(ep0),
        interrupt_in,
        interrupt_out,
        bulk_in,
        bulk_out,
    );

    Ok((
        endpoints,
        GadgetGuard {
            custom,
            registration: reg,
        },
    ))
}

fn interrupt_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Interrupt, 16)
}

fn interrupt_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Interrupt, 16)
}

fn bulk_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Bulk, 512)
}

fn bulk_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Bulk, 512)
}

fn make_ep(direction: EndpointDirection, ty: TransferType, packet_size: u16) -> Endpoint {
    let mut ep = match ty {
        TransferType::Bulk => Endpoint::bulk(direction),
        _ => Endpoint::custom(direction, ty),
    };
    ep.max_packet_size_hs = packet_size;
    ep.max_packet_size_ss = packet_size;
    ep
}

fn open_endpoint_fd(path: PathBuf) -> Result<OwnedFd> {
    let file = File::options()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    Ok(to_owned_fd(file))
}

fn to_owned_fd(file: File) -> OwnedFd {
    let raw = file.into_raw_fd();
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn parse_hex_u16(input: &str) -> Result<u16, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16).map_err(|err| err.to_string())
}
