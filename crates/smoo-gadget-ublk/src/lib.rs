use crate::sys::{
    UBLK_CMD_ADD_DEV, UBLK_CMD_DEL_DEV, UBLK_CMD_SET_PARAMS, UBLK_CMD_START_DEV, UBLK_CMD_STOP_DEV,
    UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE, UBLK_PARAM_TYPE_BASIC,
    UBLK_U_IO_COMMIT_AND_FETCH_REQ, UBLK_U_IO_FETCH_REQ, ublk_param_basic, ublk_params,
    ublksrv_ctrl_cmd, ublksrv_ctrl_dev_info, ublksrv_io_cmd, ublksrv_io_desc,
};
use anyhow::{Context, ensure};
use async_channel::{Receiver, RecvError, Sender};
use io_uring::{IoUring, cqueue, squeue, types};
use std::cmp;
use std::fs::File;
use std::io;
use std::mem::{size_of, transmute};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::ptr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{Level, debug, error, info, trace, warn};

mod sys {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(unsafe_op_in_unsafe_fn)]
    include!(concat!(env!("OUT_DIR"), "/ublk_cmd.rs"));
}

/// Top level interface to ublk. Creates SmooUblkDevices
pub struct SmooUblk {
    handle: Option<JoinHandle<()>>,
    sender: Sender<CtrlCommand>,
}

const CTRL_RING_DEPTH: u32 = 8;
type CtrlCommand = (
    u32,
    ublksrv_ctrl_cmd,
    Sender<Result<(), io::Error>>,
    Option<Duration>,
);

pub struct SmooUblkDevice {
    dev_id: u32,
    queue_count: u16,
    queue_depth: u16,
    block_size: usize,
    max_io_bytes: usize,
    data_file: Option<Arc<File>>,
    request_rx: Receiver<UblkIoRequest>,
    completion_txs: Vec<Sender<QueueCompletion>>,
    workers: Vec<QueueWorkerHandle>,
    start_handle: Option<JoinHandle<()>>,
    shutdown: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum UblkOp {
    Read,
    Write,
    Flush,
    Discard,
    Unknown(u32),
}

#[derive(Debug, Clone, Copy)]
pub struct UblkIoRequest {
    pub dev_id: u32,
    pub queue_id: u16,
    pub tag: u16,
    pub op: UblkOp,
    pub sector: u64,
    pub num_sectors: u32,
}

impl UblkIoRequest {
    pub fn byte_len(&self) -> u64 {
        (self.num_sectors as u64) << 9
    }
}

struct QueueWorkerHandle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

struct QueueCompletion {
    tag: u16,
    result: i32,
}

impl SmooUblk {
    pub fn new() -> anyhow::Result<Self> {
        let ublk_ctrl = File::options().write(true).open("/dev/ublk-control")?;
        let (sender, receiver) = async_channel::bounded::<CtrlCommand>(1);
        // Setup a simple ring + reactor that round trips one op at a time to /dev/ublk-control
        let mut ring: IoUring<io_uring::squeue::Entry128, _> =
            IoUring::<io_uring::squeue::Entry128>::builder().build(CTRL_RING_DEPTH)?;

        let span = tracing::span!(Level::INFO, "ublk-ctrl");
        let handle = std::thread::spawn(move || {
            let _enter = span.enter();
            info!("starting loop");
            let mut next_cmd_id: u64 = 1;
            loop {
                let (opcode, cmd, reply, timeout) = match receiver.recv_blocking() {
                    Ok(msg) => msg,
                    Err(RecvError) => {
                        info!("smoo-gadget-ublk ctrl loop shutting down");
                        break;
                    }
                };

                tracing::span!(Level::DEBUG, "ctrl cmd", opcode).in_scope(|| {
                    let send_completion = |res| {
                        if let Err(e) = reply.send_blocking(res) {
                            trace!("ctrl reply receiver dropped: {}", e);
                        }
                    };

                    let cmd_bytes_len = size_of::<sys::ublksrv_ctrl_cmd>();
                    assert!(cmd_bytes_len <= 80, "ublksrv_ctrl_cmd larger than 80 bytes");
                    let mut cmd_buf = [0u8; 80];
                    let raw_cmd = unsafe {
                        std::slice::from_raw_parts(
                            (&cmd as *const sys::ublksrv_ctrl_cmd).cast::<u8>(),
                            cmd_bytes_len,
                        )
                    };
                    cmd_buf[..cmd_bytes_len].copy_from_slice(raw_cmd);

                    let cmd_user_data = next_cmd_id << 2;
                    let timeout_user_data = cmd_user_data | 1;
                    let cancel_user_data = cmd_user_data | 2;
                    next_cmd_id = next_cmd_id.wrapping_add(1);

                    let mut cmd_entry = io_uring::opcode::UringCmd80::new(
                        io_uring::types::Fd(ublk_ctrl.as_raw_fd()),
                        opcode,
                    )
                    .cmd(cmd_buf)
                    .build()
                    .user_data(cmd_user_data);

                    if timeout.is_some() {
                        cmd_entry = cmd_entry.flags(squeue::Flags::IO_LINK);
                    }

                    if let Err(e) = push_ctrl_entry(&mut ring, &cmd_entry) {
                        error!("write ublksrv_ctrl_cmd SQE failed: {}", e);
                        send_completion(Err(e));
                        return;
                    }

                    let timeout_spec = timeout.map(types::Timespec::from);
                    if let Some(ref ts) = timeout_spec {
                        let timeout_entry = squeue::Entry128::from(
                            io_uring::opcode::LinkTimeout::new(ts)
                                .build()
                                .user_data(timeout_user_data),
                        );
                        if let Err(e) = push_ctrl_entry(&mut ring, &timeout_entry) {
                            error!("link timeout SQE failed: {}", e);
                            send_completion(Err(e));
                            return;
                        }
                    }

                    if let Err(e) = ring.submitter().submit() {
                        error!("submit ctrl SQE failed: {}", e);
                        send_completion(Err(e));
                        return;
                    }

                    trace!("submitting sqe");
                    let mut completion: Option<Result<i32, io::Error>> = None;
                    while completion.is_none() {
                        if let Err(e) = ring.submitter().submit_and_wait(1) {
                            error!("submit_and_wait failed: {}", e);
                            completion = Some(Err(e));
                            break;
                        }
                        let mut timeout_triggered = None;
                        while let Some(cqe) = ring.completion().next() {
                            let user_data = cqe.user_data();
                            if user_data == cmd_user_data {
                                completion = Some(Ok(cqe.result()));
                                break;
                            } else if timeout.is_some() && user_data == timeout_user_data {
                                timeout_triggered = Some(cqe.result());
                                break;
                            } else if timeout.is_some() && user_data == cancel_user_data {
                                trace!(res = cqe.result(), "ctrl cancel completion");
                            } else {
                                trace!(
                                    user_data = user_data,
                                    res = cqe.result(),
                                    "ctrl extra completion"
                                );
                            }
                        }
                        if let Some(res) = timeout_triggered {
                            trace!(res = res, "ctrl timeout completion");
                            if let Err(err) =
                                submit_ctrl_cancel(&mut ring, cmd_user_data, cancel_user_data)
                            {
                                warn!("ctrl cancel submit failed: {}", err);
                            }
                            completion = Some(Err(io::Error::from_raw_os_error(libc::ETIME)));
                        }
                    }

                    while let Some(cqe) = ring.completion().next() {
                        trace!(
                            user_data = cqe.user_data(),
                            res = cqe.result(),
                            "drain ctrl cqe"
                        );
                    }

                    let completion = completion.unwrap_or_else(|| {
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            "ctrl completion missing result",
                        ))
                    });
                    let completion_code = match &completion {
                        Ok(res) => *res,
                        Err(err) => -err.raw_os_error().unwrap_or(libc::EIO),
                    };
                    trace!(result = completion_code, "ctrl completion");
                    let final_result = match completion {
                        Ok(0) => Ok(()),
                        Ok(res) => Err(io::Error::from_raw_os_error(-res)),
                        Err(err) => Err(err),
                    };
                    send_completion(final_result);
                });
            }
        });

        Ok(Self {
            handle: Some(handle),
            sender,
        })
    }

    pub async fn setup_device(
        &mut self,
        block_size: usize,
        block_count: usize,
        queue_count: u16,
        queue_depth: u16,
    ) -> anyhow::Result<SmooUblkDevice> {
        debug!(
            block_size = block_size,
            block_count = block_count,
            queue_count = queue_count,
            queue_depth = queue_depth,
            "setup_device requested"
        );
        ensure!(block_size != 0, "block size must be non-zero");
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        let logical_shift = block_size.trailing_zeros() as u8;
        ensure!(
            logical_shift >= 9,
            "logical block size must be at least 512 bytes"
        );

        let total_bytes = block_count
            .checked_mul(block_size)
            .context("device capacity overflow")?;
        ensure!(
            total_bytes % 512 == 0,
            "device capacity must be divisible by 512"
        );
        let dev_sectors = (total_bytes / 512) as u64;
        let queue_depth_bytes = block_size
            .checked_mul(queue_depth as usize)
            .unwrap_or(usize::MAX);
        let desired_buf_bytes = cmp::max(block_size, queue_depth_bytes);
        let max_io_buf_bytes = cmp::min(desired_buf_bytes, u32::MAX as usize) as u32;
        let max_io_bytes = max_io_buf_bytes as usize;

        // For now we use -1 as the dev_id, so that a fresh dev is created for us.
        // Once we support resuming this needs to change.
        let dev_id = u32::MAX;

        // ublksrv_ctrl_dev_info is passed in ublksrv_ctrl_dev_info during UBLK_CMD_ADD_DEV
        let mut info = ublksrv_ctrl_dev_info {
            dev_id,
            nr_hw_queues: queue_count,
            queue_depth,
            max_io_buf_bytes,
            ublksrv_pid: unsafe { libc::getpid() } as i32,
            ..Default::default()
        };
        info.flags |= sys::UBLK_F_USER_COPY as u64;

        // ublk_params is passed in ublksrv_ctrl_dev_info during UBLK_CMD_SET_PARAMS
        let mut params = ublk_params {
            len: size_of::<ublk_params>() as u32,
            types: UBLK_PARAM_TYPE_BASIC,
            basic: ublk_param_basic {
                logical_bs_shift: logical_shift,
                physical_bs_shift: logical_shift,
                io_opt_shift: logical_shift,
                io_min_shift: logical_shift,
                max_sectors: cmp::max(info.max_io_buf_bytes >> 9, 1),
                dev_sectors,
                ..Default::default()
            },
            ..Default::default()
        };

        // the ublksrv_ctrl_cmd descriptor is passed in for all UBLK_CMD_* requests.
        let mut cmd = ublksrv_ctrl_cmd {
            dev_id,
            // queue is -1 for all UBLK_CMD_* requests
            queue_id: u16::MAX,
            ..Default::default()
        };

        // We begin the process by sending ublksrv_ctrl_dev_info along in a UBLK_CMD_ADD_DEV op
        cmd.len = ctrl_cmd_len::<sys::ublksrv_ctrl_dev_info>();
        cmd.addr = &raw mut info as _;
        submit_ctrl_command(&self.sender, UBLK_CMD_ADD_DEV, cmd, "add device", None).await?;
        debug!(dev_id = info.dev_id, "add_dev completed");

        // Whilst completing our UBLK_CMD_ADD_DEV op, the kernel wrote our true dev_id into the
        // ublksrv_ctrl_dev_info struct.
        let dev_id = info.dev_id as u32;
        cmd.dev_id = dev_id;

        // Now we pass the ublk_params in a UBLK_CMD_SET_PARAMS to inform ublk of geometry/capacity.
        cmd.len = params.len as _;
        cmd.addr = &raw mut params as _;
        submit_ctrl_command(&self.sender, UBLK_CMD_SET_PARAMS, cmd, "set params", None).await?;

        let ioctl_encode = (info.flags & (sys::UBLK_F_CMD_IOCTL_ENCODE as u64)) != 0;
        let user_copy = (info.flags & (sys::UBLK_F_USER_COPY as u64)) != 0;
        let cdev_path = format!("/dev/ublkc{}", dev_id);
        let base_cdev = File::options()
            .read(true)
            .write(true)
            .open(&cdev_path)
            .with_context(|| format!("open {}", cdev_path))?;
        let data_file = if user_copy {
            Some(Arc::new(
                base_cdev.try_clone().context("clone cdev for data plane")?,
            ))
        } else {
            None
        };
        let (request_tx, request_rx) = async_channel::unbounded::<UblkIoRequest>();
        let mut completion_txs = Vec::with_capacity(queue_count as usize);
        let mut workers = Vec::with_capacity(queue_count as usize);
        let mut ready_rxs = Vec::with_capacity(queue_count as usize);

        for queue_id in 0..queue_count {
            let (complete_tx, complete_rx) = async_channel::unbounded::<QueueCompletion>();
            let stop = Arc::new(AtomicBool::new(false));
            let (ready_tx, ready_rx) = mpsc::channel();
            let cdev = base_cdev
                .try_clone()
                .with_context(|| format!("clone {}", cdev_path))?;
            let worker_cfg = QueueWorkerConfig {
                dev_id,
                queue_id,
                queue_depth,
                ioctl_encode,
                user_copy,
                request_tx: request_tx.clone(),
                completion_rx: complete_rx,
                stop: stop.clone(),
                cdev,
                ready_tx,
            };
            debug!(queue_id = queue_id, "spawning queue worker");
            let thread = spawn_queue_worker(worker_cfg)?;
            completion_txs.push(complete_tx);
            workers.push(QueueWorkerHandle { stop, thread });
            ready_rxs.push(ready_rx);
        }

        for (queue_idx, ready_rx) in ready_rxs.into_iter().enumerate() {
            ready_rx.recv().context("queue worker init failed")?;
            debug!(
                queue_ready = true,
                queue_id = queue_idx,
                "queue worker ready"
            );
        }

        let device = SmooUblkDevice {
            dev_id,
            queue_count,
            queue_depth,
            block_size,
            max_io_bytes,
            data_file,
            request_rx,
            completion_txs,
            workers,
            start_handle: None,
            shutdown: false,
        };

        cmd.len = 0;
        cmd.addr = 0;
        cmd.data[0] = unsafe { libc::getpid() } as u64;
        let ctrl_sender = self.sender.clone();
        let start_cmd = cmd;
        let start_thread = std::thread::Builder::new()
            .name(format!("smoo-gadget-ublk-start-{}", dev_id))
            .spawn(move || {
                info!(dev_id = dev_id, "start_dev thread begin");
                let res = submit_ctrl_command_blocking(
                    &ctrl_sender,
                    UBLK_CMD_START_DEV,
                    start_cmd,
                    "start device",
                );
                match res {
                    Ok(()) => info!(dev_id = dev_id, "start_dev completed"),
                    Err(err) => error!(dev_id = dev_id, "start_dev failed: {:?}", err),
                }
            })
            .context("spawn start_dev thread")?;

        let mut device = device;
        device.start_handle = Some(start_thread);
        Ok(device)
    }

    /// Gracefully stop a running device and optionally delete the control node.
    ///
    /// All queue workers and io_uring resources are torn down before
    /// sending `UBLK_CMD_STOP_DEV`, matching the kernel contract documented in
    /// `Documentation/block/ublk.rst`. When `delete_ctrl` is true, a follow-up
    /// `UBLK_CMD_DEL_DEV` removes the control character device so `/dev/ublkc*`
    /// disappears as well.
    pub async fn stop_dev(
        &mut self,
        mut device: SmooUblkDevice,
        delete_ctrl: bool,
    ) -> anyhow::Result<()> {
        let dev_id = device.dev_id();
        device.shutdown();
        drop(device);

        let cmd = ublksrv_ctrl_cmd {
            dev_id,
            queue_id: u16::MAX,
            ..Default::default()
        };
        submit_ctrl_command(&self.sender, UBLK_CMD_STOP_DEV, cmd, "stop device", None).await?;

        if delete_ctrl {
            let del_cmd = ublksrv_ctrl_cmd {
                dev_id,
                queue_id: u16::MAX,
                ..Default::default()
            };
            submit_ctrl_command(
                &self.sender,
                UBLK_CMD_DEL_DEV,
                del_cmd,
                "delete device",
                None,
            )
            .await?;
        }

        Ok(())
    }
}

impl Drop for SmooUblk {
    fn drop(&mut self) {
        self.sender.close();
        if let Some(handle) = self.handle.take() {
            if let Err(err) = handle.join() {
                warn!("smoo-gadget-ublk ctrl loop panicked: {:?}", err);
            }
        }
    }
}

impl SmooUblkDevice {
    pub fn dev_id(&self) -> u32 {
        self.dev_id
    }

    pub fn queue_count(&self) -> u16 {
        self.queue_count
    }

    pub fn queue_depth(&self) -> u16 {
        self.queue_depth
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn max_io_bytes(&self) -> usize {
        self.max_io_bytes
    }

    pub fn copy_from_kernel(&self, queue_id: u16, tag: u16, buf: &mut [u8]) -> io::Result<()> {
        let file = self
            .data_file
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "user copy disabled"))?;
        let offset = self.user_copy_offset(queue_id, tag, 0)?;
        read_exact_at(file, buf, offset)
    }

    pub fn copy_to_kernel(&self, queue_id: u16, tag: u16, buf: &[u8]) -> io::Result<()> {
        let file = self
            .data_file
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "user copy disabled"))?;
        let offset = self.user_copy_offset(queue_id, tag, 0)?;
        write_all_at(file, buf, offset)
    }

    pub async fn next_io(&self) -> anyhow::Result<UblkIoRequest> {
        let req = self
            .request_rx
            .recv()
            .await
            .context("smoo-gadget-ublk device channel closed")?;
        trace!(
            dev_id = req.dev_id,
            queue_id = req.queue_id,
            tag = req.tag,
            op = ?req.op,
            sector = req.sector,
            num_sectors = req.num_sectors,
            "next_io"
        );
        Ok(req)
    }

    pub fn complete_io(&self, request: UblkIoRequest, result: i32) -> anyhow::Result<()> {
        let sender = self
            .completion_txs
            .get(request.queue_id as usize)
            .context("invalid queue id")?;

        trace!(
            dev_id = request.dev_id,
            queue_id = request.queue_id,
            tag = request.tag,
            result = result,
            "complete_io enqueue"
        );
        sender
            .send_blocking(QueueCompletion {
                tag: request.tag,
                result,
            })
            .context("complete queue command")
    }

    fn user_copy_offset(&self, queue_id: u16, tag: u16, buf_offset: usize) -> io::Result<u64> {
        if queue_id as u32 >= self.queue_count as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "queue id out of range",
            ));
        }
        if tag as u32 >= self.queue_depth as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tag out of range",
            ));
        }
        let base = sys::UBLKSRV_IO_BUF_OFFSET as u64;
        let queue_bits = (queue_id as u64) << sys::UBLK_QID_OFF;
        let tag_bits = (tag as u64) << sys::UBLK_TAG_OFF;
        base.checked_add(queue_bits)
            .and_then(|v| v.checked_add(tag_bits))
            .and_then(|v| v.checked_add(buf_offset as u64))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "buffer offset overflow"))
    }

    fn shutdown(&mut self) {
        if self.shutdown {
            return;
        }
        self.shutdown = true;
        for worker in &self.workers {
            worker.stop.store(true, Ordering::SeqCst);
        }
        for sender in &self.completion_txs {
            sender.close();
        }
        for worker in self.workers.drain(..) {
            if let Err(e) = worker.thread.join() {
                error!("queue worker join failed: {:?}", e);
            }
        }
        if let Some(handle) = self.start_handle.take() {
            if let Err(err) = handle.join() {
                error!("start_dev thread join failed: {:?}", err);
            }
        }
    }
}

impl Drop for SmooUblkDevice {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct QueueWorkerConfig {
    dev_id: u32,
    queue_id: u16,
    queue_depth: u16,
    ioctl_encode: bool,
    user_copy: bool,
    request_tx: Sender<UblkIoRequest>,
    completion_rx: Receiver<QueueCompletion>,
    stop: Arc<AtomicBool>,
    cdev: File,
    ready_tx: mpsc::Sender<()>,
}

struct CmdBuf {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Drop for CmdBuf {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

fn spawn_queue_worker(cfg: QueueWorkerConfig) -> anyhow::Result<JoinHandle<()>> {
    let name = format!("smoo-gadget-ublk-q{}", cfg.queue_id);
    let thread = std::thread::Builder::new().name(name).spawn(move || {
        if let Err(err) = queue_worker_main(cfg) {
            error!("queue worker exited: {:?}", err);
        }
    })?;
    Ok(thread)
}

fn queue_worker_main(cfg: QueueWorkerConfig) -> anyhow::Result<()> {
    let QueueWorkerConfig {
        dev_id,
        queue_id,
        queue_depth,
        ioctl_encode,
        user_copy,
        request_tx,
        completion_rx,
        stop,
        cdev,
        ready_tx,
    } = cfg;

    debug!(
        dev_id = dev_id,
        queue_id = queue_id,
        queue_depth = queue_depth,
        "queue worker starting"
    );
    let mut ring = IoUring::<io_uring::squeue::Entry, io_uring::cqueue::Entry>::builder()
        .setup_cqsize(queue_depth as u32)
        .setup_coop_taskrun()
        .build(queue_depth as u32)?;

    let cmd_buf_sz = queue_cmd_buf_size(queue_depth as u32);
    let max_cmd_buf_sz = queue_cmd_buf_size(sys::UBLK_MAX_QUEUE_DEPTH);
    let offset = sys::UBLKSRV_CMD_BUF_OFFSET as libc::off_t
        + (queue_id as libc::off_t) * max_cmd_buf_sz as libc::off_t;
    let raw_cmd_buf = unsafe {
        libc::mmap(
            ptr::null_mut(),
            cmd_buf_sz,
            libc::PROT_READ,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            cdev.as_raw_fd(),
            offset,
        )
    };
    let raw_cmd_buf = if raw_cmd_buf == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(raw_cmd_buf)
    }
    .context("map command buffer")?;
    let cmd_buf = CmdBuf {
        ptr: raw_cmd_buf,
        len: cmd_buf_sz,
    };
    let iod_base = cmd_buf.ptr as *mut ublksrv_io_desc;
    let fd = cdev.as_raw_fd();

    for tag in 0..queue_depth {
        let desc_ptr = unsafe { iod_base.add(tag as usize) };
        let cmd_addr = if user_copy { 0 } else { desc_ptr as u64 };
        trace!(
            dev_id = dev_id,
            queue_id = queue_id,
            tag = tag,
            "posting initial UBLK_IO_FETCH_REQ"
        );
        queue_cmd(
            QueueCmdCtx {
                ring: &mut ring,
                fd,
                ioctl_encode,
            },
            queue_id,
            tag,
            cmd_addr,
            UBLK_U_IO_FETCH_REQ,
            -1,
        )?;
    }
    ring.submitter().submit()?;
    debug!(
        dev_id = dev_id,
        queue_id = queue_id,
        "queue worker initial fetch submitted"
    );
    let _ = ready_tx.send(());
    debug!(
        dev_id = dev_id,
        queue_id = queue_id,
        "queue worker ready signal sent"
    );

    let timeout = types::Timespec::from(Duration::from_millis(5));
    let submit_args = types::SubmitArgs::new().timespec(&timeout);

    while !stop.load(Ordering::SeqCst) {
        while let Ok(comp) = completion_rx.try_recv() {
            let desc_ptr = unsafe { iod_base.add(comp.tag as usize) };
            let cmd_addr = if user_copy { 0 } else { desc_ptr as u64 };
            trace!(
                dev_id = dev_id,
                queue_id = queue_id,
                tag = comp.tag,
                result = comp.result,
                "issuing COMMIT_AND_FETCH"
            );
            queue_cmd(
                QueueCmdCtx {
                    ring: &mut ring,
                    fd,
                    ioctl_encode,
                },
                queue_id,
                comp.tag,
                cmd_addr,
                UBLK_U_IO_COMMIT_AND_FETCH_REQ,
                comp.result,
            )?;
        }

        match ring.submitter().submit_with_args(1, &submit_args) {
            Ok(_) => {}
            Err(err) => {
                if matches!(err.raw_os_error(), Some(x) if x == libc::ETIME) {
                    continue;
                }
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
        }

        while let Some(cqe) = ring.completion().next() {
            let result = cqe.result();
            if result < 0 {
                warn!(
                    dev = dev_id,
                    queue = queue_id,
                    "queue cqe error: {}",
                    result
                );
                return Err(io::Error::from_raw_os_error(-result).into());
            }
            let tag = cqe.user_data() as u16;
            let desc = unsafe { ptr::read(iod_base.add(tag as usize)) };
            let request = UblkIoRequest {
                dev_id,
                queue_id,
                tag,
                op: decode_op(desc.op_flags),
                sector: desc.start_sector,
                num_sectors: desc.nr_sectors,
            };
            trace!(
                dev_id = dev_id,
                queue_id = queue_id,
                tag = tag,
                op = ?request.op,
                sector = request.sector,
                num_sectors = request.num_sectors,
                "queue received io"
            );
            if request_tx.send_blocking(request).is_err() {
                debug!(
                    dev_id = dev_id,
                    queue_id = queue_id,
                    "request channel closed, terminating queue worker"
                );
                return Ok(());
            }
        }
    }

    Ok(())
}

struct QueueCmdCtx<'ring> {
    ring: &'ring mut IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry>,
    fd: i32,
    ioctl_encode: bool,
}

fn queue_cmd(
    ctx: QueueCmdCtx<'_>,
    queue_id: u16,
    tag: u16,
    desc_addr: u64,
    opcode: u32,
    result: i32,
) -> io::Result<()> {
    let QueueCmdCtx {
        ring,
        fd,
        ioctl_encode,
    } = ctx;
    let io_cmd = ublksrv_io_cmd {
        q_id: queue_id,
        tag,
        result,
        addr: desc_addr,
    };
    trace!(
        queue_id = queue_id,
        tag = tag,
        opcode = opcode,
        result = result,
        desc_addr = desc_addr,
        "submitting uring cmd"
    );
    let cmd_bytes: [u8; 16] = unsafe { transmute(io_cmd) };
    let sqe = io_uring::opcode::UringCmd16::new(types::Fd(fd), encode_cmd_op(opcode, ioctl_encode))
        .cmd(cmd_bytes)
        .build()
        .user_data(tag as u64);

    loop {
        match unsafe { ring.submission().push(&sqe) } {
            Ok(_) => break,
            Err(_) => {
                ring.submitter().submit()?;
            }
        }
    }

    Ok(())
}

fn push_ctrl_entry(
    ring: &mut IoUring<io_uring::squeue::Entry128, cqueue::Entry>,
    entry: &io_uring::squeue::Entry128,
) -> io::Result<()> {
    loop {
        match unsafe { ring.submission().push(entry) } {
            Ok(_) => return Ok(()),
            Err(_) => {
                let _ = ring.submitter().submit()?;
            }
        }
    }
}

fn submit_ctrl_cancel(
    ring: &mut IoUring<io_uring::squeue::Entry128, cqueue::Entry>,
    target_user_data: u64,
    cancel_user_data: u64,
) -> io::Result<()> {
    let cancel_entry = squeue::Entry128::from(
        io_uring::opcode::AsyncCancel::new(target_user_data)
            .build()
            .user_data(cancel_user_data),
    );
    push_ctrl_entry(ring, &cancel_entry)?;
    ring.submitter().submit()?;
    Ok(())
}

fn ctrl_cmd_len<T>() -> u16 {
    u16::try_from(size_of::<T>()).expect("control struct larger than u16")
}

fn queue_cmd_buf_size(depth: u32) -> usize {
    let desc_bytes = depth as usize * size_of::<ublksrv_io_desc>();
    let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    if desc_bytes == 0 {
        return page_sz;
    }
    desc_bytes.div_ceil(page_sz) * page_sz
}

fn encode_cmd_op(cmd: u32, ioctl_encode: bool) -> u32 {
    if ioctl_encode { cmd } else { cmd & 0xff }
}

fn decode_op(op_flags: u32) -> UblkOp {
    match op_flags & 0xff {
        UBLK_IO_OP_READ => UblkOp::Read,
        UBLK_IO_OP_WRITE => UblkOp::Write,
        UBLK_IO_OP_FLUSH => UblkOp::Flush,
        UBLK_IO_OP_DISCARD => UblkOp::Discard,
        other => UblkOp::Unknown(other),
    }
}

fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let read = file.read_at(buf, offset)?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
        }
        buf = &mut buf[read..];
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
    }
    Ok(())
}

fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let written = file.write_at(buf, offset)?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        buf = &buf[written..];
        offset = offset
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
    }
    Ok(())
}

async fn submit_ctrl_command(
    sender: &Sender<CtrlCommand>,
    opcode: u32,
    cmd: ublksrv_ctrl_cmd,
    label: &'static str,
    timeout: Option<Duration>,
) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = async_channel::bounded::<Result<(), io::Error>>(1);
    debug!(
        opcode = opcode,
        dev_id = cmd.dev_id,
        queue_id = cmd.queue_id,
        len = cmd.len,
        addr = cmd.addr,
        timeout_ms = timeout.map(|t| t.as_millis() as u64),
        "{label} submitting"
    );
    sender
        .send((opcode, cmd, reply_tx, timeout))
        .await
        .context("send ctrl command")?;
    let res = reply_rx
        .recv()
        .await
        .context("ctrl loop closed")?
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{label} failed"));
    match &res {
        Ok(_) => debug!(opcode = opcode, "{label} succeeded"),
        Err(err) => debug!(opcode = opcode, error = ?err, "{label} failed"),
    }
    res?;
    Ok(())
}

fn submit_ctrl_command_blocking(
    sender: &Sender<CtrlCommand>,
    opcode: u32,
    cmd: ublksrv_ctrl_cmd,
    label: &'static str,
) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = async_channel::bounded::<Result<(), io::Error>>(1);
    sender
        .send_blocking((opcode, cmd, reply_tx, None))
        .context("send ctrl command blocking")?;
    reply_rx
        .recv_blocking()
        .context("ctrl loop closed")?
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{label} failed"))?;
    Ok(())
}
