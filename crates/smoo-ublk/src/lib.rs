use crate::sys::{
    UBLK_CMD_ADD_DEV, UBLK_CMD_DEL_DEV, UBLK_CMD_SET_PARAMS, UBLK_PARAM_TYPE_BASIC,
    ublk_param_basic, ublk_params, ublksrv_ctrl_cmd, ublksrv_ctrl_dev_info,
};
use anyhow::Context;
use async_channel::{RecvError, Sender};
use io_uring::IoUring;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::ops::Div;
use std::os::fd::AsRawFd;
use std::thread::JoinHandle;
use tracing::{Level, error, info, trace};

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
    handle: JoinHandle<()>,
    sender: Sender<(u32, ublksrv_ctrl_cmd, Sender<Result<(), io::Error>>)>,
}

pub struct SmooUblkDevice {}

impl SmooUblk {
    pub fn new() -> anyhow::Result<Self> {
        let ublk_ctrl = File::options().write(true).open("/dev/ublk-control")?;
        let (sender, receiver) =
            async_channel::bounded::<(u32, ublksrv_ctrl_cmd, Sender<Result<(), io::Error>>)>(1);
        // Setup a simple ring + reactor that round trips one op at a time to /dev/ublk-control
        let mut ring: IoUring<io_uring::squeue::Entry128, _> =
            IoUring::<io_uring::squeue::Entry128>::builder().build(1)?;

        let span = tracing::span!(Level::INFO, "ublk-ctrl");
        let handle = std::thread::spawn(move || {
            let _enter = span.enter();
            info!("starting loop");
            loop {
                let (opcode, cmd, reply) = match receiver.recv_blocking() {
                    Ok(msg) => msg,
                    Err(RecvError) => {
                        info!("smoo-ublk ctrl loop shutting down");
                        break;
                    }
                };

                tracing::span!(Level::INFO, "ctrl cmd", opcode).in_scope(|| {
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

                    let sqe = io_uring::opcode::UringCmd80::new(
                        io_uring::types::Fd(ublk_ctrl.as_raw_fd()),
                        opcode,
                    )
                    .cmd(cmd_buf);
                    if let Err(e) = unsafe { ring.submission().push(&sqe.build()) } {
                        error!("write ublksrv_ctrl_cmd SQE failed: {}", e);
                        send_completion(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("push SQE failed: {e}"),
                        )));
                        return;
                    }

                    trace!("submitting sqe");
                    if let Err(e) = ring.submit_and_wait(1) {
                        error!("submit_and_wait failed: {}", e);
                        send_completion(Err(e));
                        return;
                    }

                    let Some(cqe) = ring.completion().next() else {
                        error!("missing completion entry from ctrl ring");
                        send_completion(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "missing completion entry",
                        )));
                        return;
                    };
                    let result = cqe.result();
                    trace!(result = result, "got cqe");
                    send_completion(if result == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::from_raw_os_error(-result))
                    });
                });
            }
        });

        Ok(Self { handle, sender })
    }

    pub async fn setup_device(
        &mut self,
        block_size: usize,
        block_count: usize,
        queue_count: u16,
        queue_depth: u16,
    ) -> anyhow::Result<SmooUblkDevice> {
        // the kernel only cares about 512 blocks
        let dev_sectors = block_count.div(512) as u64;

        // For now we use -1 as the dev_id, so that a fresh dev is created for us.
        // Once we support resuming this needs to change.
        let dev_id = u32::MAX;

        // ublksrv_ctrl_dev_info is passed in ublksrv_ctrl_dev_info during UBLK_CMD_ADD_DEV
        let mut info = ublksrv_ctrl_dev_info {
            dev_id,
            nr_hw_queues: queue_count,
            queue_depth,
            ..Default::default()
        };

        // ublk_params is passed in ublksrv_ctrl_dev_info during UBLK_CMD_SET_PARAMS
        let mut params = ublk_params {
            len: size_of::<ublk_params>() as _,
            types: UBLK_PARAM_TYPE_BASIC,
            basic: ublk_param_basic {
                logical_bs_shift: block_count.trailing_zeros() as _,
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
        cmd.len = size_of::<sys::ublksrv_ctrl_dev_info>() as _;
        cmd.addr = &raw mut info as _;
        let (sender, receiver) = async_channel::bounded::<Result<(), io::Error>>(1);
        // write the submission into the ring
        self.sender
            .send((UBLK_CMD_ADD_DEV, cmd, sender))
            .await
            .context("send sqe")?;
        // wait for the completion
        receiver
            .recv()
            .await
            .context("recv cqe")?
            .context("add dev")?;

        // Whilst completing our UBLK_CMD_ADD_DEV op, the kernel wrote our true dev_id into the
        // ublksrv_ctrl_dev_info struct.
        let dev_id = info.dev_id as u32;
        cmd.dev_id = dev_id;

        // Now we pass the ublk_params in a UBLK_CMD_SET_PARAMS to inform ublk of geometry/capacity.
        cmd.len = params.len as _;
        cmd.addr = &raw mut params as _;
        let (sender, receiver) = async_channel::bounded::<Result<(), io::Error>>(1);
        // write the submission into the ring
        self.sender
            .send((UBLK_CMD_SET_PARAMS, cmd, sender))
            .await
            .context("send sqe")?;
        // wait for the completion
        receiver
            .recv()
            .await
            .context("recv cqe")?
            .context("set ublk params")?;

        Ok(SmooUblkDevice {})
    }
}
