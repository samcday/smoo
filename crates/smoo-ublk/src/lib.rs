use crate::sys::{UBLK_CMD_ADD_DEV, ublksrv_ctrl_cmd};
use anyhow::Context;
use async_channel::{Receiver, Sender};
use io_uring::IoUring;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::thread::JoinHandle;
use tracing::{Level, info, trace, error};

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
    sender: Sender<(u32, ublksrv_ctrl_cmd, Sender<i32>)>,
}

pub struct SmooUblkDevice {}

impl SmooUblk {
    pub fn new() -> anyhow::Result<Self> {
        let ublk_ctrl = File::options().write(true).open("/dev/ublk-control")?;
        let (sender, receiver) = async_channel::bounded::<(u32, ublksrv_ctrl_cmd, Sender<i32>)>(1);
        // Setup a simple ring + reactor that round trips one op at a time to /dev/ublk-control
        let mut ring: IoUring<io_uring::squeue::Entry128, _> =
            IoUring::<io_uring::squeue::Entry128>::builder().build(1)?;

        let span = tracing::span!(Level::INFO, "ublk-ctrl");
        let handle = std::thread::spawn(move || {
            let _enter = span.enter();
            info!("starting loop");
            loop {
                let (opcode, cmd, reply) = receiver
                    .recv_blocking()
                    .context("recv ublksrv_ctrl_cmd")
                    .unwrap();

                tracing::span!(Level::INFO, "ctrl cmd", opcode).in_scope(|| {
                    let sqe = io_uring::opcode::UringCmd80::new(
                        io_uring::types::Fd(ublk_ctrl.as_raw_fd()),
                        opcode,
                    );
                    if let Err(e) = unsafe { ring.submission().push(&sqe.build()) }
                        .context("write ublksrv_ctrl_cmd SQE")
                    {
                        error!("{}", e);
                    }
                    println!("wut");

                    trace!("submitted sqe");
                    ring.submit_and_wait(1).unwrap();

                    let cqe = ring.completion().next().context("fetch cqe").unwrap();
                    trace!("received cqe: {}", cqe.result());
                    reply.send_blocking(cqe.result());
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
        let mut info = sys::ublksrv_ctrl_dev_info {
            nr_hw_queues: queue_count,
            queue_depth,
            ..Default::default()
        };
        let cmd = sys::ublksrv_ctrl_cmd {
            addr: &raw mut info as _,
            ..Default::default()
        };

        let (sender, receiver) = async_channel::bounded::<i32>(1);
        self.sender.send((sys::UBLK_CMD_ADD_DEV, cmd, sender)).await?;

        let result = receiver.recv().await?;
        println!("ok: {}", result);

        Ok(SmooUblkDevice {})
    }
}
