#![allow(non_camel_case_types)]

use std::mem::{align_of, offset_of, size_of};

pub const UBLK_CMD_GET_DEV_INFO: u32 = 0x02;
pub const UBLK_CMD_ADD_DEV: u32 = 0x04;
pub const UBLK_CMD_DEL_DEV: u32 = 0x05;
pub const UBLK_CMD_START_DEV: u32 = 0x06;
pub const UBLK_CMD_STOP_DEV: u32 = 0x07;
pub const UBLK_CMD_SET_PARAMS: u32 = 0x08;
pub const UBLK_CMD_GET_PARAMS: u32 = 0x09;
pub const UBLK_CMD_START_USER_RECOVERY: u32 = 0x10;
pub const UBLK_CMD_END_USER_RECOVERY: u32 = 0x11;
pub const UBLK_CMD_GET_DEV_INFO2: u32 = 0x12;
pub const UBLK_CMD_QUIESCE_DEV: u32 = 0x16;

const UBLK_IO_FETCH_REQ: u32 = 0x20;
const UBLK_IO_COMMIT_AND_FETCH_REQ: u32 = 0x21;

pub const UBLK_IO_RES_ABORT: i32 = -libc::ENODEV;

pub const UBLKSRV_CMD_BUF_OFFSET: u32 = 0;
pub const UBLK_MAX_QUEUE_DEPTH: u32 = 4096;

pub const UBLK_F_USER_RECOVERY: u64 = 1 << 3;
pub const UBLK_F_USER_RECOVERY_REISSUE: u64 = 1 << 4;
pub const UBLK_F_CMD_IOCTL_ENCODE: u64 = 1 << 6;
pub const UBLK_F_QUIESCE: u64 = 1 << 12;

pub const UBLK_IO_OP_READ: u32 = 0;
pub const UBLK_IO_OP_WRITE: u32 = 1;
pub const UBLK_IO_OP_FLUSH: u32 = 2;
pub const UBLK_IO_OP_DISCARD: u32 = 3;

pub const UBLK_PARAM_TYPE_BASIC: u32 = 1 << 0;

pub const UBLK_U_CMD_QUIESCE_DEV: u32 = iowr::<ublksrv_ctrl_cmd>(UBLK_CMD_QUIESCE_DEV);
pub const UBLK_U_IO_FETCH_REQ: u32 = iowr::<ublksrv_io_cmd>(UBLK_IO_FETCH_REQ);
pub const UBLK_U_IO_COMMIT_AND_FETCH_REQ: u32 =
    iowr::<ublksrv_io_cmd>(UBLK_IO_COMMIT_AND_FETCH_REQ);

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (ty << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

const fn iowr<T>(nr: u32) -> u32 {
    ioc(IOC_READ | IOC_WRITE, b'u' as u32, nr, size_of::<T>() as u32)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublksrv_ctrl_cmd {
    pub dev_id: u32,
    pub queue_id: u16,
    pub len: u16,
    pub addr: u64,
    pub data: [u64; 1],
    pub dev_path_len: u16,
    pub pad: u16,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublksrv_ctrl_dev_info {
    pub nr_hw_queues: u16,
    pub queue_depth: u16,
    pub state: u16,
    pub pad0: u16,
    pub max_io_buf_bytes: u32,
    pub dev_id: u32,
    pub ublksrv_pid: i32,
    pub pad1: u32,
    pub flags: u64,
    pub ublksrv_flags: u64,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub reserved1: u64,
    pub reserved2: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublksrv_io_desc {
    pub op_flags: u32,
    pub nr_sectors: u32,
    pub start_sector: u64,
    pub addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublksrv_io_cmd {
    pub q_id: u16,
    pub tag: u16,
    pub result: i32,
    pub addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublk_param_basic {
    pub attrs: u32,
    pub logical_bs_shift: u8,
    pub physical_bs_shift: u8,
    pub io_opt_shift: u8,
    pub io_min_shift: u8,
    pub max_sectors: u32,
    pub chunk_sectors: u32,
    pub dev_sectors: u64,
    pub virt_boundary_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublk_param_discard {
    pub discard_alignment: u32,
    pub discard_granularity: u32,
    pub max_discard_sectors: u32,
    pub max_write_zeroes_sectors: u32,
    pub max_discard_segments: u16,
    pub reserved0: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublk_param_devt {
    pub char_major: u32,
    pub char_minor: u32,
    pub disk_major: u32,
    pub disk_minor: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublk_param_zoned {
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub max_zone_append_sectors: u32,
    pub reserved: [u8; 20],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublk_param_dma_align {
    pub alignment: u32,
    pub pad: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublk_param_segment {
    pub seg_boundary_mask: u64,
    pub max_segment_size: u32,
    pub max_segments: u16,
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ublk_params {
    pub len: u32,
    pub types: u32,
    pub basic: ublk_param_basic,
    pub discard: ublk_param_discard,
    pub devt: ublk_param_devt,
    pub zoned: ublk_param_zoned,
    pub dma: ublk_param_dma_align,
    pub seg: ublk_param_segment,
}

const _: () = {
    assert!(size_of::<ublksrv_ctrl_cmd>() == 32);
    assert!(align_of::<ublksrv_ctrl_cmd>() == 8);
    assert!(offset_of!(ublksrv_ctrl_cmd, dev_id) == 0);
    assert!(offset_of!(ublksrv_ctrl_cmd, queue_id) == 4);
    assert!(offset_of!(ublksrv_ctrl_cmd, len) == 6);
    assert!(offset_of!(ublksrv_ctrl_cmd, addr) == 8);
    assert!(offset_of!(ublksrv_ctrl_cmd, data) == 16);
    assert!(offset_of!(ublksrv_ctrl_cmd, dev_path_len) == 24);
    assert!(offset_of!(ublksrv_ctrl_cmd, pad) == 26);
    assert!(offset_of!(ublksrv_ctrl_cmd, reserved) == 28);

    assert!(size_of::<ublksrv_ctrl_dev_info>() == 64);
    assert!(align_of::<ublksrv_ctrl_dev_info>() == 8);
    assert!(offset_of!(ublksrv_ctrl_dev_info, nr_hw_queues) == 0);
    assert!(offset_of!(ublksrv_ctrl_dev_info, queue_depth) == 2);
    assert!(offset_of!(ublksrv_ctrl_dev_info, state) == 4);
    assert!(offset_of!(ublksrv_ctrl_dev_info, pad0) == 6);
    assert!(offset_of!(ublksrv_ctrl_dev_info, max_io_buf_bytes) == 8);
    assert!(offset_of!(ublksrv_ctrl_dev_info, dev_id) == 12);
    assert!(offset_of!(ublksrv_ctrl_dev_info, ublksrv_pid) == 16);
    assert!(offset_of!(ublksrv_ctrl_dev_info, pad1) == 20);
    assert!(offset_of!(ublksrv_ctrl_dev_info, flags) == 24);
    assert!(offset_of!(ublksrv_ctrl_dev_info, ublksrv_flags) == 32);
    assert!(offset_of!(ublksrv_ctrl_dev_info, owner_uid) == 40);
    assert!(offset_of!(ublksrv_ctrl_dev_info, owner_gid) == 44);
    assert!(offset_of!(ublksrv_ctrl_dev_info, reserved1) == 48);
    assert!(offset_of!(ublksrv_ctrl_dev_info, reserved2) == 56);

    assert!(size_of::<ublksrv_io_desc>() == 24);
    assert!(align_of::<ublksrv_io_desc>() == 8);
    assert!(offset_of!(ublksrv_io_desc, op_flags) == 0);
    assert!(offset_of!(ublksrv_io_desc, nr_sectors) == 4);
    assert!(offset_of!(ublksrv_io_desc, start_sector) == 8);
    assert!(offset_of!(ublksrv_io_desc, addr) == 16);

    assert!(size_of::<ublksrv_io_cmd>() == 16);
    assert!(align_of::<ublksrv_io_cmd>() == 8);
    assert!(offset_of!(ublksrv_io_cmd, q_id) == 0);
    assert!(offset_of!(ublksrv_io_cmd, tag) == 2);
    assert!(offset_of!(ublksrv_io_cmd, result) == 4);
    assert!(offset_of!(ublksrv_io_cmd, addr) == 8);

    assert!(size_of::<ublk_param_basic>() == 32);
    assert!(align_of::<ublk_param_basic>() == 8);
    assert!(offset_of!(ublk_param_basic, attrs) == 0);
    assert!(offset_of!(ublk_param_basic, logical_bs_shift) == 4);
    assert!(offset_of!(ublk_param_basic, physical_bs_shift) == 5);
    assert!(offset_of!(ublk_param_basic, io_opt_shift) == 6);
    assert!(offset_of!(ublk_param_basic, io_min_shift) == 7);
    assert!(offset_of!(ublk_param_basic, max_sectors) == 8);
    assert!(offset_of!(ublk_param_basic, chunk_sectors) == 12);
    assert!(offset_of!(ublk_param_basic, dev_sectors) == 16);
    assert!(offset_of!(ublk_param_basic, virt_boundary_mask) == 24);

    assert!(size_of::<ublk_param_discard>() == 20);
    assert!(align_of::<ublk_param_discard>() == 4);
    assert!(offset_of!(ublk_param_discard, discard_alignment) == 0);
    assert!(offset_of!(ublk_param_discard, discard_granularity) == 4);
    assert!(offset_of!(ublk_param_discard, max_discard_sectors) == 8);
    assert!(offset_of!(ublk_param_discard, max_write_zeroes_sectors) == 12);
    assert!(offset_of!(ublk_param_discard, max_discard_segments) == 16);
    assert!(offset_of!(ublk_param_discard, reserved0) == 18);

    assert!(size_of::<ublk_param_devt>() == 16);
    assert!(align_of::<ublk_param_devt>() == 4);
    assert!(offset_of!(ublk_param_devt, char_major) == 0);
    assert!(offset_of!(ublk_param_devt, char_minor) == 4);
    assert!(offset_of!(ublk_param_devt, disk_major) == 8);
    assert!(offset_of!(ublk_param_devt, disk_minor) == 12);

    assert!(size_of::<ublk_param_zoned>() == 32);
    assert!(align_of::<ublk_param_zoned>() == 4);
    assert!(offset_of!(ublk_param_zoned, max_open_zones) == 0);
    assert!(offset_of!(ublk_param_zoned, max_active_zones) == 4);
    assert!(offset_of!(ublk_param_zoned, max_zone_append_sectors) == 8);
    assert!(offset_of!(ublk_param_zoned, reserved) == 12);

    assert!(size_of::<ublk_param_dma_align>() == 8);
    assert!(align_of::<ublk_param_dma_align>() == 4);
    assert!(offset_of!(ublk_param_dma_align, alignment) == 0);
    assert!(offset_of!(ublk_param_dma_align, pad) == 4);

    assert!(size_of::<ublk_param_segment>() == 16);
    assert!(align_of::<ublk_param_segment>() == 8);
    assert!(offset_of!(ublk_param_segment, seg_boundary_mask) == 0);
    assert!(offset_of!(ublk_param_segment, max_segment_size) == 8);
    assert!(offset_of!(ublk_param_segment, max_segments) == 12);
    assert!(offset_of!(ublk_param_segment, pad) == 14);

    assert!(size_of::<ublk_params>() == 136);
    assert!(align_of::<ublk_params>() == 8);
    assert!(offset_of!(ublk_params, len) == 0);
    assert!(offset_of!(ublk_params, types) == 4);
    assert!(offset_of!(ublk_params, basic) == 8);
    assert!(offset_of!(ublk_params, discard) == 40);
    assert!(offset_of!(ublk_params, devt) == 60);
    assert!(offset_of!(ublk_params, zoned) == 76);
    assert!(offset_of!(ublk_params, dma) == 108);
    assert!(offset_of!(ublk_params, seg) == 120);
};
