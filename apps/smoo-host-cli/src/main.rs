use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt};
use rusb::{Direction, Recipient, RequestType, TransferType};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let handle = rusb::open_device_with_vid_pid(0xDEAD, 0xBEEF).unwrap();

    let desc = handle.device().active_config_descriptor()?;

    for intf in desc.interfaces() {
        for ep in intf.descriptors().next().unwrap().endpoint_descriptors() {
            println!(
                "ep: {:?} {}",
                ep,
                ep.transfer_type() == TransferType::Interrupt
            );
        }
    }

    handle.claim_interface(0)?;

    let mut buf: [u8; 512] = [0; 512];

    let mut f = File::open("/tmp/file")?;
    f.seek(SeekFrom::End(0))?;
    NetworkEndian::write_u64(&mut buf, f.stream_position()?);

    handle.write_control(
        rusb::request_type(Direction::Out, RequestType::Vendor, Recipient::Interface),
        0,
        0,
        0,
        &buf[0..8],
        Duration::from_secs(1),
    )?;

    let mut read_buf = Vec::new();
    loop {
        let read = handle.read_interrupt(129, &mut buf[0..16], Duration::from_secs(0))?;
        assert_eq!(read, 16);

        let mut buf_r = &buf[..];
        let off = buf_r.read_u64::<NetworkEndian>()?;
        let sz = buf_r.read_u64::<NetworkEndian>()?;

        println!("read {} {}", off, sz);

        read_buf.resize(sz as _, 0);

        let resp = &mut read_buf[0..sz as usize];
        f.seek(SeekFrom::Start(off))?;
        f.read_exact(resp);

        handle.write_bulk(2, &resp, Duration::from_secs(1))?;
    }

    Ok(())
}
