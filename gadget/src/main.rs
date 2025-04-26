use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use libublk::{UblkFlags, UblkIORes};
use std::slice;
use usb_gadget::function::custom::{
    Custom, Endpoint, EndpointDirection, Event, Interface, TransferType,
};
use usb_gadget::{Class, Config, Gadget, Id, Strings};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    usb_gadget::remove_all()?;

    let (mut data_rx, data_dir) = EndpointDirection::host_to_device();
    let (mut int_tx, int_dir) = EndpointDirection::device_to_host();

    let mut int_ep = Endpoint::custom(int_dir, TransferType::Interrupt);
    int_ep.max_packet_size_hs = 16;
    int_ep.max_packet_size_ss = 16;

    let mut data_ep = Endpoint::bulk(data_dir);
    data_ep.max_packet_size_hs = 512;
    data_ep.max_packet_size_ss = 512;

    let (mut custom, handle) = Custom::builder()
        .with_interface(
            Interface::new(Class::vendor_specific(123, 123), "smoo")
                .with_endpoint(int_ep)
                .with_endpoint(data_ep),
        )
        .build();

    let klass = Class::new(255, 255, 3);
    let id = Id::new(0xDEAD, 0xBEEF);
    let strings = Strings::new("foo", "bar", "bacon");

    let udc = usb_gadget::default_udc()?;

    let reg = Gadget::new(klass, id, strings)
        .with_config(Config::new("config").with_function(handle))
        .bind(&udc)?;

    let mut size = None;

    while size.is_none() {
        let ev = custom.event()?;
        match ev {
            Event::SetupHostToDevice(req) => {
                let mut buf: [u8; 8] = [0; 8];
                assert_eq!(8, req.recv(&mut buf)?);
                size = Some(NetworkEndian::read_u64(&buf));
            }
            _ => {
                // println!("Unhandled event {:?}", ev);
            }
        }
    }

    println!("Initializing device of size {}", size.unwrap());

    let (tx, rx) = async_channel::unbounded();

    let jh = std::thread::spawn(move || {
        let mut ctrl = libublk::ctrl::UblkCtrlBuilder::default()
            .name("smoo")
            .nr_queues(1)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        ctrl.run_target(
            |dev: &mut UblkDev| {
                dev.set_default_params(size.unwrap());
                Ok(())
            },
            |qid: u16, dev: &UblkDev| {
                let bufs = dev.alloc_queue_io_bufs();

                UblkQueue::new(qid, dev)
                    .unwrap()
                    .regiser_io_bufs(Some(&bufs))
                    .submit_fetch_commands(Some(&bufs))
                    .wait_and_handle_io(move |q: &UblkQueue, tag: u16, io: &UblkIOCtx| {
                        let buf_addr = bufs[tag as usize].as_mut_ptr();
                        let iod = q.get_iod(tag);
                        let op = iod.op_flags & 0xFF;

                        let off = iod.start_sector << 9;
                        let sz = iod.nr_sectors << 9;

                        match op {
                            libublk::sys::UBLK_IO_OP_READ => unsafe {
                                println!("io {} {}", off, sz);
                                let (io_tx, io_rx) = async_channel::bounded(1);
                                tx.send_blocking((off, sz, io_tx)).unwrap();
                                let mut buf: Bytes = io_rx.recv_blocking().unwrap();
                                println!("got it {}", buf.len());
                                unsafe {
                                    buf.copy_to_slice(slice::from_raw_parts_mut(buf_addr, sz as _));
                                }
                            },
                            _ => {}
                        }

                        q.complete_io_cmd(tag, buf_addr, Ok(UblkIORes::Result(sz as _)));
                    });
            },
            move |_| {},
        )
        .unwrap();
    });

    loop {
        let (off, sz, done_tx) = rx.recv().await?;

        let mut int_buf = BytesMut::with_capacity(16);
        int_buf.put_u64(off);
        int_buf.put_u64(sz as _);
        int_tx.send_async(int_buf.freeze()).await?;

        let mut data = BytesMut::with_capacity(sz as _);

        // Ideally we'd be able to just queue up a buffer for the total amount of data we're
        // expecting. usb-gadget doesn't work like this, though (yet?). For now we're making the
        // assumption that the block size == bulk transfer size (512b) and doing a lot
        // of unnecessary copies.
        while data.len() != sz as usize {
            let buf = data_rx.recv_async(BytesMut::with_capacity(512)).await?;
            if let Some(buf) = buf {
                data.extend(buf);
            }
        }
        done_tx.send(data.freeze()).await?;
    }

    Ok(())
}
