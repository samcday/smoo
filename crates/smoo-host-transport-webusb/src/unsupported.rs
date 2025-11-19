use async_trait::async_trait;
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
use smoo_proto::{Request, Response};

#[derive(Debug, Default, Clone, Copy)]
pub struct WebUsbTransport;

impl WebUsbTransport {
    pub fn unsupported() -> TransportError {
        TransportError::with_message(
            TransportErrorKind::Unsupported,
            "WebUSB transport is only available when targeting wasm32",
        )
    }
}

#[async_trait]
impl Transport for WebUsbTransport {
    async fn read_request(&mut self) -> TransportResult<Request> {
        Err(Self::unsupported())
    }

    async fn send_response(&mut self, _response: Response) -> TransportResult<()> {
        Err(Self::unsupported())
    }

    async fn read_bulk(&mut self, _buf: &mut [u8]) -> TransportResult<()> {
        Err(Self::unsupported())
    }

    async fn write_bulk(&mut self, _buf: &[u8]) -> TransportResult<()> {
        Err(Self::unsupported())
    }
}

#[async_trait]
impl ControlTransport for WebUsbTransport {
    async fn control_in(
        &mut self,
        _request_type: u8,
        _request: u8,
        _value: u16,
        _index: u16,
        _buf: &mut [u8],
    ) -> TransportResult<usize> {
        Err(Self::unsupported())
    }

    async fn control_out(
        &mut self,
        _request_type: u8,
        _request: u8,
        _value: u16,
        _index: u16,
        _data: &[u8],
    ) -> TransportResult<()> {
        Err(Self::unsupported())
    }
}
