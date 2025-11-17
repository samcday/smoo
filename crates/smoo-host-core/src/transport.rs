use anyhow::Result;
use async_trait::async_trait;
use smoo_proto::{Ident, Request, Response};

/// Abstracts the USB transport that carries control-plane messages between the
/// host and gadget.
#[async_trait]
pub trait Transport: Send {
    /// Execute the FunctionFS Ident handshake and return the gadget's reported Ident.
    async fn setup(&mut self) -> Result<Ident>;

    /// Receive the next Request from the gadget (interrupt IN).
    async fn read_request(&mut self) -> Result<Request>;

    /// Send a Response back to the gadget (interrupt OUT).
    async fn send_response(&mut self, response: Response) -> Result<()>;
}
