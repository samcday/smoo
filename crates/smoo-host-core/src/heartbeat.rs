use crate::{ControlTransport, TransportError, control::read_status};
use smoo_proto::SmooStatusV0;

/// Errors that can occur while issuing periodic SMOO_STATUS requests.
#[derive(Debug, Clone)]
pub enum HeartbeatError {
    SessionChanged { previous: u64, current: u64 },
    Transfer(TransportError),
}

impl From<TransportError> for HeartbeatError {
    fn from(err: TransportError) -> Self {
        HeartbeatError::Transfer(err)
    }
}

/// Issue a SMOO_STATUS request and optionally validate the session id.
///
/// Returns the decoded status payload on success.
pub async fn heartbeat_once<C: ControlTransport>(
    control: &C,
    expected_session_id: Option<u64>,
) -> Result<SmooStatusV0, HeartbeatError> {
    let status = read_status(control)
        .await
        .map_err(HeartbeatError::Transfer)?;
    if let Some(prev) = expected_session_id {
        if status.session_id != prev {
            return Err(HeartbeatError::SessionChanged {
                previous: prev,
                current: status.session_id,
            });
        }
    }
    Ok(status)
}
