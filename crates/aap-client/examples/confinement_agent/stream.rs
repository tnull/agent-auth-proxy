use aap_types::{
    AgentService, ErrorCode, Result,
    stream::{
        self,
        service::{Admission, ApplicationIo, AttachmentError, Connection},
    },
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

const MAX_BYTES: usize = 16 * 1024;

pub async fn run(session: PathBuf, open: stream::Open, send: Vec<u8>) -> Result<Value> {
    if send.len() > MAX_BYTES {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let client = aap_client::DaemonSessionClient::new(session);
    let pending = match client.open_stream(open).await? {
        Admission::Existing(status) => return Ok(json!({"existing":status})),
        Admission::New(pending) => pending,
    };
    let connected = match pending.connect().await? {
        Connection::Terminal(terminal) => return Ok(json!({"terminal":terminal})),
        Connection::Opened(connected) => connected,
    };
    let opened = connected.opened()?;
    let received = Arc::new(Mutex::new(Received::default()));
    let terminal = connected
        .relay(Box::new(Application {
            send,
            offset: 0,
            received: received.clone(),
        }))
        .await?;
    let received = received.lock().map_err(|_| ErrorCode::InternalError)?;
    Ok(
        json!({"opened":opened,"terminal":terminal,"received":received.bytes,"received_end":received.ended}),
    )
}

#[derive(Default)]
struct Received {
    bytes: Vec<u8>,
    ended: bool,
}
struct Application {
    send: Vec<u8>,
    offset: usize,
    received: Arc<Mutex<Received>>,
}
impl ApplicationIo for Application {
    fn poll_read(
        &mut self,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let count = buffer.len().min(self.send.len() - self.offset);
        buffer[..count].copy_from_slice(&self.send[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(count))
    }
    fn poll_write(
        &mut self,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let Ok(mut received) = self.received.lock() else {
            return Poll::Ready(Err(AttachmentError::InternalError));
        };
        if received.ended || bytes.len() > MAX_BYTES.saturating_sub(received.bytes.len()) {
            return Poll::Ready(Err(AttachmentError::LimitExceeded));
        }
        received.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_send_end(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>> {
        let Ok(mut received) = self.received.lock() else {
            return Poll::Ready(Err(AttachmentError::InternalError));
        };
        received.ended = true;
        Poll::Ready(Ok(()))
    }
}
