use super::*;
use aap_types::stream::service::{
    ApplicationIo, AttachmentError, ConnectedStream, Connection, PendingStream, StreamAbort,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

impl PendingStream for PendingTcp {
    fn abort_handle(&self) -> Arc<dyn StreamAbort> {
        Arc::new(Abort(self.operation.clone()))
    }
    fn connect(self: Box<Self>) -> BoxFuture<'static, Result<Connection>> {
        Box::pin(async move {
            Ok(match PendingTcp::connect(*self).await {
                Ok(connected) => Connection::Opened(Box::new(connected)),
                Err(terminal) => Connection::Terminal(terminal),
            })
        })
    }
}
impl ConnectedStream for ConnectedTcp {
    fn abort_handle(&self) -> Arc<dyn StreamAbort> {
        Arc::new(Abort(self.operation.clone()))
    }
    fn opened(&self) -> Result<stream::Opened> {
        ConnectedTcp::opened(self)
    }
    fn relay(
        self: Box<Self>,
        attachment: Box<dyn ApplicationIo>,
    ) -> BoxFuture<'static, Result<stream::Terminal>> {
        // Ownership transfer must not be deferred until the boxed future polls.
        let relay = ConnectedTcp::relay(*self, Box::new(Attachment(attachment)));
        Box::pin(async move { Ok(relay.await) })
    }
}

struct Abort(Arc<Operation>);
impl StreamAbort for Abort {
    fn abort(&self, reason: AttachmentError) {
        self.0.finish(reason.cause());
    }
    fn terminated(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.0.cancelled.cancelled())
    }
}

struct Attachment(Box<dyn ApplicationIo>);
impl AsyncRead for Attachment {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let remaining = buffer.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.0.poll_read(cx, buffer.initialize_unfilled()) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Ready(Ok(count)) if count <= remaining => {
                buffer.advance(count);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => {
                Poll::Ready(Err(std::io::Error::other(AttachmentError::InternalError)))
            }
        }
    }
}
impl AsyncWrite for Attachment {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.0.poll_write(cx, bytes) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Ready(Ok(count)) if count <= bytes.len() => Poll::Ready(Ok(count)),
            Poll::Ready(Ok(_)) => {
                Poll::Ready(Err(std::io::Error::other(AttachmentError::InternalError)))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // The application contract reports only actual writes, with no queue.
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0.poll_send_end(cx).map_err(std::io::Error::other)
    }
}
