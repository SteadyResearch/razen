use rama::extensions::{Extensions, ExtensionsRef};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Adds connection-scoped Rama metadata without changing the underlying stream.
pub(crate) struct RamaIo<T> {
    pub inner: T,
    extensions: Extensions,
}
impl<T> RamaIo<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
        }
    }
}
impl<T> ExtensionsRef for RamaIo<T> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for RamaIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for RamaIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

/// A dropped exchange must close its driver, not detach live network effects.
pub(crate) struct OwnedTask<T>(tokio::task::JoinHandle<T>);
impl<T> OwnedTask<T> {
    pub fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(handle)
    }
    pub fn abort(&self) {
        self.0.abort();
    }
}
impl<T> Future for OwnedTask<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
