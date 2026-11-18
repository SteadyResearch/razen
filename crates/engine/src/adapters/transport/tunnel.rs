use crate::protocol::error::ProofResult;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Only encrypted byte counts are exposed; no decrypted proxy snapshot exists.
pub(crate) async fn copy<IO>(mut ingress: IO, mut upstream: TcpStream) -> ProofResult<(u64, u64)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(&mut ingress, &mut upstream, 65_536, 65_536)
        .await
        .map_err(|_| super::network())
}
