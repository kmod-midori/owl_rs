// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded link-control messages shared by the privileged radio and user transport.
#![forbid(unsafe_code)]
mod mac;
pub mod timeouts;
use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
pub use mac::{Mac, MacError};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::net::Ipv6Addr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{FramedRead, LinesCodec};

pub const MAX_MESSAGE: usize = 1024 * 1024;
pub fn generation() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkInfo {
    pub generation: String,
    pub mac: Mac,
    pub address: Ipv6Addr,
    pub scope: u32,
    pub interface: Option<String>,
    pub lease_timeout: f64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Acquire {
        port: u16,
    },
    State {
        generation: String,
        service_enabled: bool,
        transfers: u32,
    },
    Release {
        generation: String,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Event {
    Ready { link: LinkInfo },
    Snapshot { value: serde_json::Value },
    Closed { error: Option<String> },
    Error { message: String },
}
pub type Reader<R> = FramedRead<R, LinesCodec>;
pub fn reader<R: AsyncRead>(input: R) -> Reader<R> {
    FramedRead::new(input, LinesCodec::new_with_max_length(MAX_MESSAGE))
}
/// FramedRead retains partial messages when a select branch is cancelled.
pub async fn read<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut Reader<R>) -> Result<T> {
    let line = reader.next().await.context("link control disconnected")??;
    serde_json::from_str(&line).context("invalid link control message")
}
pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() < MAX_MESSAGE,
        "link control message exceeds 1 MiB"
    );
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn framing_survives_cancelled_reads_and_rejects_oversized_input() {
        let (mut input, output) = tokio::io::duplex(MAX_MESSAGE * 2);
        let mut reader = reader(output);
        input.write_all(b"{\"command\":\"ac").await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(1),
                read::<_, Request>(&mut reader)
            )
            .await
            .is_err()
        );
        input.write_all(b"quire\",\"port\":8771}\n").await.unwrap();
        assert!(matches!(
            read::<_, Request>(&mut reader).await.unwrap(),
            Request::Acquire { port: 8771 }
        ));
        input.write_all(&vec![b'x'; MAX_MESSAGE + 1]).await.unwrap();
        input.write_all(b"\n").await.unwrap();
        assert!(read::<_, Request>(&mut reader).await.is_err());
    }
}
