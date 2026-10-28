//! T1K Binary Protocol Codec for Chaitin SafeLine WAF.
//! Implements frame reading, writing, and tag parsing compatible with SafeLine Tengine & C/Lua T1K.

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const T1K_HEADER_SIZE: usize = 5;

pub const TAG_HEAD: u8 = 0x01;
pub const TAG_BODY: u8 = 0x02;
pub const TAG_EXTRA: u8 = 0x03;
pub const TAG_VERSION: u8 = 0x20;
pub const TAG_EXTRA_HEADER: u8 = 0x23;
pub const TAG_EXTRA_BODY: u8 = 0x24;

pub const MASK_FIRST: u8 = 0x40;
pub const MASK_LAST: u8 = 0x80;

pub const ACTION_PASSED: &[u8] = b".";
pub const ACTION_BLOCKED: &[u8] = b"?";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct T1kPacket {
    pub tag: u8,
    pub is_first: bool,
    pub is_last: bool,
    pub payload: Vec<u8>,
}

impl T1kPacket {
    pub fn new(tag: u8, is_first: bool, is_last: bool, payload: Vec<u8>) -> Self {
        Self {
            tag,
            is_first,
            is_last,
            payload,
        }
    }
}

/// Reads a single 5-byte header + payload T1K packet from an async reader.
pub async fn read_packet<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Option<T1kPacket>> {
    let mut header = [0u8; T1K_HEADER_SIZE];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let first_byte = header[0];
    let is_first = (first_byte & MASK_FIRST) != 0;
    let is_last = (first_byte & MASK_LAST) != 0;
    let tag = first_byte & !MASK_FIRST & !MASK_LAST;

    let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;

    let mut payload = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(Some(T1kPacket {
        tag,
        is_first,
        is_last,
        payload,
    }))
}

/// Writes a T1K packet into an async writer.
pub async fn write_packet<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    tag: u8,
    is_first: bool,
    is_last: bool,
    payload: &[u8],
) -> io::Result<()> {
    let mut first_byte = tag;
    if is_first {
        first_byte |= MASK_FIRST;
    }
    if is_last {
        first_byte |= MASK_LAST;
    }

    let length = payload.len() as u32;
    let len_bytes = length.to_le_bytes();

    let mut header = [0u8; T1K_HEADER_SIZE];
    header[0] = first_byte;
    header[1..5].copy_from_slice(&len_bytes);

    writer.write_all(&header).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

/// Constructs a SafeLine T1K PASSED response packet (`.` with FIRST and LAST flags).
pub async fn send_passed_verdict<W: AsyncWriteExt + Unpin>(writer: &mut W) -> io::Result<()> {
    write_packet(writer, TAG_HEAD, true, true, ACTION_PASSED).await
}

/// Constructs a SafeLine T1K BLOCKED response packet chain:
/// 1. TAG_HEAD (0x01 | MASK_FIRST): "?"
/// 2. TAG_BODY (0x02): "403"
/// 3. TAG_EXTRA_BODY (0x24 | MASK_LAST): custom block JSON with event_id
pub async fn send_blocked_verdict<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    event_id: &str,
    status_code: u16,
    reason: &str,
) -> io::Result<()> {
    // Packet 1: TAG_HEAD (FIRST) -> "?"
    write_packet(writer, TAG_HEAD, true, false, ACTION_BLOCKED).await?;

    // Packet 2: TAG_BODY -> status code string
    let status_str = status_code.to_string();
    write_packet(writer, TAG_BODY, false, false, status_str.as_bytes()).await?;

    // Packet 3: TAG_EXTRA_BODY (LAST) -> HTML/JSON response including event_id marker
    let body_json = serde_json::json!({
        "code": status_code,
        "success": false,
        "message": "Blocked by SATGuardian Edge WAF (SafeLine Acceleration Tier)",
        "event_id": event_id,
        "reason": reason,
    });
    let body_content = format!("{}\n<!-- event_id: {} TYPE: WAF -->", body_json, event_id);
    write_packet(writer, TAG_EXTRA_BODY, false, true, body_content.as_bytes()).await?;

    Ok(())
}
