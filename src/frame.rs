/// A single raw (possibly still encrypted) frame parsed from a TCP byte stream.
#[derive(Debug)]
pub struct RawFrame {
    /// Frame index within its stream (0-based).
    pub index: usize,
    /// Raw bytes for the CSHead section (hl bytes).
    pub head: Vec<u8>,
    /// Raw bytes for the body section (bl bytes).
    pub body: Vec<u8>,
}

/// Parse as many complete frames as possible from `data`.
///
/// Wire layout per frame:
///   [u8  hl ]  - length of the head section
///   [u16 bl ] - length of the body section (little-endian)
///   [hl bytes] - CSHead (encrypted after frame 0)
///   [bl bytes] - body   (encrypted after frame 0)
///
/// Frames that would extend past the end of `data` are silently dropped
/// (they represent an incomplete trailing frame).
pub fn parse_frames(data: &[u8]) -> Vec<RawFrame> {
    let mut frames = Vec::new();
    let mut cursor = 0usize;
    let mut index = 0usize;

    while cursor + 3 < data.len() {
        let hl = data[cursor] as usize;
        let bl = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        let total = hl + bl;

        // If the header looks impossible (Endfield hl is usually small, e.g., < 64),
        // or if we don't have enough data yet, skip one byte and try again.
        if hl == 0 || hl > 128 || cursor + 3 + total > data.len() {
            cursor += 1;
            continue;
        }

        let head = data[cursor + 3..cursor + 3 + hl].to_vec();
        let body = data[cursor + 3 + hl..cursor + 3 + total].to_vec();

        frames.push(RawFrame { index, head, body });
        cursor += 3 + total;
        index += 1;
    }
    frames
}
