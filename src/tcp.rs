use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct StreamKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl StreamKey {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    pub fn label(&self) -> String {
        format!(
            "{}:{} → {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

/// One directional TCP byte stream, with gap-tolerant reassembly.
pub struct TcpStream {
    pub key: StreamKey,
    /// Fully reassembled payload bytes in order.
    pub data: Vec<u8>,
    /// Next expected sequence number (absolute).
    next_seq: Option<u32>,
    /// Out-of-order segments keyed by sequence number.
    ooo: BTreeMap<u32, Vec<u8>>,
}

impl TcpStream {
    fn new(key: StreamKey) -> Self {
        Self {
            key,
            data: Vec::new(),
            next_seq: None,
            ooo: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }

        let next = match self.next_seq {
            None => {
                self.data.extend_from_slice(payload);
                self.next_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.drain_ooo();
                return;
            }
            Some(n) => n,
        };

        let diff = seq.wrapping_sub(next) as i32;

        if diff == 0 {
            self.data.extend_from_slice(payload);
            self.next_seq = Some(seq.wrapping_add(payload.len() as u32));
            self.drain_ooo();
        } else if diff > 0 {
            self.ooo.insert(seq, payload.to_vec());
        } else {
            let overlap = (-diff) as usize;
            if overlap < payload.len() {
                let new_data = &payload[overlap..];
                self.data.extend_from_slice(new_data);
                self.next_seq = Some(next.wrapping_add(new_data.len() as u32));
                self.drain_ooo();
            }
        }
    }

    fn drain_ooo(&mut self) {
        while let Some(next) = self.next_seq {
            if let Some(seg) = self.ooo.remove(&next) {
                self.next_seq = Some(next.wrapping_add(seg.len() as u32));
                self.data.extend_from_slice(&seg);
            } else {
                break;
            }
        }
    }
}

pub struct TcpTracker {
    streams: HashMap<StreamKey, TcpStream>,
}

impl TcpTracker {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn feed(&mut self, key: StreamKey, seq: u32, payload: &[u8]) {
        let stream = self
            .streams
            .entry(key.clone())
            .or_insert_with(|| TcpStream::new(key));
        stream.push(seq, payload);
    }

    pub fn streams(&self) -> impl Iterator<Item = &TcpStream> {
        self.streams.values()
    }
}
