use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub enum RawValue {
    Varint(u64),
    Fixed32(u32),
    Fixed64(u64),
    Bytes(Vec<u8>),
}

impl RawValue {
    pub fn as_varint(&self) -> Option<u64> {
        match self {
            Self::Varint(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_i32(&self) -> Option<i32> {
        self.as_varint().map(|v| v as i32)
    }
    pub fn as_u32(&self) -> Option<u32> {
        self.as_varint().map(|v| v as u32)
    }
    pub fn as_bool(&self) -> Option<bool> {
        self.as_varint().map(|v| v != 0)
    }
}

/// Decode a single base-128 varint. Returns `(value, bytes_consumed)`.
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate().take(10) {
        let bits = (byte & 0x7F) as u64;
        result |= bits.checked_shl(shift).unwrap_or(0);
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None
}

/// Parse `data` as a protobuf message (no schema).
///
/// Returns `None` if any wire-format rule is violated, making it usable as a
/// lightweight "does this look like protobuf?" check.
pub fn parse_raw_proto(data: &[u8]) -> Option<Vec<(u32, RawValue)>> {
    let mut fields: Vec<(u32, RawValue)> = Vec::new();
    let mut cursor = 0usize;

    while cursor < data.len() {
        let (tag, n) = read_varint(&data[cursor..])?;
        cursor += n;

        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 7) as u8;

        if field_number == 0 || field_number > 0x1FFF_FFFF {
            return None;
        }

        let value = match wire_type {
            0 /* varint */ => {
                let (v, n) = read_varint(&data[cursor..])?;
                cursor += n;
                RawValue::Varint(v)
            }
            1 /* 64-bit */ => {
                if cursor + 8 > data.len() {
                    return None;
                }
                let v = u64::from_le_bytes(
                    data[cursor..cursor + 8].try_into().unwrap(),
                );
                cursor += 8;
                RawValue::Fixed64(v)
            }
            2 /* len-delimited */ => {
                let (len, n) = read_varint(&data[cursor..])?;
                cursor += n;
                let len = len as usize;
                if cursor + len > data.len() {
                    return None;
                }
                let bytes = data[cursor..cursor + len].to_vec();
                cursor += len;
                RawValue::Bytes(bytes)
            }
            5 /* 32-bit */ => {
                if cursor + 4 > data.len() {
                    return None;
                }
                let v = u32::from_le_bytes(
                    data[cursor..cursor + 4].try_into().unwrap(),
                );
                cursor += 4;
                RawValue::Fixed32(v)
            }
            3 | 4 => return None, // deprecated group types
            _ => return None,
        };

        fields.push((field_number, value));
    }

    Some(fields)
}

/// Decoded representation of the CSHead protobuf (head section of every frame).
///
/// ```proto
/// message CSHead {
///     int32  msgid              = 1;
///     uint64 up_seqid           = 2;
///     uint64 down_seqid         = 3;
///     uint32 total_pack_count   = 4;
///     uint32 current_pack_index = 5;
///     bool   is_compress        = 6;
///     uint32 checksum           = 7;
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct CsHead {
    pub msgid: i32,
    pub up_seqid: u64,
    pub down_seqid: u64,
    pub total_pack_count: u32,
    pub current_pack_index: u32,
    pub is_compress: bool,
    pub checksum: u32,
}

/// Attempt to decode `data` as a CSHead.
///
/// Returns `None` when:
///   - the wire format is invalid, or
///   - field 1 (msgid) is absent (required field by convention).
pub fn parse_cshead(data: &[u8]) -> Option<CsHead> {
    let fields = parse_raw_proto(data)?;
    let mut head = CsHead::default();
    let mut has_msgid = false;

    for (field_num, value) in &fields {
        match field_num {
            1 => {
                head.msgid = value.as_i32()?;
                has_msgid = true;
            }
            2 => {
                head.up_seqid = value.as_varint()?;
            }
            3 => {
                head.down_seqid = value.as_varint()?;
            }
            4 => {
                head.total_pack_count = value.as_u32()?;
            }
            5 => {
                head.current_pack_index = value.as_u32()?;
            }
            6 => {
                head.is_compress = value.as_bool()?;
            }
            7 => {
                head.checksum = value.as_u32()?;
            }
            _ => {}
        }
    }

    if !has_msgid {
        return None;
    }
    Some(head)
}

/// A decoded proto schema: msgid -> (message type name, field_number -> field_name).
pub struct Schema {
    /// msgid -> (type_name, field_number → field_name)
    pub messages: HashMap<i32, (String, HashMap<u32, String>)>,
}

impl Schema {
    /// Load a `.proto` file with `protox` and wire up field-name mappings
    /// according to the `msgid_map` string (`"1001:LoginReq,1002:MoveReq"`).
    pub fn load(proto_path: &Path, msgid_map: &str) -> Result<Self> {
        let include_dir = proto_path.parent().unwrap_or(Path::new("."));
        let fds = protox::compile([proto_path], [include_dir])
            .with_context(|| format!("Failed to compile {:?}", proto_path))?;

        let mut messages: HashMap<i32, (String, HashMap<u32, String>)> = HashMap::new();

        for pair in msgid_map.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let mut parts = pair.splitn(2, ':');
            let id_str = parts.next().unwrap_or("").trim();
            let type_name = parts.next().unwrap_or("").trim();

            let msgid: i32 = id_str
                .parse()
                .with_context(|| format!("Bad msgid '{}'", id_str))?;

            let field_map = extract_fields(&fds, type_name);
            messages.insert(msgid, (type_name.to_string(), field_map));
        }

        Ok(Self { messages })
    }

    pub fn get(&self, msgid: i32) -> Option<&(String, HashMap<u32, String>)> {
        self.messages.get(&msgid)
    }
}

/// Extract `field_number -> field_name` for the named message from a descriptor set.
fn extract_fields(fds: &prost_types::FileDescriptorSet, msg_name: &str) -> HashMap<u32, String> {
    // msg_name may be bare ("LoginReq") or fully-qualified ("pkg.LoginReq").
    // We match by simple suffix for convenience.
    for file in &fds.file {
        for msg in &file.message_type {
            let name = msg.name();
            if name == msg_name || name.ends_with(&format!(".{}", msg_name)) {
                return msg
                    .field
                    .iter()
                    .map(|f| (f.number() as u32, f.name().to_string()))
                    .collect();
            }
        }
        for msg in &file.message_type {
            for nested in &msg.nested_type {
                let name = nested.name();
                if name == msg_name || name.ends_with(&format!(".{}", msg_name)) {
                    return nested
                        .field
                        .iter()
                        .map(|f| (f.number() as u32, f.name().to_string()))
                        .collect();
                }
            }
        }
    }
    HashMap::new()
}

/// One field in a decoded body message.
#[derive(Debug, Clone)]
pub struct DecodedField {
    pub number: u32,
    pub name: Option<String>,
    pub value: DecodedValue,
}

/// The display value of a single protobuf field.
#[derive(Debug, Clone)]
pub enum DecodedValue {
    Uint(u64),
    Int(i64),
    Bool(bool),
    Float32(f32),
    Float64(f64),
    Text(String),
    Bytes(Vec<u8>),
    Nested(Vec<DecodedField>),
}

impl From<RawValue> for DecodedValue {
    fn from(v: RawValue) -> Self {
        match v {
            RawValue::Varint(u) => DecodedValue::Uint(u),
            RawValue::Fixed32(u) => DecodedValue::Uint(u as u64),
            RawValue::Fixed64(u) => DecodedValue::Uint(u),
            RawValue::Bytes(bytes) => {
                let text_opt = std::str::from_utf8(&bytes).ok().filter(|s| {
                    s.chars()
                        .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
                });

                if let Some(s) = text_opt {
                    return DecodedValue::Text(s.to_string());
                }
                // Is it a nested protobuf message?
                if !bytes.is_empty() {
                    let nested_opt =
                        parse_raw_proto(&bytes)
                            .filter(|raw| !raw.is_empty())
                            .map(|raw| {
                                raw.into_iter()
                                    .map(|(num, val)| DecodedField {
                                        number: num,
                                        name: None,
                                        value: DecodedValue::from(val),
                                    })
                                    .collect::<Vec<_>>()
                            });

                    if let Some(fields) = nested_opt {
                        return DecodedValue::Nested(fields);
                    }
                }

                DecodedValue::Bytes(bytes)
            }
        }
    }
}

impl From<u64> for DecodedValue {
    fn from(v: u64) -> Self {
        DecodedValue::Uint(v)
    }
}

impl From<i64> for DecodedValue {
    fn from(v: i64) -> Self {
        DecodedValue::Int(v)
    }
}

impl From<bool> for DecodedValue {
    fn from(v: bool) -> Self {
        DecodedValue::Bool(v)
    }
}

impl From<f32> for DecodedValue {
    fn from(v: f32) -> Self {
        DecodedValue::Float32(v)
    }
}

impl From<f64> for DecodedValue {
    fn from(v: f64) -> Self {
        DecodedValue::Float64(v)
    }
}

/// Decode a raw body blob into a list of typed fields.
///
/// If `field_names` is provided, field numbers are mapped to names.
/// For length-delimited values we heuristically try: UTF-8 string -> nested
/// proto -> raw bytes (in that order).
pub fn decode_body(
    data: &[u8],
    field_names: Option<&HashMap<u32, String>>,
) -> Option<Vec<DecodedField>> {
    let raw = parse_raw_proto(data)?;
    let fields = raw
        .into_iter()
        .map(|(number, value)| {
            let name = field_names.and_then(|m| m.get(&number)).cloned();
            let decoded = DecodedValue::from(value);
            DecodedField {
                number,
                name,
                value: decoded,
            }
        })
        .collect();
    Some(fields)
}
