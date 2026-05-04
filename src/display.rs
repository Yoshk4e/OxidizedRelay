use colored::Colorize;

use crate::proto::{CsHead, DecodedField, DecodedValue};
use crate::tcp::StreamKey;

const WIDTH: usize = 70;

pub fn print_stream_header(key: &StreamKey, frame_count: usize) {
    let label = format!("  TCP Stream  {}  ({} frames)  ", key.label(), frame_count);
    let pad = WIDTH.saturating_sub(label.len());
    println!(
        "\n{}{}{}",
        "╔".cyan(),
        "═".repeat((WIDTH + 2).max(label.len() + 2)).cyan(),
        "╗".cyan()
    );
    println!(
        "{}  {}{}{}",
        "║".cyan(),
        label.cyan().bold(),
        " ".repeat(pad),
        "║".cyan()
    );
    println!(
        "{}{}{}",
        "╚".cyan(),
        "═".repeat((WIDTH + 2).max(label.len() + 2)).cyan(),
        "╝".cyan()
    );
}

pub struct FrameInfo<'a> {
    pub frame_index: usize,
    pub is_plaintext: bool,
    pub head: &'a CsHead,
    pub body_fields: Option<&'a Vec<DecodedField>>,
    pub type_name: Option<&'a str>,
    pub crc_ok: bool,
    pub raw_head: &'a [u8],
    pub raw_body: &'a [u8],
    pub show_raw: bool,
}

pub fn print_frame(info: FrameInfo) {
    let enc_tag = if info.is_plaintext {
        " plaintext".yellow().to_string()
    } else {
        " encrypted".green().to_string()
    };
    let msgid_label = if let Some(name) = info.type_name {
        format!("{}  ({})", info.head.msgid, name)
    } else {
        info.head.msgid.to_string()
    };

    println!(
        "\n{}  {}  │  msgid: {}",
        format!("▶ Frame #{}", info.frame_index).bold(),
        enc_tag,
        msgid_label.yellow().bold(),
    );
    println!("{}", "─".repeat(WIDTH).dimmed());

    println!("{}", "  [CSHead]".bold().blue());
    println!(
        "    {:25} {}",
        "msgid:".dimmed(),
        info.head.msgid.to_string().yellow().bold()
    );
    println!("    {:25} {}", "up_seqid:".dimmed(), info.head.up_seqid);
    println!("    {:25} {}", "down_seqid:".dimmed(), info.head.down_seqid);
    println!(
        "    {:25} {}",
        "total_pack_count:".dimmed(),
        info.head.total_pack_count
    );
    println!(
        "    {:25} {}",
        "current_pack_index:".dimmed(),
        info.head.current_pack_index
    );
    println!(
        "    {:25} {}",
        "is_compress:".dimmed(),
        info.head.is_compress
    );

    let crc_str = format!("0x{:08X}", info.head.checksum);
    if info.crc_ok {
        println!(
            "    {:25} {}  {}",
            "checksum:".dimmed(),
            crc_str,
            "✓".green().bold()
        );
    } else {
        println!(
            "    {:25} {}  {}",
            "checksum:".dimmed(),
            crc_str,
            "✗ mismatch".red().bold()
        );
    }

    if info.raw_body.is_empty() {
        println!("\n{}", "  [Body] (empty)".bold().blue());
    } else {
        let body_title = if let Some(name) = info.type_name {
            format!("  [Body: {}]", name)
        } else {
            "  [Body]".to_string()
        };
        println!("\n{}", body_title.bold().blue());

        if let Some(fields) = info.body_fields {
            print_fields(fields, 4);
        } else {
            println!(
                "    {}",
                "(could not parse body as protobuf, showing hex)"
                    .red()
                    .italic()
            );
            println!("    {}", hex_dump(info.raw_body, 4));
        }
    }
    if info.show_raw {
        println!("\n{}", "  [Raw Bytes]".bold().dimmed());
        println!(
            "    head ({} B): {}",
            info.raw_head.len(),
            hex::encode(info.raw_head).dimmed()
        );
        println!(
            "    body ({} B): {}",
            info.raw_body.len(),
            hex::encode(info.raw_body).dimmed()
        );
    }
}

fn print_fields(fields: &[DecodedField], indent: usize) {
    let pad = " ".repeat(indent);
    for f in fields {
        let key = match &f.name {
            Some(name) => format!("{} ({})", name, f.number),
            None => format!("field_{}", f.number),
        };
        match &f.value {
            DecodedValue::Nested(nested) => {
                println!("{}{}:", pad, key.dimmed());
                print_fields(nested, indent + 2);
            }
            other => {
                println!(
                    "{}{}  {}",
                    pad,
                    format!("{:30}", format!("{}:", key)).dimmed(),
                    format_value(other)
                );
            }
        }
    }
}

fn format_value(v: &DecodedValue) -> String {
    match v {
        DecodedValue::Uint(n) => n.to_string().yellow().to_string(),
        DecodedValue::Int(n) => n.to_string().yellow().to_string(),
        DecodedValue::Bool(b) => {
            if *b {
                "true".green().to_string()
            } else {
                "false".red().to_string()
            }
        }
        DecodedValue::Float32(f) => format!("{}", f).yellow().to_string(),
        DecodedValue::Float64(f) => format!("{}", f).yellow().to_string(),
        DecodedValue::Text(s) => format!("{:?}", s).green().to_string(),
        DecodedValue::Bytes(b) => {
            format!("<bytes {} B> {}", b.len(), hex::encode(b).dimmed()).to_string()
        }
        DecodedValue::Nested(_) => "(nested)".to_string(),
    }
}

pub fn print_invalid_frame(frame_index: usize, raw_head: &[u8], raw_body: &[u8]) {
    println!(
        "\n{} {}",
        format!("▶ Frame #{}", frame_index).bold(),
        "[invalid / skipped]".red()
    );
    println!("{}", "─".repeat(WIDTH).dimmed());
    println!(
        "    head ({} B): {}",
        raw_head.len(),
        hex::encode(raw_head).dimmed()
    );
    println!(
        "    body ({} B): {}",
        raw_body.len(),
        hex::encode(raw_body).dimmed()
    );
}

pub fn print_summary(total_frames: usize, valid: usize, invalid: usize, crc_fail: usize) {
    println!("\n{}", "═".repeat(WIDTH).cyan());
    println!(
        "{}  total={}  valid={}  crc_fail={}  skipped={}",
        " Summary".bold(),
        total_frames.to_string().bold(),
        valid.to_string().green().bold(),
        crc_fail.to_string().yellow().bold(),
        invalid.to_string().red().bold()
    );
    println!("{}", "═".repeat(WIDTH).cyan());
}

fn hex_dump(data: &[u8], indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::new();
    for chunk in data.chunks(16) {
        let hex_part: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii_part: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{}{}  {}\n", pad, hex_part.join(" "), ascii_part));
    }
    out.trim_end().to_string()
}
