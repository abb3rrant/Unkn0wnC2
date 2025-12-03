# Common DNS C2 Detection Rules

Reference document for Suricata/IDS signatures detecting DNS-based command and control (C2) and data exfiltration.

---

## Detection Categories

### 1. High Volume / Beaconing Detection

```
alert dns any any -> any 53 (msg:"Multiple Huge DNS Queries - Possible C2/Exfil"; \
    dns.opcode:0; \
    threshold:type both, track by_src, count 30, seconds 60; \
    sid:1000020; rev:1;)

alert dns any any -> any any (msg:"Regular Interval DNS Query - Possible Beacon"; \
    flow:stateless; \
    detection_filter:track by_src, count 10, seconds 60; \
    sid:1000014; rev:1;)
```

### 2. Large Query/Response Size (DNS Tunneling)

```
alert dns any any -> any 53 (msg:"DNS Query Length exceeds 25 chars - Possible C2/Exfil"; \
    dns.opcode:0; dns.query; bsize:>25; \
    threshold:type both, track by_src, count 10, seconds 60; \
    sid:1000021; rev:1;)

alert dns any 53 -> any any (msg:"Large DNS Answer >100 bytes - Possible C2"; \
    dsize:>=100; \
    threshold:type both, track by_dst, count 10, seconds 60; \
    sid:1000022; rev:1;)

alert dns any any -> any any (msg:"Large DNS Query - Possible Tunneling"; \
    dns.query; dsize:>100; \
    sid:1000013; rev:1;)
```

### 3. Excessive TXT Record Requests

```
alert dns any any -> any any (msg:"Excessive DNS TXT Requests - Possible C2/Exfil"; \
    dns.query_type; content:"TXT"; \
    threshold:type both, track by_src, count 30, seconds 60; \
    sid:1000012; rev:1;)
```

### 4. Known Malicious Domain Patterns

```
# Suspicious TLDs commonly used for malware hosting
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET DNS Query to *.pw domain - Likely Hostile"; \
    content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; \
    content:"|02|pw|00|"; fast_pattern; nocase; distance:0; \
    classtype:bad-unknown; sid:2016778; rev:4;)

# DNS tunneling services
alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DNS Query for vpnoverdns - DNS Tunneling"; \
    content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; \
    content:"|03|tun|10|vpnoverdns|03|com|00|"; fast_pattern; nocase; distance:0; \
    classtype:bad-unknown; sid:2018438; rev:2;)

# Known C2 domain template
alert dns any any -> any any (msg:"DNS Query to Known C2 Domain"; \
    dns.query; content:"maliciousc2.com"; nocase; \
    sid:1000015; rev:1;)
```

---

## Tool-Specific Signatures

### dnscat2
| Indicator | Description |
|-----------|-------------|
| `dnscat.` prefix | Common subdomain prefix |
| Mixed record types | Uses A, TXT, CNAME, MX for communication |
| High entropy subdomains | Encrypted/encoded data in queries |
| Consistent beaconing | Regular interval DNS requests |

### iodine
| Indicator | Description |
|-----------|-------------|
| Uniform packet sizes | Consistent query/response sizes |
| Rapid query cadence | High frequency DNS requests |
| IPv4 tunneling artifacts | IP data encoded in DNS |
| NULL record usage | Uncommon record type for data transfer |

### Cobalt Strike DNS Beacon
| Indicator | Description |
|-----------|-------------|
| `api.`, `post.` prefixes | Customizable query prefixes |
| Hex-encoded subdomains | Data encoded in subdomain labels |
| A records for beaconing | Check-in traffic |
| TXT records for commands | Command delivery mechanism |

### Sliver
| Indicator | Description |
|-----------|-------------|
| Customizable patterns | Highly configurable DNS C2 |
| A/TXT record usage | Similar to Cobalt Strike |
| ML-evasion features | Designed to evade behavioral detection |

---

## Emerging Threats (ET) Rule Categories

| Category | Description |
|----------|-------------|
| `dns.rules` | DNS tunneling and protocol abuse |
| `trojan.rules` | Known trojan network signatures |
| `botcc.rules` | Bot C2 communication (updated daily) |
| `compromised.rules` | Known compromised domains/IPs |

### Key ET DNS Rules

```
# Excessive DNS responses - Cache poisoning
alert udp any 53 -> $DNS_SERVERS any (msg:"ET DNS Excessive DNS Responses (100+ in 10s)"; \
    byte_test:2,>,0,6; byte_test:2,>,0,10; \
    threshold:type both, track by_src, count 100, seconds 10; \
    classtype:bad-unknown; sid:2008446; rev:9;)

# Excessive NXDOMAIN - DGA detection
alert udp any 53 -> $HOME_NET any (msg:"ET DNS Excessive NXDOMAIN - Possible DGA"; \
    byte_test:1,&,128,2; byte_test:1,&,1,3; byte_test:1,&,2,3; \
    threshold:type both, track by_src, count 50, seconds 10; \
    classtype:bad-unknown; sid:2008470; rev:6;)

# APT C2 domain examples
alert udp $HOME_NET any -> any 53 (msg:"ET DNS APT C2 Domain micorsofts.net"; \
    content:"|0a|micorsofts|03|net|00|"; nocase; fast_pattern:only; \
    threshold:type limit, track by_src, count 1, seconds 300; \
    classtype:bad-unknown; sid:2016569; rev:3;)
```

---

## Behavioral Indicators

### Query Anomalies
- Subdomain length >50 characters
- High entropy in subdomain labels (base64/hex encoding)
- Consistent query timing intervals
- Single host querying same external domain repeatedly

### Response Anomalies
- Large TXT record responses
- Responses from non-standard DNS servers
- Answers pointing to known sinkhole IPs

### Volume Anomalies
- >30 queries/minute to same domain
- Unusual ratio of query types (high TXT/NULL)
- DNS traffic without corresponding HTTP/HTTPS

---

## Resources

### Rule Repositories
- [GDATAAdvancedAnalytics/Suricata-C2](https://github.com/GDATAAdvancedAnalytics/Suricata-C2)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)
- [daffainfo/suricata-rules](https://github.com/daffainfo/suricata-rules)

### Threat Intelligence
- [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/) - DNS Application Layer Protocol
- [Feodo Tracker](https://feodotracker.abuse.ch/) - Botnet C2 blocklist
- [Abuse.ch](https://abuse.ch/) - SSL/JA3 fingerprints

### Documentation
- [Suricata Rules Format](https://docs.suricata.io/en/latest/rules/intro.html)
- [ET Category Descriptions](https://tools.emergingthreats.net/docs/ETPro%20Rule%20Categories.pdf)
- [Unit42 DNS Tunneling Analysis](https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild/)

---

## Threshold Tracking Deep Dive

Understanding how Suricata tracks thresholds is critical for both detection tuning and evasion analysis.

### Track Types

| Track Type | What It Counts | Multi-Domain C2 Evasion |
|------------|----------------|-------------------------|
| `by_src` | All queries from source IP | No benefit - aggregates all queries |
| `by_dst` | All queries to destination IP | Helps if using different NS IPs |
| `by_rule` | Global across all traffic | No benefit |
| `by_both` | Source + Destination pair | Helps with different dest IPs |

### Example Analysis

```
threshold:type both, track by_src, count 10, seconds 60;
```

| Scenario | Result |
|----------|--------|
| 10 queries to `evil1.com` in 60s | Triggers |
| 10 queries split across 5 domains in 60s | Still triggers (same source) |
| 5 queries across 5 domains in 60s | Does not trigger |

**Key Insight:** Multi-domain rotation does NOT evade `track by_src` rules. All queries from the same source IP are aggregated regardless of destination domain.

### Common Rule Thresholds

| Rule Type | Typical Threshold | Queries/Min to Evade |
|-----------|-------------------|----------------------|
| High volume detection | 30 in 60s | < 0.5/min |
| Large query detection | 10 in 60s | < 0.16/min |
| TXT record detection | 30 in 60s | < 0.5/min |
| NXDOMAIN/DGA detection | 50 in 10s | < 5/min |

---

## Evasion Analysis

### What Threshold-Based Rules Catch

| C2 Timing Profile | ~Queries/Min | Detection Likelihood |
|-------------------|--------------|----------------------|
| Aggressive (1-5s) | 12-60 | High - triggers most rules |
| Default (60-120s) | 0.5-1 | Medium - may trigger some |
| Low-and-slow (5-15min) | 0.07-0.2 | Low - evades thresholds |
| Ultra-slow (30min+) | < 0.03 | Very low |

### What Multi-Domain Rotation Helps With

| Detection Type | Evasion Benefit |
|----------------|-----------------|
| `track by_src` thresholds | None |
| `track by_dst` thresholds | Distributes across IPs |
| Per-domain reputation | No single domain flagged |
| Domain blocklisting | Redundancy if one burned |
| Analyst investigation | Harder to correlate |

### Detection Gaps for Low-and-Slow C2

These techniques are **harder to detect** with standard rules:

1. **Sub-threshold beaconing** - Queries below count/time thresholds
2. **Encrypted payloads** - No content signatures match
3. **Non-standard encoding** - Base36 vs Base64 avoids common patterns
4. **Aged/categorized domains** - Not in threat intel feeds
5. **Business hours operation** - Blends with legitimate traffic

### What Still Detects Low-and-Slow

| Detection Method | Why It Works |
|------------------|--------------|
| **Single-query rules** (no threshold) | Triggers on characteristics, not volume |
| **Entropy analysis** | High randomness in subdomain labels |
| **ML/behavioral models** | Pattern recognition over time |
| **Rare domain correlation** | Repeated queries to uncommon domains |
| **DNS-only traffic analysis** | DNS without corresponding HTTP/HTTPS |
| **Long-term baseline deviation** | Statistical anomaly over days/weeks |

---

## Detection Recommendations

### For Defenders

1. **Don't rely solely on thresholds** - Add single-query entropy/length rules
2. **Use `track by_both`** - Catches per source-destination pair patterns
3. **Implement ML-based detection** - Catches low-and-slow behavioral patterns
4. **Monitor TXT record ratios** - Unusual TXT% relative to baseline
5. **Correlate DNS with other traffic** - Flag DNS-only external communication
6. **Track unique domains per host** - Sudden increase = suspicious

### For Red Teams

1. **Know your thresholds** - Test against target's detection stack
2. **Timing is everything** - Volume-based rules are easily evaded
3. **Domain strategy matters** - Aged, categorized, mixed TLDs
4. **Blend with environment** - Match target's DNS patterns
5. **Avoid tool signatures** - No `dnscat.`, `api.`, `post.` prefixes

---

## Best Practices

1. **Baseline normal DNS behavior** - Understand typical query patterns before alerting
2. **Tune thresholds** - Adjust count/time values to reduce false positives
3. **Layer detection** - Combine signature + behavioral + threat intel
4. **Update regularly** - Subscribe to ET Open/Pro for current IOCs
5. **Monitor entropy** - Flag high-entropy subdomains algorithmically
6. **Track record type distribution** - Alert on unusual TXT/NULL ratios
7. **Correlate with other traffic** - DNS-only communication to external domains is suspicious
