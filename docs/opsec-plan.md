# Anonymous OPSEC Plan — Bug Bounty Hunter 2026

**Date:** 2026-08-06  
**Scope:** Full anonymity infrastructure for autonomous bug bounty hunting  
**Threat Model:** Platform bans, IP-based rate limiting, identity correlation, legal exposure

---

## 1. Network Layer Anonymity

### 1.1 VPN Rotation

**Current State:** Config mentions `proxy_support: "optional"` but no implementation  
**Target State:** Automatic VPN rotation with kill switch

**Implementation:**
```bash
# VPN providers that support WireGuard and API rotation:
# - Mullvad (supports WireGuard, no account needed)
# - ProtonVPN (free tier available, WireGuard)
# - Windscribe (API for server rotation)
# - Self-hosted WireGuard on VPS (AWS/GCP/DigitalOcean)

# Rotation strategy:
# - New server every 30 minutes OR on 403/429 detection
# - Kill switch: iptables DROP all non-VPN traffic
# - DNS leak protection: force DNS through VPN tunnel
# - IPv6 disable: prevent leaks via IPv6
```

**OpenCode Integration:**
- Add `vpn_manager.py` tool to rotate VPN from autopilot
- Trigger rotation on HTTP 429/403 patterns
- Log rotation events (not IPs) for debugging

### 1.2 Tor Routing

**Current State:** Not implemented  
**Target State:** Optional Tor egress for high-sensitivity targets

**Implementation:**
```bash
# Tor configuration for selective routing:
# - SOCKS5 proxy on 127.0.0.1:9050
# - IsolateDestAddr per-target stream isolation
# - Exit node country whitelist (avoid 5-eyes if needed)
# - Circuit rotation every 10 minutes

# Limitations:
# - Many targets block Tor exit nodes
# - Slow for scanning (use only for submission/report phases)
# - Some platforms (HackerOne) require account login over Tor
```

**OpenCode Integration:**
- `tor_controller.py` for circuit management
- Route only OSINT/research traffic through Tor
- Active testing uses VPN (faster, less blocked)

### 1.3 Proxy Chains

**Current State:** Not implemented  
**Target State:** Multi-hop proxy chains for traffic analysis resistance

**Implementation:**
```bash
# Chain architecture:
# [OpenCode] → [Local SOCKS5] → [VPN] → [Proxy] → [Target]
# 
# Proxy types:
# - Residential proxies (brightdata, oxylabs) — expensive but unblocked
# - Mobile proxies (4G/5G rotation) — highest trust score
# - Datacenter proxies — cheap but easily identified

# Rotation per-request for high-value targets
```

---

## 2. Browser Fingerprint Isolation

### 2.1 Profile Isolation

**Current State:** No browser automation  
**Target State:** Per-target browser profiles with unique fingerprints

**Implementation:**
```bash
# Firefox Multi-Account Containers or Chrome profiles:
# - New profile per target program
# - Unique: user-agent, screen resolution, timezone, fonts, WebGL renderer
# - Canvas/audiopadding randomization (via CanvasBlocker extension)
# - Cookie jar isolation (no cross-target cookies)
# - localStorage and IndexedDB cleared between sessions

# Tools:
# - Playwright with firefox for realistic fingerprinting
# - puppeteer-extra with stealth plugin for Chrome
# - Multilogin/Gologin for commercial-grade fingerprint management
```

**OpenCode Integration:**
- `browser_manager.py` creates/destroys profiles per target
- Fingerprint profiles stored encrypted at rest
- Automatic cleanup after each session

### 2.2 Headless Browser Security

**Current State:** Not implemented  
**Target State:** Hardened headless browser for safe testing

**Implementation:**
```bash
# Security hardening:
# - Disable JavaScript execution by default (enable per-test)
# - Block third-party requests unless explicitly allowed
# - Disable WebRTC (prevents IP leaks)
# - Run in ephemeral Docker container per session
# - Network namespace isolation (no host network access)
# - seccomp-bpf syscall filtering
```

---

## 3. Identity Rotation

### 3.1 Account Management

**Current State:** Anonymous mode declared but no infrastructure  
**Target State:** Burner identity generation and rotation

**Implementation:**
```bash
# For platforms requiring accounts (HackerOne, Bugcrowd):
# - Dedicated burner email per platform (ProtonMail, Tutanota)
# - Unique username per platform (no correlation)
# - PGP key per identity (HackerOne requires)
# - Separate browser profile per identity
# - Separate VPN exit per identity (no IP correlation)

# For anonymous testing (no account):
# - Only passive recon + no-auth vuln testing
# - No platform interaction needed
# - Submit via program's security.txt email if available
```

### 3.2 Payment Anonymity

**Current State:** Not addressed  
**Target State:** Untraceable bounty collection

**Implementation:**
```bash
# Options:
# - Monero (XMR) — preferred, truly anonymous
# - Bitcoin via CoinJoin — pseudo-anonymous
# - Platform-specific: some pay via PayPal (requires identity)
# - Some programs pay in gift cards (anonymous)
# - OpenCollective for open-source projects
```

---

## 4. Ephemeral Containers

**Current State:** Not implemented  
**Target State:** Docker-based ephemeral workspace per target

**Implementation:**
```dockerfile
# Per-target ephemeral container:
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    python3 python3-pip wireguard curl git \
    nmap ncat proxychains4
COPY tools/ /opt/tools/
WORKDIR /workspace
# Container destroyed after session
# No volume mounts — all data ephemeral
# Network restricted to VPN tunnel only
```

**OpenCode Integration:**
- `container_orchestrator.py` manages ephemeral environments
- Spin up container per target program
- Auto-destroy after session timeout (default: 4 hours)
- Screenshots/findings extracted before destruction

---

## 5. Traffic Shaping

### 5.1 Rate Limiting

**Current State:** `max_request_rate_per_minute: 30` in config (not enforced)  
**Target State:** Adaptive rate limiting with per-target profiles

**Implementation:**
```python
# Rate limit profiles:
RATE_PROFILES = {
    "conservative": {"rpm": 10, "delay_ms": 500, "jitter_ms": 200},
    "normal": {"rpm": 30, "delay_ms": 200, "jitter_ms": 100},
    "aggressive": {"rpm": 60, "delay_ms": 100, "jitter_ms": 50},
}

# Adaptive logic:
# - Start conservative
# - Increase if no 429/403 for 5 minutes
# - Decrease on any rate limit response
# - Hard stop on 3 consecutive 429s
```

### 5.2 Request Randomization

**Current State:** Not implemented  
**Target State:** Human-like request patterns

**Implementation:**
```python
# Randomization parameters:
# - Inter-request delay with Gaussian distribution
# - Random User-Agent rotation (real browser UAs)
# - Random Accept-Language headers
# - Random HTTP/2 pseudo-header ordering
# - Random TLS fingerprint (JA3/JA4 via custom client)
# - Random request ordering (don't enumerate sequentially)
```

---

## 6. DNS Isolation

**Current State:** Not implemented  
**Target State:** Per-target DNS resolution isolation

**Implementation:**
```bash
# DNS configuration:
# - Use DNS over HTTPS (DoH) via Cloudflare/Quad9
# - Never use ISP DNS
# - Separate DNS cache per target (prevent cache snooping)
# - DNS query logging disabled
# - Block DNS leaks via iptables

# Implementation:
# - systemd-resolved with per-interface DNS
# - dnscrypt-proxy for encrypted resolution
# - Local DNS cache flush between targets
```

---

## 7. Cookie Separation

**Current State:** agent-reach stores cookies locally  
**Target State:** Hardware-isolated cookie storage per identity

**Implementation:**
```bash
# Cookie management:
# - Separate cookie jar per target program
# - Cookie jar encrypted at rest (AES-256)
# - Automatic expiration after session
# - No cross-target cookie sharing
# - Session cookies only (no persistent tracking cookies)

# For browser automation:
# - Firefox containers or Chrome profiles isolate cookies
# - Cookie AutoDelete extension for cleanup
```

---

## 8. Workspace Isolation

**Current State:** Single `~/.config/` workspace  
**Target State:** Per-target encrypted workspace

**Implementation:**
```bash
# Workspace structure:
~/.config/opencode/workspaces/
├── {target_hash_A}/
│   ├── findings/       # Encrypted at rest
│   ├── recon_data/     # Encrypted at rest
│   ├── screenshots/    # Encrypted at rest
│   └── state.json      # Ephemeral
├── {target_hash_B}/
│   └── ...

# Encryption:
# - LUKS-encrypted directories (per-target key)
# - Key derived from master key + target hash
# - Auto-unmount after session
# - Secure delete (shred) of ephemeral data
```

---

## 9. Audit Trail Sanitization

**Current State:** `audit.jsonl` with 12-char session hashes  
**Target State:** Zero-knowledge audit system

**Implementation:**
```python
# Audit log principles:
# - No raw IP addresses
# - No raw target names (use hashes)
# - No raw finding data (reference IDs only)
# - No timestamps with second precision (hour precision only)
# - No User-Agent strings
# - Session IDs are SHA-256 truncated to 12 chars

# Log format:
# {"sid": "a1b2c3d4e5f6", "hour": "2026-08-06T14", "action": "recon", "status": "ok"}
```

---

## 10. Communication Security

### 1. Platform Interaction

**Implementation:**
```bash
# HackerOne:
# - Dedicated account with burner identity
# - PGP key for encrypted communication
# - Tor for account creation (if anonymous)
# - Never link to real email/phone

# Bugcrowd:
# - Similar to HackerOne
# - Some programs allow anonymous submissions via email

# Independent programs:
# - security.txt email (often ProtonMail)
# - PGP-encrypted submission emails
# - No account required
```

### 2. Report Submission

**Implementation:**
```bash
# Anonymous submission flow:
# 1. Write report in ephemeral container
# 2. Encrypt with program's PGP key
# 3. Submit via Tor or anonymous email
# 4. No metadata in PDF/document properties
# 5. Strip EXIF from screenshots
# 6. Use burner email for communication
```

---

## Implementation Roadmap

| Phase | Component | Difficulty | Time |
|-------|-----------|-----------|------|
| 1 | VPN rotation + kill switch | Medium | 4h |
| 1 | Adaptive rate limiting | Low | 2h |
| 2 | Browser fingerprint isolation | High | 8h |
| 2 | Tor routing integration | Medium | 4h |
| 3 | Ephemeral containers | Medium | 6h |
| 3 | Workspace encryption | Medium | 4h |
| 4 | Identity rotation | High | 8h |
| 4 | Traffic randomization | Medium | 4h |
| 5 | Full integration with autopilot-hunter | High | 12h |

**Total estimated effort:** ~52 hours
