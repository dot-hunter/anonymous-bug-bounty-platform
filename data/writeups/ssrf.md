# SSRF — technique corpus

## git_http_smuggle
- target: Web
- payload hint: gopher→git protocol RCE chain
- bounty: $8000.0 (2024)
- source: aggregated:hacktivity ssrf git 2024
- summary: git:// protocol behind allowlist → internal git SSH/RCE chains

## gopher_redis
- target: Cloud
- payload hint: gopher:// protocol attacks internal Redis
- bounty: $7500.0 (2024)
- source: https://hackerone.com/reports/101010
- summary: SSRF via gopher writes cron job to internal Redis

## azure_imds
- target: Cloud
- payload hint: http://169.254.169.254/metadata/instance?api-version=2021-02-01
- bounty: $6500.0 (2024)
- source: aggregated:hacktivity ssrf azure 2024
- summary: Azure IMDS credential endpoint

## gcp_metadata
- target: Cloud
- payload hint: http://metadata.google.internal/computeMetadata/v1/
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity ssrf gcp 2024-2025
- summary: GCP metadata endpoint with Metadata-Flavor: Google header variant

## jdbc_url_injection
- target: Web
- payload hint: jdbc:mysql://internal
- bounty: $5500.0 (2024)
- source: aggregated:hacktivity ssrf jdbc 2024
- summary: JDBC URL params accepted by driver (MySQL/RCE chains)

## cloud_metadata_aws
- target: Cloud
- payload hint: http://169.254.169.254/latest/meta-data/
- bounty: $5000.0 (2025)
- source: https://hackerone.com/reports/666666
- summary: Webhook URL fetches AWS metadata, leaks IAM credentials

## webhook_management
- target: SaaS
- payload hint: POST /webhooks {url: internal→SSRF}
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity ssrf webhooks 2024
- summary: Webhook URL field uncontrolled fetch

## pdf_include_remote
- target: Web
- payload hint: PDF markdown/remote-URL include
- bounty: $4600.0 (2024)
- source: aggregated:hacktivity ssrf pdf 2024
- summary: PDF generator imports remote resources (URL with file reading)

## image_processing
- target: Web
- payload hint: img-src=internal URL resize
- bounty: $4400.0 (2024)
- source: aggregated:hacktivity ssrf image 2023-2024
- summary: Image resize service fetches internal IMG (multi-hop chain)

## avatar_upload_fetch
- target: Web
- payload hint: avatar URL fetcher field
- bounty: $4200.0 (2024)
- source: aggregated:hacktivity ssrf avatar 2023-2024
- summary: Avatar URL upload performs server-side fetch

## dns_rebinding
- target: Web App
- payload hint: DNS rebinding bypasses allowlist
- bounty: $4000.0 (2025)
- source: https://hackerone.com/reports/999999
- summary: Attacker domain resolves to public then internal IP

## redirect_chain
- target: Web App
- payload hint: Open redirect chains to metadata endpoint
- bounty: $3000.0 (2024)
- source: https://hackerone.com/reports/888888
- summary: Trusted redirect endpoint chains to metadata IP

## graphql_batch_ssrf
- target: GraphQL
- payload hint: introspection+query to fetch internal
- bounty: $2800.0 (2024)
- source: aggregated:hacktivity graphql ssrf 2024
- summary: GraphQL-specific SSRF (e.g. custom directives implementations)

## ip_encoding_bypass
- target: Web App
- payload hint: Decimal IP encoding bypasses blocklist
- bounty: $2500.0 (2025)
- source: https://hackerone.com/reports/777777
- summary: http://2130706433/ bypasses 127.0.0.1 blocklist

## lfi_to_ssrf
- target: Web
- payload hint: include file:http://
- bounty: $2400.0 (2024)
- source: aggregated:hacktivity lfi ssrf 2024
- summary: LFI include of remote URL

## dns_resolution_racer
- target: Web
- payload hint: Double resolution race (TOCTOU in allowlist)
- bounty: $2300.0 (2024)
- source: aggregated:hacktivity ssrf toctou 2024
- summary: Allowlist checked once, resolution to internal happens later

## s3_spoof
- target: Cloud
- payload hint: http://s3.amazonaws.com/...?internal
- bounty: $2200.0 (2024)
- source: aggregated:hacktivity ssrf s3 2024
- summary: S3 bucket name spoofing when DNS allows

## ipv6_encoding
- target: Web
- payload hint: http://[::1]/ etc
- bounty: $2100.0 (2024)
- source: aggregated:hacktivity ssrf ipv6 2023-2024
- summary: IPv6 literal bypasses IPv4 blocklist

## port_scan_limited
- target: Web
- payload hint: time-based port scans via fetch
- bounty: $2000.0 (2025)
- source: aggregated:hacktivity ssrf scan 2024-2025
- summary: Selective port scanning through SSRF (noise-managed)

## short_url_resolver
- target: Web
- payload hint: bit.ly internal URL expansion
- bounty: $1900.0 (2024)
- source: aggregated:hacktivity ssrf shorturl 2024
- summary: Short-URL expander fetches internal

## ftp_scheme
- target: Web
- payload hint: ftp://user:pass@internal
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity ssrf proto 2024
- summary: FTP scheme may reach internal FTP services

## crlf_ssrf
- target: Web
- payload hint: url=%0d%0aHost:%20internal
- bounty: $1700.0 (2024)
- source: aggregated:hacktivity ssrf crlf 2024
- summary: CRLF injection in URL rewriter

## file_scheme
- target: Web
- payload hint: file:///etc/passwd
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity ssrf file 2024
- summary: file:// reads local files if scheme allowed

## backslash_bug
- target: Web
- payload hint: http:/127.0.0.1 (backslash host confusion)
- bounty: $1000.0 (2024)
- source: aggregated:hacktivity ssrf parser 2024
- summary: Backslash host confusion in URL parsers

## userinfo_bug
- target: Web
- payload hint: http://attacker@127.0.0.1/
- bounty: $900.0 (2024)
- source: aggregated:hacktivity ssrf parser 2024
- summary: URL parser host ambiguity bypasses validators

## unicode_domain
- target: Web
- payload hint: http://é.example/
- bounty: $800.0 (2024)
- source: aggregated:hacktivity ssrf unicode 2024
- summary: Unicode normalization maps to internal hostname

## chunked_dns
- target: Web
- payload hint: DNS-body uniquely identifies internal host
- bounty: $700.0 (2024)
- source: aggregated:hacktivity oob 2024
- summary: OOB DNS callback confirmation
