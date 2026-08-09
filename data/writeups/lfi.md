# LFI — technique corpus

## log_poisoning
- target: PHP App
- payload hint: User-Agent log injection + include
- bounty: $15000.0 (2025)
- source: https://hackerone.com/reports/373737
- summary: LFI + log poisoning achieves RCE

## log4j_trace
- target: Java
- payload hint: JNDI from UA
- bounty: $9500.0 (2024)
- source: aggregated:hacktivity lfi javax 2024
- summary: JNDI via log poisoning

## docker_secret
- target: Cloud
- payload hint: /run/secrets/
- bounty: $8000.0 (2024)
- source: aggregated:hacktivity lfi docker 2024
- summary: Docker secrets read

## writable_upload_include
- target: Web
- payload hint: upload path included LFI
- bounty: $8000.0 (2024)
- source: aggregated:hacktivity lfi upload 2024
- summary: LFI + upload chain

## ssh_key_read
- target: Web
- payload hint: /home/user/.ssh/id_rsa
- bounty: $7000.0 (2024)
- source: aggregated:hacktivity lfi ssh 2024
- summary: SSH key read

## nginx_logs
- target: Web
- payload hint: /var/log/nginx/access.log
- bounty: $6500.0 (2024)
- source: aggregated:hacktivity lfi nginx 2024
- summary: Nginx access log include

## php_filter
- target: PHP App
- payload hint: php://filter/convert.base64-encode
- bounty: $6000.0 (2025)
- source: https://hackerone.com/reports/353535
- summary: php://filter reads source code via LFI

## apache_error_log
- target: Web
- payload hint: /var/log/apache2/error.log
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity lfi apache 2024
- summary: Apache error log include

## php_wrapper_resource
- target: PHP
- payload hint: data://text/plain;base64
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity lfi data 2024
- summary: data URI include

## php_wrapper_phar
- target: PHP
- payload hint: phar://
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity lfi phar 2024
- summary: Phar include

## proc_self_env
- target: Web
- payload hint: /proc/self/environ
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity lfi proc 2024
- summary: Environment via proc

## config_read
- target: Web
- payload hint: /etc/nginx/conf.d/default.conf
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity lfi conf 2024
- summary: Document-root config disclosure

## lfi_to_ssrf
- target: Web
- payload hint: include http://
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity lfi ssrf 2024
- summary: Remote include SSRF

## pg_hba_ssl_conf
- target: Web
- payload hint: /etc/postgresql/.../pg_hba.conf
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity lfi pg 2024
- summary: DB config disclosure

## env_file
- target: Web
- payload hint: /.env
- bounty: $3500.0 (2024)
- source: aggregated:hacktivity env 2024
- summary: .env disclosure

## cgi_bin_bug
- target: Web
- payload hint: CGI param include
- bounty: $3500.0 (2024)
- source: aggregated:hacktivity lfi cgi 2024
- summary: CGI param include

## null_byte
- target: PHP App
- payload hint: %00.png path truncation
- bounty: $3000.0 (2024)
- source: https://hackerone.com/reports/363636
- summary: Null byte truncates extension check

## git_objects
- target: Web
- payload hint: /.git/HEAD
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity git 2024
- summary: Git repo disclosure

## unicode_traversal
- target: Web
- payload hint: ..%c0%af
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity lfi unicode 2024
- summary: Unicode slashes

## double_url
- target: Web
- payload hint: %252e%252e%252f
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity lfi enc 2024
- summary: Double-encoded traversal
