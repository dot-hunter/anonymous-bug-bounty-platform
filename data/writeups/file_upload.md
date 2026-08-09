# FILE_UPLOAD — technique corpus

## polyglot_php
- target: Web App
- payload hint: GIF89a;<?php system($_GET['c']);
- bounty: $10000.0 (2024)
- source: https://hackerone.com/reports/303031
- summary: Polyglot image with PHP backdoor executes

## polyglot_svg_php
- target: Web
- payload hint: SVG with PHP delimiter
- bounty: $9000.0 (2024)
- source: aggregated:hacktivity svg php 2024
- summary: SVG polyglot

## upload_permission_chain
- target: Web
- payload hint: upload then admin-exec triggered
- bounty: $8500.0 (2024)
- source: aggregated:hacktivity upload chain 2024
- summary: Upload executed by internal job

## external_storage_backdoor
- target: Cloud
- payload hint: upload into public bucket with attacker path
- bounty: $8500.0 (2024)
- source: aggregated:hacktivity s3 upload 2024
- summary: Storage ACL leak

## path_traversal_name
- target: Web App
- payload hint: filename=../../shell.php
- bounty: $8000.0 (2025)
- source: https://hackerone.com/reports/313131
- summary: Upload filename traverses to webroot

## zip_slip
- target: Web
- payload hint: zip ../../
- bounty: $7200.0 (2024)
- source: aggregated:hacktivity zipslip 2024
- summary: Zip slip arbitrary file

## targ_symlink
- target: Web
- payload hint: tar symlink to /etc
- bounty: $6800.0 (2024)
- source: aggregated:hacktivity tar symlink 2024
- summary: Tar symlink read/write

## content_type_spoof
- target: Web
- payload hint: image/png with php code
- bounty: $6500.0 (2024)
- source: aggregated:hacktivity upload mime 2024
- summary: Content-type only check

## 7z_multipayload
- target: Web
- payload hint: 7z with multiple dangerous paths
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity 7z 2024
- summary: 7z path files

## rar_path
- target: Web
- payload hint: rar with absolute path
- bounty: $5500.0 (2024)
- source: aggregated:hacktivity rar 2024
- summary: RAR absolute path overwrite

## double_extension
- target: Web
- payload hint: shell.php.jpg
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity upload ext 2024
- summary: Double ext confusion

## null_byte_ext
- target: Web
- payload hint: shell.php%00.jpg
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity upload null
- summary: Null byte truncation

## office_macro
- target: Office
- payload hint: docm macro
- bounty: $3500.0 (2024)
- source: aggregated:hacktivity office macro 2024
- summary: Docm macros download

## html_upload_stored_xss
- target: Web
- payload hint: html file → stored XSS
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity html upload 2024
- summary: Arbitrary HTML storage

## pdf_score_javascript
- target: Web
- payload hint: JavaScript in PDF
- bounty: $2200.0 (2024)
- source: aggregated:hacktivity pdf 2024
- summary: PDF javascript SPA delivery

## svg_xss
- target: Web App
- payload hint: SVG with embedded script
- bounty: $2000.0 (2025)
- source: https://hackerone.com/reports/292929
- summary: SVG upload rendered inline executes JS

## svg_css_exfil
- target: Web
- payload hint: SVG with external CSS data
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity svg 2024
- summary: SVG CSS exfil

## upload_name_ss
- target: Web
- payload hint: filename reflected in response = stored XSS
- bounty: $1700.0 (2024)
- source: aggregated:hacktivity upload name 2024
- summary: Filename stored XSS

## svg_xlink
- target: Web
- payload hint: xlink:href javascript
- bounty: $1600.0 (2024)
- source: aggregated:hacktivity svg xlink 2024
- summary: SVG xlink handler

## xlsx_formula
- target: Web
- payload hint: XLSX formula injection
- bounty: $1600.0 (2024)
- source: aggregated:hacktivity xlsx formula 2024
- summary: XLSX formula injection

## csv_import
- target: Web
- payload hint: CSV formula injection
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity csv formula 2024
- summary: CSV formula injection

## mimetype_rotation
- target: Web
- payload hint: rotation between content sniff engines
- bounty: $1400.0 (2024)
- source: aggregated:hacktivity image 2024
- summary: Sniffer differential

## zip_bomb_profile
- target: Web
- payload hint: 10:1 compression bomb
- bounty: $900.0 (2024)
- source: aggregated:hacktivity zip 2024
- summary: Decompression DoS

## metadata_strip_html
- target: Web
- payload hint: docx metadata extraction
- bounty: $800.0 (2024)
- source: aggregated:hacktivity docx meta 2024
- summary: Document metadata leak

## exif_data_leak
- target: Web
- payload hint: EXIF GPS stripping
- bounty: $600.0 (2024)
- source: aggregated:hacktivity exif 2024
- summary: EXIF privacy leak
