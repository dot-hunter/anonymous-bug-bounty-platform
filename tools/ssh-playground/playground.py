#!/usr/bin/env python3
"""
playground.py — public SSH playground that greets you by GitHub username.

Inspired by whoami.filippo.io. SSH clients tunnel every local public key to
the server while they look for an accepted one. This server NEVER accepts
any key — it simply records the offered fingerprints, lets the client in
via a zero-prompt keyboard-interactive challenge, looks the fingerprints up
in the index built by build-index.py, and prints a greeting naming the
GitHub user who owns the key.

    ssh -p 2222 user@playground.example
    ->  _o/ Hello @octocat!  (we matched your offered public key)

Requires: pip install paramiko

Usage:
    python3 playground.py --index index.jsonl --host-key host_key --port 2222
Options:
    --index     key->user index (JSONL, built by build-index.py)
    --host-key  server host private key (ssh-keygen -t ed25519 -f host_key -N '')
    --port      listen port (default 2222)
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import sys
import threading
import time

try:
    import paramiko
except ImportError:
    print("missing dependency: pip install paramiko", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# index
# --------------------------------------------------------------------------
def load_index(path):
    """index.jsonl -> {fingerprint: username}"""
    idx = {}
    if not os.path.exists(path):
        return idx
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("fp"):
                idx[rec["fp"]] = rec.get("user") or "?"
    return idx


def fp32(pub) -> str:
    """SHA256 fingerprint, e.g. 'SHA256:VcH7...' (same as ssh-keygen -lf)."""
    digest = hashlib.sha256(pub.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


# --------------------------------------------------------------------------
# server protocol
# --------------------------------------------------------------------------
class GreetingServer(paramiko.ServerInterface):
    """Collects offered public keys, rejects all, then passes client via
    keyboard-interactive with no prompts."""

    def __init__(self):
        self.offered = []

    def get_allowed_auths(self, username):
        return "publickey,keyboard-interactive"

    def check_auth_publickey(self, username, key):
        if key is not None:
            self.offered.append(key)
        # Always reject: we want to observe ALL keys the client offers,
        # including the ones it only tries after the first is refused.
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        # Accept without showing prompts. OpenSSH then reports success
        # without requiring any user input.
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_interactive_prompt(self, username, instructions, prompt_list):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


# --------------------------------------------------------------------------
# greeting
# --------------------------------------------------------------------------
def render_greeting(user, first_fp):
    fp = first_fp[:24] + "..."
    inner_w = 59
    hello = "_o/  Hello @" + user + "!"
    lines = [
        "+" + "-" * inner_w + "+",
        "|" + hello.ljust(inner_w) + "|",
        "|" + "".ljust(inner_w) + "|",
        "|" + "The SSH client you used offered us this public key:".ljust(inner_w) + "|",
        "|" + ("  " + fp).ljust(inner_w) + "|",
        "|" + "".ljust(inner_w) + "|",
        "|" + "GitHub publishes that key at:".ljust(inner_w) + "|",
        "|" + ("  https://github.com/" + user + ".keys").ljust(inner_w) + "|",
        "|" + "".ljust(inner_w) + "|",
        "|" + "No key was accepted - we only looked at it.".ljust(inner_w) + "|",
        "|" + "(whoami.filippo.io does the same; keys are public)".ljust(inner_w) + "|",
        "+" + "-" * inner_w + "+",
        "",
    ]
    return "\n".join(lines)


def render_unknown(offered):
    fps = ", ".join(fp32(k)[:20] for k in offered[:3]) or "(none offered)"
    return (
        "\nHello! We saw your SSH keys, but none matched the index.\n"
        "Offered fingerprints: " + fps + "\n"
        "Add yourself to the playground:\n"
        "  python3 build-index.py --users-file <you>.txt --out index.json\n\n"
    )


# --------------------------------------------------------------------------
# connection handler
# --------------------------------------------------------------------------
def handle_conn(conn, index, host_key):
    transport = paramiko.Transport(conn)
    transport.add_server_key(host_key)
    server = GreetingServer()
    try:
        transport.start_server(server=server)
    except Exception:
        transport.close()
        return

    chan = transport.accept(15)
    if chan is None:
        transport.close()
        return

    # drain client (keeps session alive) while we look up the user
    def drain():
        try:
            while True:
                if not chan.recv_ready():
                    time.sleep(0.1)
                    continue
                data = chan.recv(1024)
                if not data:
                    break
        except Exception:
            pass

    threading.Thread(target=drain, daemon=True).start()
    time.sleep(1.0)  # let ssh client finish listing keys (multiple attempts)

    user = None
    first_fp = None
    for key in server.offered:
        candidate = fp32(key)
        if first_fp is None:
            first_fp = candidate
        if candidate in index:
            user = index[candidate]
            break

    if user:
        text = render_greeting(user, first_fp or "?")
    else:
        text = render_unknown(server.offered)

    try:
        chan.send(text.replace("\n", "\r\n"))
    except Exception:
        pass
    try:
        transport.close()
    except Exception:
        pass


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="SSH playground — greet by GitHub username")
    ap.add_argument("--index", required=True, help="JSONL index from build-index.py")
    ap.add_argument("--host-key", required=True, help="SSH host private key (ed25519)")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()

    global index
    index = load_index(args.index)
    print(f"[+] index loaded: {len(index)} key fingerprints")

    if not os.path.exists(args.host_key):
        print(f"[!] host key not found: {args.host_key}")
        print("    generate one: ssh-keygen -t ed25519 -f host_key -N ''")
        sys.exit(1)

    try:
        host_key = paramiko.Ed25519Key(filename=args.host_key)
    except Exception:
        host_key = paramiko.RSAKey(filename=args.host_key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.listen(16)
    print(f"[+] playground ready on {args.bind}:{args.port}")
    print(f"    try:  ssh -p {args.port} -o StrictHostKeyChecking=no user@<host>")

    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle_conn, args=(conn, index, host_key), daemon=True).start()


index = None  # set in main()


if __name__ == "__main__":
    main()