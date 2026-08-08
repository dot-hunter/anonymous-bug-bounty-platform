# SSH Playground — greet users by GitHub username

A public SSH honeypot-that-isn't: when a client connects, it **offers** all
its public keys (that's how OpenSSH discovers the right key). The playground
never accepts any of them — it just reads the offered fingerprints, lets the
client in via empty keyboard-interactive auth, then prints

```
+-----------------------------------------------------------+
|_o/  Hello @octocat!                                       |
|The SSH client you used offered us this public key:        |
|  SHA256:SlSdsTYgtT3jhz1QF...                              |
|GitHub publishes that key at:                              |
|  https://github.com/octocat.keys                          |
+-----------------------------------------------------------+
```

The same trick powers [whoami.filippo.io](https://whoami.filippo.io) —
SSH keys are public data linked to your GitHub identity.

## Setup

```bash
pip install paramiko                     # server dependency

# 1. index: map key-fingerprints -> GitHub usernames
printf "octocat\ntorvalds\n" > users.txt
python3 build-index.py --users-file users.txt --out index.jsonl
python3 build-index.py --org <org> --out index.jsonl     # whole org

# 2. host key
ssh-keygen -t ed25519 -f host_key -N ''

# 3. run
python3 playground.py --index index.jsonl --host-key host_key --port 2222
```

## Try it

```bash
ssh -o StrictHostKeyChecking=no -p 2222 anyone@your-server
```

Anyone whose GitHub key is in the index gets greeted by username. Everyone
else gets a polite "we saw your keys but nothing matched" message listing
the fingerprints they offered.

## Privacy notes

This is a concrete demonstration that SSH clients disclose all local public
keys to any server they try to talk to. Users who care about linkability
should use `IdentitiesOnly yes` + per-host `IdentityFile`s (see
`man ssh_config`). The playground records nothing persistently.