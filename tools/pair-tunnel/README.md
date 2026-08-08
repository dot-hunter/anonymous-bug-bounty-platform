# pair-tunnel — instant pair-programming tunnels, no manual key sharing

Exchange **GitHub usernames**, not key files.

Both sides' SSH identities are derived from their GitHub-published public
keys (`https://github.com/<user>.keys`). No scp, no pastebin, no "send me
your .pub".

## Host side (the machine running the code)

```bash
# one machine, sharing port 3000 with alice and bob:
pair-tunnel.sh host --users alice,bob --port 3000
#   -> guest connection string printed

# behind NAT? bounce through a relay:
pair-tunnel.sh host --users alice,bob --port 3000 --relay relay.example:2222
```

The host writes an **ephemeral authorized_keys** file
(`~/.ssh/pair-authorized_keys`) containing exactly the GitHub-published keys
of the requested users — nothing else changes. Clean up after the session.

## Guest side

```bash
pair-tunnel.sh guest --user alice --host relay.example:2222 --port 3000
```

The guest authenticates with their own key as published on GitHub; the host
accepts only those. No key material is sent by the script — the SSH
handshake does the work.

## Requirements

* `curl`, `ssh` on both sides.
* Inbound connectivity (or a relay) for the host.

## Security notes

* The ephemeral authorized-keys file grants **your GitHub key** to the host
  only for the session lifetime — delete `~/.ssh/pair-authorized_keys` when
  done, and consider `ssh-keygen -R` host cleanup.
* GitHub keys are public: anyone can *read* them, but only you can produce
  signatures proving possession of the private key. That's the entire
  authentication premise of OpenSSH.