# ssh-keys — GitHub-key server access & team onboarding

Two scripts that turn GitHub-published SSH keys into server access with no
key exchange conversations:

## 1. One-liner server access

```bash
# manual one-liner (the classic):
curl https://github.com/<user>.keys >> ~/.ssh/authorized_keys

# wrapped, with safety checks (filters junk, dedups, first-run backup):
bash github-keys.sh <user> --install
```

`github-keys.sh`:
- fetches `https://github.com/<user>.keys` (no auth, no rate limit)
- validates every line against OpenSSH public-key regexes before touching
  `authorized_keys`
- skips already-installed keys (idempotent), keeps `authorized_keys.bak`
- custom target file via `GITHUB_KEYS_FILE=/custom/path`

## 2. Team onboarding — auto-pull keys for an entire org

```bash
bash org-onboard.sh <org>            # draft listing (no changes)
bash org-onboard.sh <org> --install  # append ALL members' keys
GITHUB_TOKEN=ghp_xxx bash org-onboard.sh <org> --install  # private orgs
GITHUB_KEYS_FILE=/etc/ssh/authorized_keys bash org-onboard.sh <org> --install
ORG_ONBOARD_MAX_USERS=20 bash org-onboard.sh <org>  # cap for CI/testing
```

- member list: `api.github.com/orgs/<org>/public_members` (single call)
- keys per member: `github.com/<user>.keys` (no rate limit)
- reports members without keys so you can chase them
- each installed key is commented `# github:<user> (org:<org>)` for audit

## Notes / hardening

- Keys are only as strong as the owner's GitHub account — enable 2FA on
  GitHub for anyone with push access.
- For long-lived servers, consider locking the account
  (`restrict,command=...` in authorized_keys) so a GitHub key alone cannot
  open a shell.
- Orphan keys: members who leave don't automatically revoke. Consider
  scripted re-runs (cron) that *replace* the org block rather than append.