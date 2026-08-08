# keytrends — RSA vs Ed25519 over the years

Track the SSH key-type landscape (RSA / Ed25519 / ECDSA / DSA) by sampling
public GitHub keys with `created_at` metadata.

## Data sources

1. `--users-file users.txt` — reads each user's public keys from
   `https://github.com/<user>.keys` (no auth, no rate limit) and, when the
   API allows, `created_at` per key from the GitHub REST API.
2. `--demo` — synthetic dataset (logistic RSA→Ed25519 shift, documented
   as synthetic) for offline testing.

## Usage

```bash
python3 keytrends.py --users-file users.txt --out trends.md
GITHUB_TOKEN=ghp_xxx python3 keytrends.py --users-file users.txt  # faster
python3 keytrends.py --demo --out demo.md                          # offline
```

Output is a Markdown table (year × key-type counts + Ed25519 share bar
chart). No numpy/matplotlib needed — pure stdlib.

## Behind the numbers

* GitHub has supported Ed25519 since 2014; newer accounts overwhelmingly
  choose it (and GitHub's own docs recommend it).
* Sampling flux gives a nice logistic-style takeover curve; the demo data
  is generated to resemble that shape so CI runs are deterministic.