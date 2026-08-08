# pi-tool — direct program-intelligence tool caller

Bypasses the LLM layer to call the program-intelligence MCP server's 28 tools
directly over JSON-RPC-free Python invocation. Use when the model API is
flaky (e.g. free-model endpoint outages) or for scripting/automation.

## Setup

The script assumes the live server at:
`/home/bb/.opencode/mcp/servers/program-intelligence-mcp/` with the venv at
`/home/bb/.opencode/.venv/bin/python`. Symlink it into your PATH if desired:

```bash
ln -s "$(pwd)/pi-tool" /usr/local/bin/pi-tool
```

## Usage

```bash
# Discover programs from providers
PI_ARGS='{"connector":"all","max_results":20}' pi-tool discover_programs

# Authorization gate before any fingerprinting
PI_ARGS='{"handle":"<handle>","target":"blog.acme.com"}' pi-tool resolve_authorization

# Fingerprint an authorized asset (passive WordPress detection)
PI_ARGS='{"url":"https://wordpress.org","authorized":true}' pi-tool fingerprint_asset

# Find + rank WordPress targets for a program
PI_ARGS='{"handle":"<handle>","max_targets":25}' pi-tool find_wordpress_assets
PI_ARGS='{"handle":"<handle>"}' pi-tool rank_wordpress_targets

# Provenance and scope-change tracking
PI_ARGS='{"handle":"<handle>"}' pi-tool get_target_provenance
PI_ARGS='{"handle":"<handle>"}' pi-tool get_scope_changes

# List all available tools (call with any unknown name)
pi-tool help
```

## Notes

- Output is JSON to stdout; server logs go to stderr.
- Fingerprinting is passive (readme.txt/style.css/generator meta) and
  authorization-gated: `fingerprint_asset` refuses unless
  `authorized=true`, which callers must only set after
  `resolve_authorization` returns `in_scope`.
