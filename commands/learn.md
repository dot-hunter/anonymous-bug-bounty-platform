---
description: Record the outcome of a submitted finding and extract lessons from a completed investigation. Usage: /learn
---

# /learn

End-of-cycle learning. Records what happened (accepted / duped / N/A / rejected), updates technique
weights for future prioritization, and auto-extracts lessons from completed investigations.

## Run This

Call the MCP tools directly:

```json
{
  "tool": "vulnera-mcp.record_outcome",
  "args": {
    "platform": "hackerone|bugcrowd|intigriti|immunefi",
    "outcome": "accepted|duplicated|na|rejected|pending",
    "vuln_class": "xss|ssrf|idor|...",
    "technique": "name of the technique used",
    "target": "example.com",
    "payout": 0,
    "notes": "what worked / what didn't"
  }
}
```

Then extract lessons from the investigation (if any ID exists):

```json
{
  "tool": "vulnera-mcp.platform_generate_lessons",
  "args": {
    "investigation_id": "<id from platform_status>"
  }
}
```

Finally, persist the lesson in long-term memory:

```json
{
  "tool": "vulnera-mcp.platform_record_lesson",
  "args": {
    "lesson": {
      "title": "...",
      "vuln_class": "...",
      "technique": "...",
      "target": "...",
      "outcome": "...",
      "note": "what changed / what to do differently"
    }
  }
}
```

## Rules

- NEVER auto-submit. `/learn` is called only after the human has submitted a report through the platform UI.
- If the session produced multiple findings, record each outcome separately.
- If nothing was submitted in this session, run `/memory-gc` instead and record a "no-finding" lesson so technique weights decay.