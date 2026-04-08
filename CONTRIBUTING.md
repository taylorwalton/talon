# Contributing to Talon

Talon is a SOCfortress product. Contributions are welcome but reviewed with a security-first lens — this tool processes live SOC alert data and runs with access to customer SIEM environments.

## Before You Start

1. **Check for existing work.** Search open PRs and issues before starting:
   ```bash
   gh pr list --repo taylorwalton/talon --search "<your topic>"
   gh issue list --repo taylorwalton/talon --search "<your topic>"
   ```

2. **One thing per PR.** One bug fix, one capability, one improvement. Don't mix unrelated changes.

3. **No real customer data.** Never include actual alert data, credentials, hostnames, IPs, or customer names in issues, PRs, or example output.

## What We Accept

### Source code changes

**Accepted:**
- Bug fixes and security fixes
- Improvements to the anonymising proxy (`siem/anon_proxy/`) — new field types, tokenisation rules, edge cases
- MemPalace integration improvements — room taxonomy, init reliability, MCP tool coverage
- Investigation workflow improvements in `groups/copilot/CLAUDE.md`
- Container build reliability fixes
- Documentation fixes

**Not accepted:**
- Broad feature additions that change core NanoClaw behaviour — these belong in skills
- Changes that weaken the anonymising proxy or expose PII to the cloud model
- Anything that bypasses the mount allowlist security layer

### Skills

Talon inherits the NanoClaw skill system. Skills are markdown files (with optional supporting code) that teach Claude how to do something new.

#### Container skills (most common for SOC work)

These run inside the agent container and extend what the SOC agent can do during an investigation.

**Location:** `container/skills/<name>/`

**Examples:** new investigation templates, IOC enrichment workflows, reporting formats

**Guidelines:**
- Follow the SKILL.md frontmatter format (see below)
- Use `allowed-tools` frontmatter to scope tool permissions
- Keep them focused — the agent shares its context window across all container skills
- Do not hardcode customer-specific values — use env vars or CLAUDE.md annotations

#### Operational skills (host-side workflows)

Instruction-only workflows that run on the host via Claude Code.

**Location:** `.claude/skills/<name>/`

**Examples:** `/setup`, `/debug`, onboarding a new CoPilot customer

#### Feature skills (branch-based)

Larger capabilities that require source code changes. Code lives on a `skill/*` branch; the SKILL.md on `main` contains setup instructions.

**Contributing a feature skill:**
1. Fork and branch from `main`
2. Make the code changes
3. Add a SKILL.md in `.claude/skills/<name>/` — step 1 of the instructions should be merging the branch
4. Open a PR

### SKILL.md format

```markdown
---
name: my-skill
description: What this skill does and when to use it.
---

Instructions here...
```

- `name`: lowercase, alphanumeric + hyphens, max 64 chars
- `description`: required — used by Claude to decide when to invoke the skill
- Keep SKILL.md under 500 lines — move detail to separate reference files
- Put code in separate files, not inline in the markdown

## Security Considerations

Because Talon handles live security data, contributions touching these areas get extra scrutiny:

| Area | Concern |
|---|---|
| `siem/anon_proxy/` | Must not leak PII fields to the cloud model |
| `siem/anon_proxy/fields.yaml` | New fields must be correctly categorised (token vs preserve) |
| `mempalace/` | Palace data must never be committed to the repo |
| `mount-allowlist.json` | Changes that widen write access need justification |
| MCP server wrappers | Must follow the `_is_native_exec` pattern for container compatibility |
| `.mcp.json` | New servers must be vetted — they run with container-level access |

## Testing

Test on a real (or realistic) CoPilot environment before submitting. For MCP changes, verify the server starts cleanly inside the container:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  docker run --rm -i --entrypoint bash nanoclaw-agent \
  /workspace/extra/<your-tool>/<your-tool>-mcp.sh 2>/dev/null
```

For anonymising proxy changes, confirm tokens round-trip correctly through `deanonymize`.

## Pull Requests

### Description format

- **What** — what the PR adds or changes
- **Why** — the motivation
- **How it works** — brief explanation of the approach
- **How it was tested** — what you ran to verify it
- **Security impact** — does this touch PII handling, mounts, or MCP servers?

Keep it concise. A few clear sentences beat lengthy paragraphs.

### Before opening

- `Closes #123` in the description if it resolves an open issue
- No real customer data anywhere in the diff, test output, or description
- Run `npm run build` and confirm the container builds cleanly

---

*Talon is developed and maintained by [SOCfortress](https://www.socfortress.co).*
