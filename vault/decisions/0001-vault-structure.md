---
status: active
date: 2026-04-27
---

# 0001 — Vault structure: `vault/` subdirectory inside project root

## Status

Accepted

## Context

This project is expanding past the original tutorial into multiple sequential sub-projects (structured outputs, response actions, EDR, detection engineering, multi-agent triage, case memory, etc.). The user wants:

1. Each sub-project to be pickable up by a fresh Claude Code instance with no chat-context dependency
2. A persistent record of decisions, architecture, and operations
3. The Karpathy LLM-wiki pattern (https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f) as the reference model

Three layouts were considered: a `vault/` subdirectory inside the existing project folder, a separate Obsidian vault elsewhere, or a flat structure at the project root.

## Decision

Create `vault/` as a subdirectory of `f:\Claude_Code\SOC_Automation_Project\`. Inside `vault/`:

- `CLAUDE.md` — schema for fresh instances
- `README.md`, `index.md`, `log.md` at the root
- `architecture/` (with `components/` subfolder)
- `subprojects/` (one folder per sub-project, named `YYYY-MM-DD-<topic>/`)
- `decisions/` (numbered ADRs)
- `runbooks/` (cross-cutting operational docs)
- `workflows/` (per-workflow living documentation)
- `sources/` (session notes, raw artifacts the vault is built from)

Existing folders (`Photos/`, `JSON/`, `Transcripts/`, `splunk-mcp-main/`) stay where they are at the project root. Vault files reference them with relative links.

## Consequences

**Positive**

- One project, one location — vault sits next to the artifacts it documents
- Obsidian opens `vault/` directly with no nesting concerns
- Fresh Claude Code instances see the project root and have everything reachable
- Source artifacts don't move, so existing references to them stay valid

**Negative**

- Sources live outside the vault, so Obsidian's graph view won't show links into them
- `.obsidian/` config will appear inside the project; needs to be gitignored (handled in root `.gitignore`)

**Rejected alternatives**

- **Separate vault elsewhere** — clean separation but breaks proximity to source artifacts and complicates relative links
- **Flat structure at project root** — simplest but doesn't scale past a few sub-projects and removes the per-sub-project boundary that fresh-instance handoffs need
