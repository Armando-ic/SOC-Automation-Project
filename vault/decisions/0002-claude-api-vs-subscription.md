---
status: active
date: 2026-04-27
---

# 0002 — Claude API for autonomous workflows, Max subscription for interactive use

## Status

Accepted

## Context

The user pays $100/mo for Claude Max and also has Anthropic API credits. The n8n triage workflow originally used the OpenAI ChatGPT API per the video tutorial; the user swapped it for Anthropic. Question: should both autonomous (n8n) and interactive (Claude Desktop, Claude Code) usage go through the same channel?

The Max subscription does not include programmatic API access — separate billing entirely.

## Decision

- **n8n triage workflow → Claude API.** Programmatic, per-token billing.
- **Claude Desktop with Splunk MCP → Max subscription.** Interactive investigation, no per-query cost.
- **Claude Code with Splunk MCP → Max subscription.** Same — interactive use, mirrored from Desktop so the capability follows the project into the IDE.

## Consequences

**Positive**

- Each interface uses the appropriate billing model
- Interactive investigation is essentially free at the margin (covered by flat fee)
- Per-alert API costs scale predictably with alert volume

**Negative**

- Two billing relationships to manage
- API keys must be tracked separately from subscription credentials
