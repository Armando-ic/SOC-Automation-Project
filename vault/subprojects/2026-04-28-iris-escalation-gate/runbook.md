---
status: active
updated: 2026-04-29
sub_project: A2
related: [[spec]], [[notes]], [[../../architecture/components/dfir-iris]], [[../../architecture/components/n8n]], [[../2026-04-27-structured-outputs/runbook]]
---

# Runbook — A2 Iris Escalation Gate

Operational guide for the `SOC Triage v2` workflow that A2 produced. Builds on A1's runbook ([[../2026-04-27-structured-outputs/runbook]]); this file documents only A2-new operations.

## Architecture at a glance

```
Splunk webhook -> n8n v2 -> Anthropic (triage) -> Extract Triage Result
              -> Create Iris Alert (with alert_iocs) -> Has Malicious IOCs?
              |- NO  -> Slack plain post -> END
              `- YES -> Slack post + Approve/Deny URL buttons
                         -> Wait For Decision (signed webhook, 1800s)
                         -> Decision? Switch
                            |- approve  -> Build Escalate Body -> Escalate Iris Alert
                            |             -> Escalation Succeeded? -> Slack thread (case link or fail)
                            |- deny     -> Slack thread: denied
                            `- fallback -> Slack thread: timeout
```

Three webhooks live on the n8n VM (192.168.129.132:5678):

| Surface | URL |
|---|---|
| v2 production webhook | `http://192.168.129.132:5678/webhook/db7245f7-8451-4bea-b47d-f6ad35b818cd` |
| v2 test webhook (during pinning) | `http://192.168.129.132:5678/webhook-test/db7245f7-...` |
| v1 legacy webhook (rollback target) | `http://192.168.129.132:5678/webhook/9ccbefed-5e8a-4f16-87f4-12128ffa89ae` |

n8n did **not** preserve the webhook GUID across the v1->v2 duplicate. Any cutover, rollback, or external-system change (Splunk, etc.) must touch the webhook URL.

## Deploy A2 to a fresh n8n environment

Prerequisites — same as A1's runbook (Anthropic, Slack, DFIR-Iris, VirusTotal, AbuseIPDB credentials registered).

1. **Import:** Workflows -> Add Workflow -> Import from File -> select `JSON/SOC-Triage-v2.json`.
2. **Reattach credentials.** Open each node missing a credential icon. The HTTP Request nodes for Slack (`Post Slack Alert + Approve/Deny`, four `Reply: ...` thread reply nodes) all use the **Slack API** predefined credential — no manual token extraction needed.
3. **Verify workflow timeout = 2100s** (Workflow Settings -> Timeout). The v2 export ships at 2100s; if it landed at A1's 120s the Wait node will be killed before the analyst can approve.
4. **Verify Wait node `Resume time limit = 1800s`** (the 30-min production gate). Phase 10 testing temporarily reset this to 30s; Phase 11 pre-flight reset it to 1800s and exported. If you see 30s in the live UI after import, the JSON is stale — re-export from a known-good source.
5. **Verify `Create Iris Alert` "Always Output Data" = ON**. Without this, downstream nodes can't read the response and the workflow fails with `Cannot read properties of undefined (reading 'alert_id')`.
6. **Verify `Escalate Iris Alert` "Continue On Fail" = ON**. Without this, an Iris-down failure crashes the workflow instead of routing to the `Reply: Approved but escalate failed` Slack thread reply.
7. **Activate** `SOC Triage v2`. The production webhook starts listening.
8. **Update Splunk's `Test-Brute-Force` saved search** -> Webhook URL -> set to v2's production URL above.

## Roll back to v1

Symptom that justifies rollback: A2's gate, escalate, or Wait infrastructure is producing repeated execution failures and the analyst pipeline is stalled. v1 still has the original triage path (without the gate) and is the safest fallback.

1. **Deactivate** `SOC Triage v2` in n8n.
2. **Activate** `SOC Triage v1 (legacy)` — production webhook starts listening.
3. **Update Splunk's saved-search webhook URL** back to v1's production URL (above). **GUIDs differ; copy carefully.**
4. (Optional) Disable Splunk's saved search if you don't want re-triage during recovery.

Roll-forward is the same procedure in reverse. v1 and v2 can both exist in n8n; only one should be active at a time.

## Verify production health

After cutover or after any change to v2, send one real alert through:

1. **Trigger:** in Splunk, enable the `Test-Brute-Force` saved search and either wait for the next cron tick or click "Run search now". For a guaranteed gate-fires path use the spoofed-IP saved search (see "Re-running e2e against v2" below).
2. **Watch n8n executions** (`Executions` tab on the workflow). The execution should show all expected nodes green; the Wait node will sit "Running" until the analyst clicks.
3. **Check Slack `#alerts`.** A Block Kit message with structured sections + Approve / Deny buttons should appear within ~60s of the Splunk alert firing.
4. **Click Approve.** The browser tab opens to a JSON `{"message":"Workflow was started"}` page (known cosmetic limitation; see "Known limitations").
5. **Check Slack thread reply.** An `Approved — Iris case <link>` message should appear in-thread within a few seconds.
6. **Check Iris UI.** The new case (e.g., `#13`) should exist with the IOC promoted to its case-level threat-intel tab — **not** just the alert-level IOC tab. The case tags should include `soc-automation,a2,auto-escalated`; TLP should be Amber.

If anything fails, see "Debug a failed execution" below.

## Re-running e2e against v2

Two saved searches exist for verification:

| Saved search | What it does | Status by default |
|---|---|---|
| `Test-Brute-Force` | Real Splunk search; emits the actual `src_ip` from the event log (typically RFC1918, takes the **gate-skipped** path) | Disabled |
| `Test-Brute-Force-External-Spoofed` | Same query with `\| eval src_ip="185.220.101.42"` inlined; emits an external IP, takes the **gate-fires** path | Disabled |

Both must be **disabled** when not actively testing — otherwise every cron tick produces a Slack message and an Iris alert, and the analyst review queue fills up.

To run an end-to-end gate-fires test:
1. Splunk -> Settings -> Searches, reports, and alerts -> enable `Test-Brute-Force-External-Spoofed`.
2. Generate >=5 failed RDP logons on the Windows VM (or wait for natural traffic). The saved search runs on a 1-minute cron.
3. Wait <=60s for n8n execution to start.
4. Approve / Deny / Timeout per the verification steps above.
5. **Disable the saved search again.** Skipping this step has bitten us — the search keeps firing every minute.

## Build new IOC types or new gated actions

A2's `Extract Triage Result` Code node hardcodes Iris IOC type IDs captured in Phase 0.1. If A3+ adds new IOC categories (URLs, hostnames, registry keys, etc.):

1. Re-capture from live: `curl -ks -H "Authorization: Bearer <iris-api-key>" https://192.168.129.133/manage/ioc-types/list`.
2. Update the `IRIS_IOC_TYPE_IDS` constant in `Extract Triage Result` and the `resolveIrisTypeId` function.
3. Update the catalog in [[../../architecture/components/dfir-iris]] under "IOC type IDs".
4. Update the schema in `submit_triage_result`'s `ioc_type` enum.
5. **When the schema changes, bump to v2.** See [[../../decisions/0005-additive-ioc-type-schema-enhancement]] for the v1/v2 boundary rule.

For new gated *actions* (e.g., A3's blocklist write), the gate pattern is the reusable architectural piece:

- Slack URL buttons -> `{{ $execution.resumeUrl }}&decision=approve|deny`
- Wait node, On Webhook Call, Resume Time Limit 1800s, Respond Immediately
- Switch on `$json.query.decision === 'approve' | 'deny' | (fallback)` — **not** `$json.timedOut` (that field does not exist; see [[spec]] erratum and Phase 6 finding in [[notes]])
- Each branch posts a Slack thread reply for audit trail

A new action just plugs into the approve sub-flow alongside or in place of `Build Escalate Body` / `Escalate Iris Alert`.

## Debug a failed execution

1. **n8n -> Executions -> click the failed run -> identify the failing node.**
2. **Common failure modes:**

| Symptom | Cause | Fix |
|---|---|---|
| `'NoneType' object is not iterable` from Iris escalate | `assets_import_list` or `case_tags` missing from body — Iris's handler has unhandled-None bugs in spec-marked-optional fields | Always include both fields in the escalate body, even if empty. The `Build Escalate Body` Code node already does this; if you forked it, restore. |
| `Cannot read properties of undefined (reading 'alert_id')` | `Create Iris Alert` "Always Output Data" toggled OFF | Toggle ON. Re-run. |
| `iocs_import_list` accepted (HTTP 200) but case-level IOC tab empty in Iris | n8n template substitution wrapped the array in JSON-string quotes | The repo's `Build Escalate Body` Code node + Raw HTTP Request body (Pattern H) avoids this. Don't switch back to "Using JSON" body with `{{ ... }}` substitution for arrays. |
| Iris HTTP 401 after long uptime | API key in n8n credential expired or rotated | Regenerate at Iris UI -> User profile -> API keys; update `DFIR-IRIS account` credential. |
| Iris connection refused; `docker-compose ps` says everything is "Up (healthy)" | Stale iptables NAT rules from a hard VM stop | `cd ~/iris-web && sudo docker-compose down && sudo docker-compose up -d`. Volumes are preserved. See "Iris recovery" below. |
| Slack post fires twice | Workflow re-triggered (Splunk webhook duplicate, manual + cron, etc.) — A2 has no dedup | Acceptable lab behavior; manually delete the duplicate Iris alert. |
| `Wrong type: '1' is a string but was expecting a number` from `Has Malicious IOCs?` IF | Trailing newline in the leftValue expression | Strip whitespace after `}}`. Don't enable "Convert types where required" — it masks the cause. |
| Slack message body literally says `"undefined"` | Cross-graph expression collision: `$json.field` resolves to *immediate* upstream node's output, not the source node | Use `$('Source Node').item.json.field` instead of `$json.field` in any node that consumes from a non-immediate upstream node. |
| Decision branch never fires; Switch always lands on fallback | Slack URL buttons constructed manually as `.../webhook-waiting/{exec_id}?decision=approve` | n8n Wait webhooks require the `signature=...` query param. Use `{{ $execution.resumeUrl }}&decision=approve` (note `&` not `?` — `?signature=...` is already on the URL). |
| Slack post says HTTP 200 but blocks/buttons don't render | Tried to use n8n's native Slack node `Message Type: Blocks` field | The native Slack node accepts the JSON in the UI but doesn't translate it to a `blocks` payload. Use HTTP Request to `chat.postMessage` instead (the repo already does this). |
| Iris case_title shows replacement-character glyph instead of separator | Em-dash got mangled at HTTP encoding boundary | See "Em-dash mangling" below. |

## Iris recovery (after VM hard stop)

After a hard stop (deliberate or accidental), bringing the Iris VM back up is a **two-command sequence**:

```bash
ssh adminuser@192.168.129.133
cd ~/iris-web
sudo docker-compose down    # tears down docker network + clears stale NAT rules
sudo docker-compose up -d   # fresh network, fresh NAT rules
```

**Do not** just run `up -d` after the VM comes back — `docker-compose ps` will report all containers "Up (healthy)" but host-level `https://localhost/` will hang. The in-container nginx healthcheck is misleading; it confirms nginx is alive but says nothing about whether host:container port forwarding is working. Always confirm with a host-side `curl -ks https://192.168.129.133/api/ping` or similar before trusting that recovery is complete.

`down` does not remove volumes (no `-v` flag), so postgres data — including alerts and cases from the previous session — survives.

## Em-dash mangling (historical, not currently reproducing)

During Phase 10/11, cases #10/#11/#12's case_titles were observed (in [[notes]]) to render with a Unicode replacement glyph in place of the em-dash separator (`[ALERT #41] Test-Brute-Force-External � high` instead of `... — high`). The hypothesis was an encoding issue at the n8n->Iris HTTP boundary on the `case_title` field built by `Build Escalate Body`.

**Phase 12 verification** (after the additional Approve-path e2e producing case #13, 2026-04-30): the cases list view in Iris UI shows cases #10, #11, #12, #13 all rendering clean em-dashes — `[ALERT #50] Test-Brute-Force-External-Spoofed — high`. The bug does **not** reproduce in current state with the as-shipped JSON (`JSON/SOC-Triage-v2.json`'s `Build Escalate Body` Code node uses a `—` JS escape, which resolves to U+2014 at runtime and survives the HTTP transit cleanly).

**No source change was made.** The Phase 11 observation may have been a transient display issue, a misread of glyphs, or a UI surface that has since rendered differently. The historical observation is preserved in [[notes]] so that if the bug recurs, future debugging can compare against it.

**Generalized rule (still good practice, originally captured for `Extract Triage Result` in [[notes]] under "Phase 3 Code node — Unicode encoding lesson"):** in any n8n Code node whose output will travel over HTTP to a downstream system, prefer ASCII characters in user-visible string templates *or* JS Unicode escapes (`—`) over raw Unicode literals. This is primarily about clipboard-paste hygiene — the literal characters can mojibake on paste through some clipboard pathways into n8n's Code editor, while JS escapes are pure ASCII bytes and survive any clipboard. Runtime output then resolves to the intended codepoint.

## Known limitations (deferred, not blocking)

- **Wait node returns JSON `{"message":"Workflow was started"}` to the analyst's browser**, not the configured HTML confirmation page. n8n's Wait node ignores `responseData`/`responseHeaders` for resume-webhook responses in this version. Acceptable: the Slack thread reply is the authoritative outcome surface; the JSON page is visible for ~1 second before the tab is closed.
- **Slack flags URL buttons with a benign "This app is not configured to handle interactive responses" warning**. URL buttons work fine — Slack only sends a callback if interactivity is configured, which we don't use. Eliminating the warning would require switching to mrkdwn link sections (less visually styled buttons). A2.5 may revisit.
- **Anyone with the signed resume URL on the LAN can approve.** Slack message itself is the access-control surface — only `#alerts` channel members see the URL. Mitigated by the signed-token requirement (Phase 6 finding); fully addressed by A2.5 (signed Slack interactivity behind a public tunnel).
- **30-minute timeout is wall-clock, not business-hours.** An alert that fires at 03:00 will time out by 03:30 unsupervised. Out of scope for A2.
- **No alert deduplication.** Two Splunk firings of the same condition produce two Iris alerts and two Slack approval prompts. Acceptable lab behavior.
- **n8n restart during a paused Wait kills that execution.** The corresponding Iris alert remains in the queue with no Slack thread reply — operational silence. Run a `cd ~/n8n && docker-compose restart n8n` only when no Slack approval is pending (check `#alerts` for unread thread-less posts).
- **A1 limitations carried forward:** `investigation_notes` sometimes-omitted (fallback in place); Splunk URL hostname patch hardcoded; AbuseIPDB inline key in legacy export JSON. None blocking.

## Operational gotchas to remember

These are A2-discovered patterns the next sub-project (A3+) will hit again. Captured here in priority order; full context for each is in [[notes]].

1. **Iris severity IDs are non-linear and deployment-specific.** A1's mapping was wrong (`{low: 2, medium: 3, ...}`); A2's correction (`{low: 4, medium: 1, high: 5, critical: 6}`) is verified against the live catalog at [[../../architecture/components/dfir-iris]]. Re-capture if Iris is upgraded.
2. **n8n HTTP Request bodies with non-string types (arrays, objects, booleans, numbers) need the Code-node-builds-body + Raw-HTTP-body pattern.** Don't use "Using JSON" with `{{ }}` substitution (silently quote-wraps arrays) or "Using Fields Below" (silently nulls arrays). The Code node is debuggable (output panel shows the constructed body) and bypasses n8n's body-field validation/stringification entirely. See the `Build Escalate Body` node for the canonical example.
3. **Wait node webhooks require the signed `signature` query param.** Manual URL construction (`http://.../webhook-waiting/{exec_id}?decision=...`) returns `{"error": "Invalid token"}`. Always use `{{ $execution.resumeUrl }}` (which n8n populates with the full signed URL during expression resolution, even in nodes before the Wait).
4. **Wait timeout doesn't set a `timedOut` field; the Switch's fallback branch is the timeout-detection mechanism.** On timeout, the upstream item passes through unchanged. The `Decision?` Switch routes anything-not-`approve`-or-`deny` (including undefined query.decision) to the timeout reply.
5. **Splunk saved-search SPL with `eval` clauses must be edited in the Search & Reporting bar and "Save As Alert".** Editing an existing saved search via Settings silently strips post-stats modifications. The `Test-Brute-Force-External-Spoofed` alert (created via Save As) is the working pattern.
6. **n8n Slack node's `Message Type: Blocks` field is a UI-only feature in this version.** It accepts JSON without complaint but doesn't translate it to a `blocks` API payload — Slack receives a text-only message. Use HTTP Request to `chat.postMessage` directly (Branch B).
7. **n8n IF nodes default to strict type validation.** Trailing whitespace in expression fields (e.g., a newline after `}}`) coerces a numeric result to a string and fails strict comparison. Click into the field after pasting and verify it ends at `}}` with nothing after.
8. **Cross-graph expressions:** `$json.field` resolves to the **immediate** upstream node's output, not the source node. Once you insert nodes between source and consumer, switch to `$('Source Node').item.json.field`.
