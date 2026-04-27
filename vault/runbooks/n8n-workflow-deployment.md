---
status: active
updated: 2026-04-27
related: [[architecture/components/n8n]], [[workflows/soc-triage-pipeline]]
---

# n8n Workflow Deployment

How to back up, modify, and restore n8n workflows.

## Exporting a workflow

From the n8n web UI:

1. Open the workflow
2. Three-dot menu → "Download"
3. Save the JSON to `f:\Claude_Code\SOC_Automation_Project\JSON\` with a descriptive name

## Importing a workflow

From the n8n web UI:

1. Workflows list → "Add Workflow" → "Import from File"
2. Select the JSON
3. Re-attach credentials (they don't transfer with JSON exports — just the IDs do)

## Versioning

n8n has internal version history per workflow. For external versioning, save exports to `JSON/` with a date suffix or use git on the project folder once it's a repo.

## Editing workflows

Two safe approaches:

**A. Direct in the UI** — fastest for small changes. Always export afterwards.

**B. Edit JSON locally, re-import** — better for larger refactors. Lets you diff in your editor. Re-importing replaces the entire workflow; existing executions remain in history but new runs use the new definition.

## Credentials

Credentials in n8n are stored encrypted in the n8n_data volume on the n8n VM. They do **not** travel with workflow JSON exports — only credential IDs do. After importing a workflow on a fresh n8n instance, you must recreate every credential and rewire each node.

## Webhook URLs

Test webhooks (`/webhook-test/<id>`) are listening only when "Listen for test event" is active in the editor. Production webhooks (`/webhook/<id>`) are always live when the workflow is active. The Splunk alert is currently configured to hit the test URL — change to production URL once stable.
