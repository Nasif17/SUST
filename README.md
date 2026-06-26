# QueueStorm Investigator

FastAPI solution for the SUST CSE Carnival 2026 Codex Community Hackathon preliminary round. It now ships with a browser interface for trying the analyzer before deployment.

The required API endpoints remain:

- `GET /health`
- `POST /analyze-ticket`

Vercel-friendly aliases are also available:

- `GET /api/health`
- `POST /api/analyze-ticket`

## Quick Start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open:

- Interface: `http://localhost:8000/`
- Health: `http://localhost:8000/health`
- API docs: `http://localhost:8000/docs`

## Test

```bash
pytest
```

The tests run the public sample cases in `SUST_Preli_Sample_Cases.json` and verify the core judging fields, response shape, safety rules, UI serving, static assets, and `/api` aliases.

## API

### `GET /health`

Returns:

```json
{
  "status": "ok",
  "service": "queue-storm-investigator",
  "version": "1.0.0"
}
```

### `POST /analyze-ticket`

Required input fields:

- `ticket_id`
- `complaint`

Optional input fields:

- `language`
- `channel`
- `user_type`
- `campaign_context`
- `transaction_history`
- `metadata`

Returns the required fields:

- `ticket_id`
- `relevant_transaction_id`
- `evidence_verdict`
- `case_type`
- `severity`
- `department`
- `agent_summary`
- `recommended_next_action`
- `customer_reply`
- `human_review_required`
- `confidence`
- `reason_codes`

## Interface

The web UI is served from `public/` by the FastAPI app:

- `public/index.html`
- `public/styles.css`
- `public/app.js`

It loads sample tickets, validates transaction history JSON, calls the analyzer endpoint, shows route/severity/confidence, and displays the raw JSON response.

## Vercel Deployment

This repository includes Vercel configuration:

- `pyproject.toml` sets the ASGI entrypoint to `app.main:app`.
- `.python-version` pins Python `3.12`.
- `vercel.json` excludes tests, PDFs, cache files, and local server logs from the serverless bundle.
- `public/` contains the static interface assets.

Deploy with the Vercel dashboard or CLI from the repository root. After deployment, verify:

```text
https://your-project.vercel.app/
https://your-project.vercel.app/health
https://your-project.vercel.app/analyze-ticket
https://your-project.vercel.app/docs
```

## AI / Model Usage

This submission does not call an external AI model. It uses a deterministic rules-and-evidence engine in `app/analyzer.py`.

Why this choice:

- no API keys or secrets are required;
- no network dependency during judging;
- output is stable across repeated calls;
- evidence decisions can be explained through `agent_summary`, `recommended_next_action`, and `reason_codes`.

The analyzer detects the main hackathon case types:

- wrong transfer
- payment failed with possible balance deduction
- refund request
- duplicate payment
- merchant settlement delay
- agent cash-in issue
- phishing or social engineering
- other / insufficient detail

## Safety Logic

The customer reply is generated with guardrails:

- never asks for PIN, OTP, password, or full card details;
- does not promise refunds, reversals, or account unblock decisions;
- uses safe language such as `any eligible amount will be returned through official channels`;
- ignores adversarial instructions embedded inside the complaint text;
- asks for clarification when evidence is ambiguous instead of guessing a transaction.

## Evidence Reasoning

The analyzer compares the complaint with `transaction_history` using:

- mentioned transaction IDs;
- amount matches, including Bangla digits;
- expected transaction type and status;
- counterparty references;
- duplicate payment timing;
- repeated-recipient patterns for suspicious wrong-transfer claims;
- ambiguity detection when multiple transactions can match one complaint.

`evidence_verdict` values:

- `consistent`: complaint aligns with transaction evidence;
- `inconsistent`: a likely transaction exists, but evidence contradicts part of the claim;
- `insufficient_data`: the service cannot identify a safe, specific transaction.

## Limitations

- This is a deterministic hackathon implementation, not a production fraud decision system.
- It uses synthetic sample-style transaction data only.
- Bangla support covers the provided case style and common keywords, but it is not full natural-language understanding.
- Final refund, reversal, account action, and fraud outcomes must be approved by authorized internal workflows.
