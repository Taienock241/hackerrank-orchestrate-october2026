# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.

## Implemented agent

The submitted implementation is in `code/main.py` and uses only the Python
standard library. Its default mode is deterministic; optional Gemini evidence
review is available through `--ai` and `code/gemini_review.py`. The agent:

1. resolves current and historical identifiers from the identity snapshot and
   audit log;
2. reads participant-visible text and SQL evidence and the evidence manifest;
3. ignores evidence captured after each case's `audit_at`;
4. links identifiers to resource IDs and systems, recognizes residual PII,
   anonymized/redacted/absent records, active data flows, and restore risks;
5. applies `deletion_rules.csv` to choose deterministic remediation and
   verification operations; and
6. optionally asks Gemini to classify retrieved ambiguous evidence in AI mode; and
7. writes the exact `case_id,deletion_status,steps_json` contract.

Unreadable images and PDFs are not used as proof of completion. This keeps a
clean run reproducible without credentials or external services.

Use these Windows commands from the repository root:

```powershell
python .\code\main.py --requests .\dataset\deletion_requests.csv --output .\output.csv
python .\code\evaluation\main.py --output .\output.csv --requests .\dataset\deletion_requests.csv
```

The public sample can be evaluated separately:

```powershell
python .\code\main.py --requests .\dataset\sample_deletion_requests.csv --output .\sample_generated.csv
python .\code\evaluation\main.py --output .\sample_generated.csv --requests .\dataset\sample_deletion_requests.csv --sample-expected .\dataset\sample_output.csv
```

## Optional Gemini evidence review

The default run is local and makes no model calls. Temporary Gemini HTTP 503
capacity errors are retried twice with a short backoff. To enable Gemini, create an
API key in [Google AI Studio](https://aistudio.google.com/apikey) and choose a
model enabled for that key. The integration uses Gemini's `generateContent`
REST endpoint and forced function-call schema; no extra Python package is required.
See Google's [API key guide](https://ai.google.dev/gemini-api/docs/api-key),
[Generate Content API](https://ai.google.dev/api/generate-content), and
[function calling guide](https://ai.google.dev/gemini-api/docs/generate-content/function-calling).

From PowerShell at the repository root, create the local settings file and
edit it with the replacement key and a model ID enabled for your account:

```powershell
Copy-Item .env.example .env
notepad .env
```

The repository ignores `.env`, and the program loads it automatically. It is
still a plain-text file on your computer; use Windows user-level environment
variables instead if you do not want the key stored in the project folder.
Never use the key pasted into chat; revoke it and put the replacement in `.env`.

Start with the 32 public sample cases. The AI call limit caps the number of
evidence-bearing requests reviewed by Gemini:

```powershell
python .\code\main.py --dataset .\dataset --requests .\dataset\sample_deletion_requests.csv --output .\sample_generated.csv --ai --ai-limit 32
python .\code\evaluation\main.py --output .\sample_generated.csv --requests .\dataset\sample_deletion_requests.csv --sample-expected .\dataset\sample_output.csv
```

After reviewing the sample and your available API quota/budget, run all requests
with `--ai --ai-limit 518`. This can make up to 518 model calls. The program
sends request text and up to 40 retrieved evidence excerpts per reviewed request
to Google; excerpts can contain identifiers from the challenge dataset. Python
still validates the model's evidence indices and preserves directly parsed
states. Do not use this mode if the dataset must not be sent to an external API.

For estimated costs in `code/evaluation/usage_report.md`, set the model-specific
rates from [Google's current pricing page](https://ai.google.dev/gemini-api/docs/pricing)
before the full run. Values are USD per million tokens. Review the data-use terms
for your API tier: Google's pricing page says free-tier content may be used to
improve products, while paid-tier content is not used for that purpose.

```powershell
$env:GEMINI_INPUT_USD_PER_MTOK = Read-Host "Input rate per million tokens"
$env:GEMINI_OUTPUT_USD_PER_MTOK = Read-Host "Output rate per million tokens"
```

Never commit the API key or place it in prompts, source files, or `log.txt`.

## Packaging

Create the HackerRank archive without the dataset or generated output:

```powershell
Compress-Archive -Path .\README.md, .\.env.example, .\code -DestinationPath .\code.zip -Force
```

Inspect the archive before uploading and confirm it contains no `dataset`,
virtual environment, cache, nested archive, or secret files.


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md .env.example code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, .env.example, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.
