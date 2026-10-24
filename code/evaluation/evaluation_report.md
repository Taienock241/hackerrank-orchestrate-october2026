# Evaluation report

## Deterministic baseline evaluation

The checked-in `output.csv` was generated without an API key, using the deterministic baseline. Its 518 rows pass checks for the required header, row count, sorted unique case IDs, allowed status values, valid JSON arrays, consecutive step numbers, and required step fields. There are no `INCOMPLETE` rows with empty step arrays.

## Public sample comparison

The deterministic generator was run on `dataset/sample_deletion_requests.csv` and compared structurally with `dataset/sample_output.csv` (32 cases):

- Status accuracy: 31/32 (96.875%)
- Exact step-array accuracy: 8/32 (25%)
- Step accuracy by position: 48.70%
- Field accuracy across aligned steps: 80.98%
- Exact operation/resource sequence accuracy: 8/32 (25%)

The one remaining status mismatch is case_04. The available evidence does not establish an attributable resource ID, so the agent does not infer one from the case number. These public sample scores do not guarantee hidden-evaluation performance.

## Added regression cases

`test_agent.py` adds 12 targeted cases: explicit deletion intent; negated deletion and account-close wording; correction without deletion; marketing-only and promotional-message requests; information/access requests; JSON, key-value, pipe-delimited, legacy `rb-`, and hyphenated trace identifiers. These protect the fixes for the previously empty incomplete rows.

## AI integration status

An optional Google Gemini API adapter is included in `code/gemini_review.py`. It classifies only retrieved candidate evidence, uses a forced Gemini function call with a fixed assessment schema, and cannot introduce new resource IDs. The current function-call response path completed a one-call sample smoke check (471 input and 27 output tokens) and the generated 32-row sample passed the CSV contract check. With `--ai-limit 1`, only one eligible sample case used Gemini; the rest used deterministic logic. The public sample scores above describe the deterministic baseline and do not show a full AI run. A prior JSON-text response path produced malformed JSON and was replaced; transient Gemini 503 responses now receive bounded retries.

## Failures and improvements

The original keyword-only intent check treated negated and limited requests as account deletion. The evidence reader also missed identity-to-resource links in JSON, request-ID, pipe-delimited, and legacy logs. Intent handling now checks non-deletion/negation language first; trace extraction supports those log formats. Six previously unlinked deletion cases now have evidence-derived steps, and six non-deletion cases now use `NOT_APPLICABLE` with an empty step array.

PDF and image OCR are still not implemented in the production runtime. Unreadable media is not treated as proof.
