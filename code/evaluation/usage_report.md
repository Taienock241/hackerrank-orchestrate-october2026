# Usage report

The last full-dataset run that produced the checked-in root `output.csv` used
deterministic mode, with no model calls. Separate sample smoke checks are listed
below and are not part of the full-dataset totals. One successful smoke check
used the current Gemini function-call adapter; another earlier check used the
replaced JSON-text adapter. Failed calls from user-run retries were not captured
by the runner's completed-run usage report.

## Last output run

- Model provider: none
- Model name: none
- Model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated total cost: $0
- Estimated cost per request: $0

## Separate sample smoke checks

- Current adapter: Google Gemini API, model `gemini-flash-latest`, 1 successful call, 471 input tokens, 27 output tokens (498 total); generated sample passed the output contract check.
- Earlier adapter: Google Gemini API, 1 successful call, 324 input tokens, 16 output tokens (340 total); generated sample passed the output contract check.
- These calls were not part of the full-dataset output run. Their cost was not calculated because model-specific rate settings were not recorded for those runs.


## Running with Gemini

Run the full dataset with `--ai --ai-limit 518` after setting `GEMINI_API_KEY`
and `GEMINI_MODEL`. The runner records actual API calls and token counts. Set
`GEMINI_INPUT_USD_PER_MTOK` and `GEMINI_OUTPUT_USD_PER_MTOK` to the selected
model's current rates to write an estimated cost into this report. Sample runs
do not replace the full-run usage report.
