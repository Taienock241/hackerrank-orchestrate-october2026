# Evaluation report

## Full dataset contract

The agent was run on all 518 rows in `dataset/deletion_requests.csv` and its generated `output.csv` was checked for the required header, row count, sorted unique case IDs, allowed status values, valid JSON arrays, consecutive step numbers, and required step fields. All checks pass.

## Public sample comparison

The production generator was run separately on `dataset/sample_deletion_requests.csv` and compared structurally with `dataset/sample_output.csv` (32 cases):

- Status accuracy: 31/32 (96.875%)
- Exact step-array accuracy: 8/32 (25%)
- Step accuracy by position: 48.70%
- Field accuracy across aligned steps: 80.98%
- Exact operation/resource sequence accuracy: 8/32 (25%)

These metrics compare against the public sample and do not establish hidden-evaluation performance. The remaining status mismatch is case_04: available evidence does not link an account resource to the requester, so the agent does not infer a resource ID from the case number.

The sample may include screenshots or PDF evidence that the standard-library-only production runtime cannot extract. Such artifacts are not silently treated as proof.
