"""Local evaluation and contract checks.

Expected sample answers are read only by this evaluator; the production agent
never loads sample_output.csv.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


HEADER = ["case_id", "deletion_status", "steps_json"]
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


def load(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def validate_output(path: Path, requests_path: Path) -> list[str]:
    errors: list[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != HEADER:
            return [f"header must be {HEADER}, got {reader.fieldnames}"]
        rows = list(reader)
    requests = load(requests_path)
    expected_ids = sorted(row["case_id"] for row in requests)
    actual_ids = [row["case_id"] for row in rows]
    if len(rows) != len(requests):
        errors.append(f"row count {len(rows)} != request count {len(requests)}")
    if actual_ids != expected_ids:
        errors.append("case IDs are missing, duplicated, or not sorted")
    for row in rows:
        if row["deletion_status"] not in STATUSES:
            errors.append(f"invalid status for {row['case_id']}")
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            errors.append(f"invalid steps JSON for {row['case_id']}")
            continue
        if not isinstance(steps, list):
            errors.append(f"steps JSON is not an array for {row['case_id']}")
            continue
        if [step.get("step_no") for step in steps] != list(range(1, len(steps) + 1)):
            errors.append(f"step numbers are not consecutive for {row['case_id']}")
        for step in steps:
            required = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
            if set(step) != required:
                errors.append(f"step fields are invalid for {row['case_id']}")
                break
    return errors


def compare_sample(output_path: Path, sample_expected: Path) -> dict[str, float]:
    actual = {row["case_id"]: row for row in load(output_path)}
    expected = {row["case_id"]: row for row in load(sample_expected)}
    common = sorted(set(actual) & set(expected))
    status_matches = sum(actual[k]["deletion_status"] == expected[k]["deletion_status"] for k in common)
    exact_cases = 0
    sequence_matches = 0
    expected_fields = 0
    matching_fields = 0
    expected_steps = 0
    matching_steps = 0
    for case_id in common:
        actual_steps = json.loads(actual[case_id]["steps_json"])
        expected_steps_json = json.loads(expected[case_id]["steps_json"])
        if actual_steps == expected_steps_json:
            exact_cases += 1
        actual_ops = [
            (step.get("phase"), step.get("operation"), step.get("system_id"), step.get("resource_id"))
            for step in actual_steps
        ]
        expected_ops = [
            (step.get("phase"), step.get("operation"), step.get("system_id"), step.get("resource_id"))
            for step in expected_steps_json
        ]
        expected_steps += len(expected_steps_json)
        matching_steps += sum(
            left == right for left, right in zip(actual_steps, expected_steps_json)
        )
        sequence_matches += int(actual_ops == expected_ops)
        for actual_step, expected_step in zip(actual_steps, expected_steps_json):
            for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                expected_fields += 1
                matching_fields += int(actual_step.get(field) == expected_step.get(field))
    return {
        "cases": float(len(common)),
        "status_accuracy": status_matches / len(common) if common else 0.0,
        "case_exact_step_accuracy": exact_cases / len(common) if common else 0.0,
        "step_accuracy": matching_steps / expected_steps if expected_steps else 0.0,
        "field_accuracy": matching_fields / expected_fields if expected_fields else 0.0,
        "sequence_accuracy": sequence_matches / len(common) if common else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("output.csv"))
    parser.add_argument("--requests", type=Path, default=Path("dataset/deletion_requests.csv"))
    parser.add_argument("--sample-expected", type=Path)
    args = parser.parse_args()
    errors = validate_output(args.output, args.requests)
    print("contract:", "PASS" if not errors else "FAIL")
    for error in errors:
        print(" -", error)
    if args.sample_expected:
        print("sample:", json.dumps(compare_sample(args.output, args.sample_expected), sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())