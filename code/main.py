"""Evidence-grounded deletion audit agent with optional Gemini evidence review.

The default path is deterministic. The --ai option asks Gemini to interpret
retrieved, identity-linked evidence; local policy and output validation remain in Python.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from gemini_review import GeminiEvidenceReviewer


STATUS_VALUES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
TEXT_SUFFIXES = {".json", ".log", ".sql", ".txt", ".csv"}
RESOURCE_RE = re.compile(
    r"\b(account|search|support|export|analytics|data_flow|backup|"
    r"audit_record|tombstone|marketing|cache|object|email_delivery)_\d+\b"
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", re.IGNORECASE)
USER_RE = re.compile(r"\buser_[A-Za-z0-9-]+\b", re.IGNORECASE)
TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b")

SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "search": "search_service",
    "support": "support_platform",
    "export": "export_service",
    "analytics": "analytics_platform",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "marketing": "marketing_platform",
    "cache": "cache_service",
    "object": "object_storage",
    "email_delivery": "email_delivery_service",
}

OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

ACTION_FOR_PREFIX = {
    "account": "DELETE_RECORD",
    "search": "DELETE_RECORD",
    "support": "REDACT_RECORD",
    "export": "DELETE_RECORD",
    "analytics": "ANONYMIZE_RECORD",
    "marketing": "DELETE_RECORD",
    "email_delivery": "REDACT_RECORD",
    "cache": "DELETE_RECORD",
    "tombstone": "REDACT_RECORD",
    "object": "DELETE_RECORD",
}

VERIFY_FOR_ACTION = {
    "DELETE_RECORD": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT_RECORD": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE_RECORD": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
}


def parse_time(value: str) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def normalize(value: str) -> str:
    return " ".join((value or "").casefold().split())


def request_authorizes_deletion(text: str) -> bool:
    lowered = normalize(text)
    non_deletion = (
        "access request",
        "access my data",
        "information request",
        "not a request to erase",
        "not asking for deletion",
        "not asking for erasure",
        "correct my",
        "correction",
        "misspelled",
        "resetting the login",
        "export my data",
        "unsubscribe",
        "do not sell",
        "no destructive action",
        "still need the account",
        "still want the account",
    )
    if any(term in lowered for term in non_deletion):
        return False
    # Negation must be considered before keyword matching: phrases such as
    # "don't delete" and "without removing records" are not authorizations.
    if re.search(
        r"\b(?:not|never|don't|dont|do not|doesn't|does not|without)\b"
        r".{0,60}\b(?:delet\w*|eras\w*|remov\w*|purge\w*|clos\w*)",
        lowered,
    ):
        return False
    if re.search(r"\b(?:marketing|promotional|promotions|advertising)\b.{0,50}\bonly\b", lowered):
        return False
    if re.search(r"\b(?:only|just)\b.{0,50}\b(?:marketing|promotional|promotions|advertising)\b", lowered):
        return False
    deletion_terms = (
        "delet",
        "eras",
        "remov",
        "purge",
        "close my account",
        "delete my account",
        "supprim",
        "suppression",
        "elimin",
        "borrar",
        "close the account",
        "close this account",
        "profile is gone",
        "削除",
        "删除",
        "удал",
    )
    return any(term in lowered for term in deletion_terms)


def extract_log_trace_id(line: str) -> str | None:
    """Extract a trace/request identifier from common structured log formats."""
    patterns = (
        r"\b(?:trace_id|requestId)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9][A-Za-z0-9._-]{3,})",
        r"\|\s*((?:tr|rb)-[A-Za-z0-9._-]+)\s*\|",
        r"\b((?:tr|rb)-[A-Za-z0-9._-]+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def resource_parts(resource_id: str) -> tuple[str, str]:
    prefix = next(
        (candidate for candidate in SYSTEM_BY_PREFIX if resource_id.startswith(candidate + "_")),
        resource_id.split("_", 1)[0],
    )
    return SYSTEM_BY_PREFIX.get(prefix, "unknown_system"), prefix


@dataclass(frozen=True)
class EvidenceHit:
    file_id: str
    captured_at: dt.datetime | None
    resource_id: str
    system_id: str
    line: str
    line_no: int
    present: bool
    exposed: bool
    anonymized: bool
    redacted: bool
    absent: bool
    active_flow: bool
    restore_risk: bool



class AuditIndex:
    def __init__(self, dataset: Path) -> None:
        self.dataset = dataset
        self.identities = read_csv(dataset / "user_identities.csv")
        self.audit_log = read_csv(dataset / "user_audit_log.csv")
        self.manifest = read_csv(dataset / "evidence_files.csv")
        self.activities = read_csv(dataset / "system_activity.csv")
        self.values_by_user: dict[str, set[str]] = defaultdict(set)
        self.users_by_identifier: dict[str, set[str]] = defaultdict(set)
        self._build_identity_index()
        self.evidence_lines: list[tuple[str, dt.datetime | None, str, int, str]] = []
        self.sql_snapshots: list[tuple[str, dt.datetime | None, str]] = []
        self._load_evidence()
        self.activity_links: dict[str, list[tuple[str, str, dt.datetime | None]]] = defaultdict(list)
        self._load_activity_links()

    def _add_identifier(self, user_id: str, value: str) -> None:
        normalized = normalize(value)
        if normalized:
            self.values_by_user[user_id].add(normalized)
            self.users_by_identifier[normalized].add(user_id)

    def _build_identity_index(self) -> None:
        for row in self.identities:
            user_id = row.get("user_id", "").strip()
            if not user_id:
                continue
            self._add_identifier(user_id, user_id)
            for field in ("email", "name", "phone", "email_hash"):
                self._add_identifier(user_id, row.get(field, ""))
        for row in self.audit_log:
            user_id = row.get("user_id", "").strip()
            if not user_id:
                continue
            self._add_identifier(user_id, user_id)
            for field in ("old_value", "new_value"):
                self._add_identifier(user_id, row.get(field, ""))

    def resolve_user(self, email: str) -> str | None:
        candidates = self.users_by_identifier.get(normalize(email), set())
        return next(iter(candidates)) if len(candidates) == 1 else None

    @staticmethod
    def _json_resource_objects(value: object) -> list[dict[str, object]]:
        found: list[dict[str, object]] = []
        if isinstance(value, dict):
            if any(key in value for key in ("resource_id", "resourceId")):
                found.append(value)
            else:
                for child in value.values():
                    found.extend(AuditIndex._json_resource_objects(child))
        elif isinstance(value, list):
            for child in value:
                found.extend(AuditIndex._json_resource_objects(child))
        return found

    def _load_evidence(self) -> None:
        for manifest_row in self.manifest:
            raw_path = manifest_row.get("file_path", "").replace("\\", "/")
            path = self.dataset / raw_path
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            captured = parse_time(manifest_row.get("captured_at", ""))
            file_id = manifest_row.get("file_id", "")
            suffix = path.suffix.casefold()
            if suffix == ".sql":
                self.sql_snapshots.append((file_id, captured, content))
            units: list[str] = []
            if suffix == ".json":
                try:
                    parsed = json.loads(content)
                    units = [
                        json.dumps(obj, ensure_ascii=False, sort_keys=True)
                        for obj in self._json_resource_objects(parsed)
                    ]
                except (json.JSONDecodeError, TypeError):
                    units = []
            if not units:
                if suffix == ".log":
                    trace_groups: dict[str, list[str]] = defaultdict(list)
                    ungrouped: list[str] = []
                    for line in content.splitlines():
                        trace_id = extract_log_trace_id(line)
                        if trace_id:
                            trace_groups[trace_id].append(line)
                        elif RESOURCE_RE.search(line):
                            ungrouped.append(line)
                    units = ungrouped + [
                        "\n".join(lines) for lines in trace_groups.values()
                        if any(RESOURCE_RE.search(line) for line in lines)
                    ]
                elif suffix in {".sql", ".csv", ".txt"}:
                    units = [
                        line for line in content.splitlines()
                        if RESOURCE_RE.search(line)
                    ]
                else:
                    units = [
                        block for block in re.split(r"\n\s*\n", content)
                        if RESOURCE_RE.search(block)
                    ]
            for line_no, unit in enumerate(units, 1):
                self.evidence_lines.append((file_id, captured, unit, line_no, path.name))

    @staticmethod
    def _matches_identifier(text: str, identifier: str) -> bool:
        value = normalize(identifier)
        if len(value) < 4:
            return False
        normalized_text = normalize(text)
        if value.startswith("user_"):
            return re.search(r"(?<![A-Za-z0-9_])" + re.escape(value) + r"(?![A-Za-z0-9_])", normalized_text) is not None
        if "@" in value or re.fullmatch(r"[0-9a-f]{32,}", value):
            return value in normalized_text
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 8 and len(value) < 30:
            text_digits = re.sub(r"\D", "", text)
            return digits in text_digits
        pattern = r"(?<![A-Za-z0-9])" + re.escape(value).replace(r"\ ", r"\s+") + r"(?![A-Za-z0-9])"
        return re.search(pattern, normalized_text) is not None

    def _load_activity_links(self) -> None:
        for row in self.activities:
            if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
                continue
            detail = row.get("details", "")
            identifiers = [normalize(x) for x in EMAIL_RE.findall(detail)]
            identifiers += [normalize(x) for x in USER_RE.findall(detail)]
            resource_ids = {row.get("resource_id", "")}
            resource_ids.update(match.group(0) for match in RESOURCE_RE.finditer(detail))
            for identifier in identifiers:
                candidates = self.users_by_identifier.get(identifier, set())
                linked_users = candidates if len(candidates) == 1 else {identifier}
                for linked_user in linked_users:
                    for resource_id in resource_ids:
                        if resource_id:
                            self.activity_links[linked_user].append(
                                (resource_id, row.get("activity_id", ""), parse_time(row.get("event_time", "")))
                            )

    def identifiers_for(self, user_id: str | None) -> set[str]:
        if not user_id:
            return set()
        return {value for value in self.values_by_user.get(user_id, set()) if len(value) >= 4}

    def hits_for(
        self,
        user_id: str | None,
        audit_at: dt.datetime | None,
        request_text: str = "",
    ) -> list[EvidenceHit]:
        identifiers = self.identifiers_for(user_id)
        if not identifiers:
            return []
        direct_units = []
        anchors: dict[str, list[dt.datetime]] = defaultdict(list)
        for item in self.evidence_lines:
            file_id, captured, unit, _line_no, _source_name = item
            if audit_at and captured and captured > audit_at:
                continue
            if any(self._matches_identifier(unit, identifier) for identifier in identifiers):
                direct_units.append(item)
                timestamp_match = TIMESTAMP_RE.search(unit)
                event_time = parse_time(timestamp_match.group(0)) if timestamp_match else captured
                if event_time:
                    anchors[file_id].append(event_time)

        request_lower = normalize(request_text)
        flow_requested = bool(re.search(r"\b(sync|synchron|integration|connector|import|recreat|copy|send my data)\b", request_lower))
        restore_requested = bool(re.search(r"\b(backup|restore|archive)\b", request_lower))
        contextual_units: list[tuple[str, dt.datetime | None, str, int, str]] = []
        for item in self.evidence_lines:
            file_id, captured, unit, _line_no, _source_name = item
            if file_id not in anchors or (audit_at and captured and captured > audit_at):
                continue
            if any(self._matches_identifier(unit, identifier) for identifier in identifiers):
                continue
            timestamp_match = TIMESTAMP_RE.search(unit)
            event_time = parse_time(timestamp_match.group(0)) if timestamp_match else captured
            if not event_time or not any(abs((event_time-anchor).total_seconds()) <= 15*60 for anchor in anchors[file_id]):
                continue
            resources = [match.group(0) for match in RESOURCE_RE.finditer(unit)]
            if flow_requested and any(resource.startswith("data_flow_") for resource in resources):
                contextual_units.append(item)
            elif restore_requested and any(resource.startswith("backup_") for resource in resources):
                contextual_units.append(item)
        latest_context: dict[tuple[str, str], tuple[str, dt.datetime | None, str, int, str]] = {}
        for item in contextual_units:
            file_id, captured, unit, _line_no, _source_name = item
            timestamp_match = TIMESTAMP_RE.search(unit)
            event_time = parse_time(timestamp_match.group(0)) if timestamp_match else captured
            for match in RESOURCE_RE.finditer(unit):
                resource_id = match.group(0)
                if not resource_id.startswith(("data_flow_", "backup_")):
                    continue
                key = (file_id, resource_id.split("_", 1)[0])
                previous = latest_context.get(key)
                previous_time = None
                if previous:
                    previous_match = TIMESTAMP_RE.search(previous[2])
                    previous_time = parse_time(previous_match.group(0)) if previous_match else previous[1]
                if previous is None or (event_time and (previous_time is None or event_time > previous_time)):
                    latest_context[key] = item

        selected_units = direct_units + list(latest_context.values())
        selected_keys = {(item[0], item[2], item[3]) for item in selected_units}
        hits: list[EvidenceHit] = []
        for file_id, captured, unit, line_no, _source_name in selected_units:
            matched = [identifier for identifier in identifiers if self._matches_identifier(unit, identifier)]
            resources = sorted(set(match.group(0) for match in RESOURCE_RE.finditer(unit)))
            for resource_id in resources:
                _, prefix = resource_parts(resource_id)
                nearby_lower = normalize(unit)
                semantic_text = nearby_lower.replace('"', '').replace("'", "")
                absent = bool(
                    re.search(
                        r"\b(rows?\s*=\s*0|404|result\s*=\s*miss|not[_ -]?found|absent)\b",
                        nearby_lower,
                    )
                )
                active_flow = prefix == "data_flow" and bool(
                    re.search(r"\b(enabled|active|registered)\s*[:=]\s*(true|yes|1)\b", semantic_text)
                    or (prefix == "data_flow" and re.search(r"\bINSERT\s+INTO\s+connector_subscriptions\b.*?,\s*'1'\s*,", unit, re.IGNORECASE))
                )
                restore_allowed = bool(
                    re.search(r"\b(eligible|can[_ -]?restore|restore[_ -]?allowed)\s*[:=]\s*(true|yes|1)\b", semantic_text)
                    or (prefix == "backup" and re.search(r"archive[^,]*,\s*'1'\s*,", unit, re.IGNORECASE))
                )
                restore_blocked = bool(
                    re.search(r"\b(deletion[_ -]?block|restore[_ -]?allowed)\s*[:=]\s*(false|no|0)\b", semantic_text)
                    or (prefix == "backup" and re.search(r"archive[^,]*,\s*'0'\s*,", unit, re.IGNORECASE))
                )
                restore_risk = prefix == "backup" and (
                    (restore_allowed and not restore_blocked)
                    or bool(re.search(r"\b(status|state)\s*[:=|]\s*active\b|\bBACKUP_ARCHIVE\s*\|\s*ACTIVE\b", unit, re.IGNORECASE))
                )
                direct_value_present = any(
                    self._matches_identifier(unit, identifier)
                    for identifier in matched
                    if "@" in identifier
                    or re.fullmatch(r"[0-9a-f]{32,}", identifier)
                    or len(re.sub(r"\D", "", identifier)) >= 8
                )
                anonymized = (
                    "anonym" in semantic_text
                    or bool(re.search(r"\b(attributable|linkable)\s*[:=]\s*(false|no)\b", semantic_text))
                ) and not direct_value_present
                redacted = (
                    "redact" in semantic_text
                    or bool(re.search(r"\b(direct_identifiers?|email|phone|email_hash)\s*[:=]\s*(null|none|removed)\b", semantic_text))
                ) and not direct_value_present
                exposed = not absent and not anonymized and not redacted and direct_value_present
                present = not absent and (exposed or prefix in {"audit_record", "backup", "data_flow"})
                hits.append(
                    EvidenceHit(
                        file_id,
                        captured,
                        resource_id,
                        resource_parts(resource_id)[0],
                        unit,
                        line_no,
                        present,
                        exposed,
                        anonymized,
                        redacted,
                        absent,
                        active_flow,
                        restore_risk,
                    )
                )
        return hits

    def linked_resources(
        self, user_id: str | None, audit_at: dt.datetime | None
    ) -> list[tuple[str, str]]:
        if not user_id:
            return []
        return [
            (resource, evidence_id)
            for resource, evidence_id, when in self.activity_links.get(user_id, [])
            if not audit_at or not when or when <= audit_at
        ]

    def account_activity_near_reported_at(
        self, reported_at: dt.datetime | None, audit_at: dt.datetime | None, window_minutes: int = 15
    ) -> tuple[str, str] | None:
        if not reported_at:
            return None
        candidates = []
        for row in self.activities:
            if row.get("event_type") != "DELETE_RECORD":
                continue
            resource_id = row.get("resource_id", "")
            when = parse_time(row.get("event_time", ""))
            if not resource_id.startswith("account_") or not when:
                continue
            if audit_at and when > audit_at:
                continue
            delta = abs((when - reported_at).total_seconds())
            if delta <= window_minutes * 60:
                candidates.append((delta, resource_id, row.get("activity_id", "")))
        if not candidates:
            return None
        candidates.sort()
        if len(candidates) > 1 and abs(candidates[0][0] - candidates[1][0]) < 30:
            return None
        return candidates[0][1], candidates[0][2]

    def absent_snapshot_proof(
        self, resource_id: str, audit_at: dt.datetime | None
    ) -> EvidenceHit | None:
        prefix = resource_id.split("_", 1)[0]
        table_patterns = {
            "account": r"customer_profiles|customer_accounts",
        }
        table_pattern = table_patterns.get(prefix)
        if not table_pattern:
            return None
        eligible = [
            item for item in self.sql_snapshots
            if (not audit_at or not item[1] or item[1] <= audit_at)
            and re.search(r"CREATE\s+TABLE\s+[^;]*?(" + table_pattern + r")", item[2], re.IGNORECASE)
        ]
        if not eligible:
            return None
        file_id, captured, content = max(
            eligible,
            key=lambda item: item[1] or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
        )
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(resource_id) + r"(?![A-Za-z0-9_])", content):
            return None
        return EvidenceHit(
            file_id, captured, resource_id, resource_parts(resource_id)[0],
            "complete SQL snapshot contains no row for this resource", 0,
            False, False, False, False, True, False, False,
        )

    def activity_candidates(
        self,
        requested_at: dt.datetime | None,
        audit_at: dt.datetime | None,
        identifiers: set[str],
        window_hours: int = 24,
        limit: int = 12,
    ) -> list[EvidenceHit]:
        if not requested_at or not identifiers:
            return []
        candidates: list[EvidenceHit] = []
        for row in self.activities:
            when = parse_time(row.get("event_time", ""))
            if not when or abs((when - requested_at).total_seconds()) > window_hours * 3600:
                continue
            if audit_at and when > audit_at:
                continue
            details = row.get("details", "")
            if not any(self._matches_identifier(details, identifier) for identifier in identifiers):
                continue
            event_type = row.get("event_type", "")
            result = row.get("reported_result", "")
            resource_id = row.get("resource_id", "")
            if not resource_id:
                continue
            system_id, prefix = resource_parts(resource_id)
            failed = result in {"FAILED", "PARTIAL"}
            active_flow = event_type == "CHECK_DATA_FLOW" and bool(
                re.search(r"\b(enabled|active|registered)\b", normalize(details))
            )
            restore_risk = event_type == "CHECK_RESTORE_ACCESS" and bool(
                re.search(r"\b(can still be restored|can be restored|eligible=true)\b", normalize(details))
            )
            if event_type == "RESTORE_BACKUP":
                restore_risk = True
            residual = failed and prefix in ACTION_FOR_PREFIX
            downstream_copy = event_type in {"SYNC_RECORD", "INDEX_RECORD", "CREATE_EXPORT"} and failed
            if not (active_flow or restore_risk or residual or downstream_copy):
                continue
            candidates.append(
                EvidenceHit(
                    row.get("activity_id", ""),
                    when,
                    resource_id,
                    system_id,
                    details,
                    0,
                    residual or downstream_copy,
                    event_type in {"REDACT_RECORD", "ANONYMIZE_RECORD"} and failed,
                    False,
                    False,
                    False,
                    active_flow,
                    restore_risk,
                )
            )
        candidates.sort(
            key=lambda hit: (
                abs((hit.captured_at - requested_at).total_seconds()) if hit.captured_at else float("inf"),
                hit.resource_id,
            )
        )
        return candidates[:limit]

def evidence_id_for(hits: Iterable[EvidenceHit]) -> str:
    ordered = sorted(
        hits,
        key=lambda hit: (
            hit.captured_at or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
            hit.file_id,
            hit.line_no,
        ),
        reverse=True,
    )
    return ordered[0].file_id if ordered else ""


def make_step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, object]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def audit_case(
    row: dict[str, str],
    index: AuditIndex,
    reviewer: GeminiEvidenceReviewer | None = None,
) -> tuple[str, list[dict[str, object]]]:
    if not request_authorizes_deletion(row.get("request_text", "")):
        return "NOT_APPLICABLE", []
    user_id = index.resolve_user(row.get("email", ""))
    audit_at = parse_time(row.get("audit_at", ""))
    hits = index.hits_for(user_id, audit_at, row.get("request_text", ""))
    reported_account = index.account_activity_near_reported_at(
        parse_time(row.get("reported_at", "")), audit_at
    )
    if reported_account and all(hit.resource_id != reported_account[0] for hit in hits):
        proof = index.absent_snapshot_proof(reported_account[0], audit_at)
        if proof:
            hits.append(proof)
    if not hits:
        requested_at = parse_time(row.get("requested_at", ""))
        hits = index.activity_candidates(requested_at, audit_at, index.identifiers_for(user_id))
        if not hits:
            hits = index.activity_candidates(requested_at, audit_at, index.identifiers_for(user_id), window_hours=72, limit=8)
    by_resource: dict[str, list[EvidenceHit]] = defaultdict(list)
    for hit in hits:
        by_resource[hit.resource_id].append(hit)
    for resource_id, activity_id in index.linked_resources(user_id, audit_at):
        system_id, prefix = resource_parts(resource_id)
        if resource_id not in by_resource:
            hits.append(
                EvidenceHit(
                    activity_id,
                    audit_at,
                    resource_id,
                    system_id,
                    "",
                    0,
                    prefix not in {"account", "search", "support", "export", "analytics", "marketing"},
                    prefix in {"account", "search", "support", "export", "analytics", "marketing"},
                    False,
                    False,
                    False,
                    prefix == "data_flow",
                    prefix == "backup",
                )
            )
            by_resource[resource_id].append(hits[-1])

    if reviewer is not None and hits:
        assessments = reviewer.assess(row.get("request_text", ""), row.get("audit_at", ""), hits)
        state_flags = {
            "RECORD_PRESENT": {"present": True},
            "PII_PRESENT": {"present": True, "exposed": True},
            "ABSENT": {"absent": True, "present": False, "exposed": False},
            "REDACTED": {"redacted": True, "present": False, "exposed": False},
            "ANONYMIZED": {"anonymized": True, "present": False, "exposed": False},
            "ACTIVE_DATA_FLOW": {"active_flow": True},
            "RESTORE_RISK": {"restore_risk": True},
        }
        reviewed_hits = []
        for hit_index, hit in enumerate(hits):
            state = assessments.get(hit_index, "UNCERTAIN")
            explicit_record_state = any((
                hit.present, hit.exposed, hit.anonymized, hit.redacted, hit.absent,
            ))
            flags = state_flags.get(state, {})
            # Keep parsed record states; allow Gemini to add a process risk because
            # a record may be present and also exposed to sync or restore.
            if state == "ACTIVE_DATA_FLOW" and not hit.active_flow:
                reviewed_hits.append(replace(hit, active_flow=True))
            elif state == "RESTORE_RISK" and not hit.restore_risk:
                reviewed_hits.append(replace(hit, restore_risk=True))
            elif flags and not explicit_record_state and state not in {"ACTIVE_DATA_FLOW", "RESTORE_RISK"}:
                reviewed_hits.append(replace(hit, **flags))
            else:
                reviewed_hits.append(hit)
        hits = reviewed_hits
        by_resource = defaultdict(list)
        for hit in hits:
            by_resource[hit.resource_id].append(hit)

    findings: list[dict[str, object]] = []
    remediation: list[dict[str, object]] = []
    verification: list[dict[str, object]] = []
    compliant_records: list[tuple[str, str, str, str, str]] = []
    for resource_id, resource_hits in by_resource.items():
        system_id, prefix = resource_parts(resource_id)
        latest = sorted(
            resource_hits,
            key=lambda hit: (
                hit.captured_at or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
                hit.line_no,
            ),
            reverse=True,
        )
        if latest:
            latest_time = latest[0].captured_at
            latest = [hit for hit in latest if hit.captured_at == latest_time]
        evidence_id = evidence_id_for(latest or resource_hits)
        if any(hit.active_flow for hit in latest):
            findings.append(make_step("FINDING", system_id, resource_id, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evidence_id))
            remediation.append(make_step("REMEDIATION", system_id, resource_id, "DISABLE_DATA_FLOW", "DISABLED", ""))
            verification.append(make_step("VERIFICATION", system_id, resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
            continue
        if any(hit.restore_risk for hit in latest):
            findings.append(make_step("FINDING", system_id, resource_id, "REPORT_RESTORE_RISK", "ACTIVE", evidence_id))
            remediation.append(make_step("REMEDIATION", system_id, resource_id, "BLOCK_RESTORE", "BLOCKED", ""))
            verification.append(make_step("VERIFICATION", system_id, resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
            continue
        action = ACTION_FOR_PREFIX.get(prefix)
        resource_text = " ".join(hit.line for hit in latest).upper()
        if prefix == "support" and "SUPPORT_ATTACHMENT" in resource_text:
            action = "DELETE_RECORD"
        if not action:
            if prefix == "audit_record":
                compliant_records.append(
                    (system_id, resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id)
                )
            continue
        if any(hit.absent for hit in latest) and not any(hit.present for hit in latest):
            compliant_records.append(
                (system_id, resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id)
            )
            continue
        if any(hit.anonymized for hit in latest):
            compliant_records.append(
                (system_id, resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_id)
            )
            continue
        if any(hit.redacted for hit in latest):
            compliant_records.append(
                (system_id, resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", evidence_id)
            )
            continue
        if any(hit.exposed or hit.present for hit in latest):
            operation = "REPORT_EXPOSED_PII" if action != "DELETE_RECORD" else "REPORT_REMAINING_RECORD"
            findings.append(make_step("FINDING", system_id, resource_id, operation, "PRESENT", evidence_id))
            remediation_state = {
                "DELETE_RECORD": "ABSENT",
                "REDACT_RECORD": "REDACTED",
                "ANONYMIZE_RECORD": "ANONYMIZED",
            }[action]
            remediation.append(make_step("REMEDIATION", system_id, resource_id, action, remediation_state, ""))
            verify_operation, verify_state = VERIFY_FOR_ACTION[action]
            verification.append(make_step("VERIFICATION", system_id, resource_id, verify_operation, verify_state, ""))

    def order(step: dict[str, object]) -> tuple[int, int, str, str]:
        return (
            OPERATION_ORDER[str(step["operation"])],
            0,
            str(step["system_id"]),
            str(step["resource_id"]),
        )

    findings.sort(key=order)
    remediation.sort(key=order)
    verification_evidence = "" if findings else None
    verification.extend(
        make_step(
            "VERIFICATION",
            system_id,
            resource_id,
            operation,
            state,
            verification_evidence if verification_evidence is not None else evidence_id,
        )
        for system_id, resource_id, operation, state, evidence_id in compliant_records
    )
    verification.sort(key=order)
    all_steps = findings + remediation + verification
    for number, step in enumerate(all_steps, 1):
        step["step_no"] = number
    insufficient_evidence = not hits and not by_resource
    is_complete = not findings and not insufficient_evidence and bool(verification)
    return ("COMPLETE" if is_complete else "INCOMPLETE"), all_steps


def write_output(
    requests_path: Path,
    dataset: Path,
    output_path: Path,
    reviewer: GeminiEvidenceReviewer | None = None,
    ai_limit: int = 32,
) -> None:
    requests = read_csv(requests_path)
    index = AuditIndex(dataset)
    results = []
    for row in requests:
        active_reviewer = reviewer if reviewer and reviewer.calls < ai_limit else None
        status, steps = audit_case(row, index, active_reviewer)
        results.append(
            {
                "case_id": row.get("case_id", ""),
                "deletion_status": status,
                "steps_json": json.dumps(steps, ensure_ascii=True, separators=(",", ":")),
            }
        )
    results.sort(key=lambda row: row["case_id"])
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)
    if reviewer is not None:
        print(f"Gemini model: {reviewer.model}; API calls: {reviewer.calls}; "
              f"tokens: {reviewer.input_tokens} input, {reviewer.output_tokens} output")


def update_usage_report(path: Path, request_count: int, reviewer: GeminiEvidenceReviewer) -> None:
    input_rate = os.environ.get("GEMINI_INPUT_USD_PER_MTOK")
    output_rate = os.environ.get("GEMINI_OUTPUT_USD_PER_MTOK")
    if input_rate and output_rate:
        estimated_cost = (
            reviewer.input_tokens * float(input_rate)
            + reviewer.output_tokens * float(output_rate)
        ) / 1_000_000
        cost_text = f"${estimated_cost:.6f}"
        per_request = f"${estimated_cost / max(request_count, 1):.8f}"
        rates_text = f"${input_rate} / ${output_rate} per million input/output tokens"
    else:
        cost_text = "Not calculated (set model-specific rate environment variables)"
        per_request = "Not calculated"
        rates_text = "Not configured"
    path.write_text(
        "# Usage report\n\n"
        "Final full-dataset run with Gemini API.\n\n"
        f"- Provider: Google Gemini API\n- Model: {reviewer.model}\n"
        f"- Requests in dataset: {request_count}\n- Model calls: {reviewer.calls}\n"
        f"- Input tokens: {reviewer.input_tokens}\n- Output tokens: {reviewer.output_tokens}\n"
        f"- Total tokens: {reviewer.input_tokens + reviewer.output_tokens}\n"
        f"- Average tokens per request: {(reviewer.input_tokens + reviewer.output_tokens) / max(request_count, 1):.2f}\n"
        f"- Input/output rates: {rates_text}\n- Estimated total cost: {cost_text}\n"
        f"- Estimated cost per request: {per_request}\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Northstar Shop deletion audit.")
    parser.add_argument("--dataset", type=Path, default=Path("dataset"))
    parser.add_argument("--requests", type=Path)
    parser.add_argument("--output", type=Path, default=Path("output.csv"))
    parser.add_argument("--ai", action="store_true", help="Use Gemini to interpret retrieved evidence.")
    parser.add_argument("--ai-limit", type=int, default=32, help="Maximum Gemini API calls (default: 32).")
    args = parser.parse_args(argv)
    if args.ai_limit < 1:
        parser.error("--ai-limit must be at least 1")
    dataset = args.dataset
    requests = args.requests or (dataset / "deletion_requests.csv")
    reviewer = None
    if args.ai:
        from gemini_review import configured_reviewer
        try:
            reviewer = configured_reviewer()
        except ValueError as exc:
            parser.error(str(exc))
    write_output(requests, dataset, args.output, reviewer, args.ai_limit)
    if reviewer is not None and args.output.name == "output.csv" and len(read_csv(requests)) == 518:
        update_usage_report(Path("code/evaluation/usage_report.md"), 518, reviewer)
    return 0


if __name__ == "__main__":
    sys.exit(main())