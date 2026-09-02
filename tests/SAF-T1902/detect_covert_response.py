#!/usr/bin/env python3
"""Detect synthetic covert response carriers in JSONL audit events.

The analytic is intentionally narrow: it recognizes suspicious encoded response
URLs only when a matching same-session network request follows within 120
seconds, and it recognizes Unicode tag runs outside a well-formed emoji tag
sequence. It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit


URL_RE = re.compile(r"https?://[^\s\]\[()<>\"']+")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{24,}")
TAG_RE = re.compile(r"[\U000E0020-\U000E007F]")
VALID_EMOJI_TAG_RE = re.compile(
    r"\U0001F3F4[\U000E0030-\U000E0039\U000E0061-\U000E007A]+\U000E007F"
)
DEFAULT_ALLOWLIST = {"cdn.example.invalid"}
CORRELATION_SECONDS = 120


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = host
    if port and not ((parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def candidate_tokens(url: str) -> Iterable[str]:
    parsed = urlsplit(url)
    for segment in parsed.path.split("/"):
        yield unquote(segment)
    for _name, value in parse_qsl(parsed.query, keep_blank_values=True):
        yield unquote(value)


def suspicious_url(url: str, allowlist: set[str]) -> bool:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host or host in allowlist:
        return False
    for candidate in candidate_tokens(url):
        for token in TOKEN_RE.findall(candidate):
            if entropy(token) >= 3.2:
                return True
    return False


def unexplained_tag_count(text: str) -> int:
    remaining = VALID_EMOJI_TAG_RE.sub("", text)
    return len(TAG_RE.findall(remaining))


def analyze(events: list[dict[str, Any]], allowlist: set[str] | None = None) -> list[dict[str, Any]]:
    allowed = set(DEFAULT_ALLOWLIST if allowlist is None else allowlist)
    network_by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("event_type") == "network_request" and event.get("session_id"):
            network_by_session[str(event["session_id"])].append(event)

    alerts: list[dict[str, Any]] = []
    for event in events:
        if event.get("event_type") not in {"agent_response", "mcp_tool_result"}:
            continue
        session_id = event.get("session_id")
        timestamp = event.get("timestamp")
        text = event.get("response_text")
        if not isinstance(session_id, str) or not isinstance(timestamp, str) or not isinstance(text, str):
            continue

        tag_count = unexplained_tag_count(text)
        if tag_count >= 4:
            alerts.append(
                {
                    "case_id": event.get("case_id"),
                    "session_id": session_id,
                    "reason": "unexplained_unicode_tag_run",
                    "tag_count": tag_count,
                }
            )
            continue

        response_time = parse_time(timestamp)
        for response_url in URL_RE.findall(text):
            response_url = response_url.rstrip(".,;:")
            if not suspicious_url(response_url, allowed):
                continue
            response_canonical = canonical_url(response_url)
            for network in network_by_session.get(session_id, []):
                destination = network.get("destination_url")
                network_time_raw = network.get("timestamp")
                if not isinstance(destination, str) or not isinstance(network_time_raw, str):
                    continue
                delta = (parse_time(network_time_raw) - response_time).total_seconds()
                if (
                    network.get("auto_fetched") is True
                    and 0 <= delta <= CORRELATION_SECONDS
                    and canonical_url(destination) == response_canonical
                ):
                    alerts.append(
                        {
                            "case_id": event.get("case_id"),
                            "session_id": session_id,
                            "reason": "encoded_response_url_followed_by_fetch",
                            "destination": response_canonical,
                            "delta_seconds": int(delta),
                        }
                    )
                    break
    return alerts


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"line {line_number} is not a JSON object")
        events.append(record)
    return events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("events", type=Path)
    args = parser.parse_args()
    events = load_events(args.events)
    alerts = analyze(events)
    print(json.dumps({"alerts": alerts, "alert_count": len(alerts)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
