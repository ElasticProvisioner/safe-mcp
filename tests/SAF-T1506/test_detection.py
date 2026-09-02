#!/Users/fkautz/anaconda3/bin/python3
import json
from pathlib import Path

PRIVATE = {"loopback", "private", "reserved", "link_local"}
PATH_MARKERS = (
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/latest/meta-data/",
    "/computeMetadata/v1/",
    "/metadata/identity/oauth2/token",
)


def detect(event):
    return bool(
        event.get("mcp.authorization_flow") is True
        and event.get("http.request.method") in {"GET", "POST"}
        and any(marker in event.get("url.path", "") for marker in PATH_MARKERS)
        and (
            event.get("destination.address_class") in PRIVATE
            or event.get("http.redirect.address_class") in PRIVATE
        )
    )


def main():
    fixture_path = Path(__file__).with_name("fixtures.jsonl")
    events = [json.loads(line) for line in fixture_path.read_text().splitlines() if line]
    failures = []
    for event in events:
        actual = detect(event)
        if actual != event["expected"]:
            failures.append({"id": event["id"], "expected": event["expected"], "actual": actual})
    if failures:
        raise SystemExit(json.dumps(failures, indent=2))
    positives = sum(1 for event in events if event["expected"])
    negatives = len(events) - positives
    print(f"PASS SAF-T1506 detection fixtures={len(events)} positive={positives} negative={negatives}")


if __name__ == "__main__":
    main()
