import argparse
import json
from datetime import datetime, timedelta, timezone

import boto3

from detections.atomic import is_target_event, severity_and_reason
from detections.correlation import correlate_privesc_chain

LOG_GROUP = "detection-lab-cloudtrail"

def parse_event(message: str):
    message = message.strip()
    if not message:
        return None
    try:
        return json.loads(message)
    except json.JSONDecodeError:
        return None

def main():
    parser = argparse.ArgumentParser(description="CloudTrail detection lab")
    parser.add_argument("--hours", type=int, default=6)
    parser.add_argument("--actor", type=str, default=None)
    args = parser.parse_args()

    client = boto3.client("logs")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=args.hours)

    resp = client.filter_log_events(
        logGroupName=LOG_GROUP,
        startTime=int(start_time.timestamp() * 1000),
        endTime=int(end_time.timestamp() * 1000),
    )

    parsed_events = []
    alerts = []

    for e in resp.get("events", []):
        evt = parse_event(e.get("message", ""))
        if not evt:
            continue

        event_name = evt.get("eventName")
        if not event_name or not is_target_event(event_name):
            continue

        ui = evt.get("userIdentity") or {}
        actor = ui.get("userName") or ""

        if args.actor and actor != args.actor:
            continue

        sev, reason = severity_and_reason(evt)

        alert = {
            "severity": sev,
            "event_name": event_name,
            "reason": reason,
            "event_time": evt.get("eventTime"),
            "actor": actor or ui.get("arn"),
            "target_user": (evt.get("requestParameters") or {}).get("userName"),
        }

        alerts.append(alert)
        parsed_events.append(evt)

    correlated = correlate_privesc_chain(parsed_events, minutes=15)

    output = {
        "alerts": alerts,
        "correlated_findings": correlated,
    }

    print(json.dumps(output, indent=2))

    with open("alerts.json", "w") as f:
        json.dump(output, f, indent=2)

if __name__ == "__main__":
    main()