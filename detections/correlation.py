from collections import defaultdict
from datetime import datetime, timedelta

from detections.atomic import is_admin_attach

def to_dt(event_time: str) -> datetime:
    return datetime.fromisoformat(event_time.replace("Z", "+00:00"))

def correlate_privesc_chain(events: list[dict], minutes: int = 15) -> list[dict]:
    by_target = defaultdict(list)

    for evt in events:
        tgt = (evt.get("requestParameters") or {}).get("userName")
        if tgt:
            by_target[tgt].append(evt)

    correlated = []
    window = timedelta(minutes=minutes)

    for target_user, evts in by_target.items():
        evts_sorted = sorted(evts, key=lambda x: to_dt(x["eventTime"]))

        for start_evt in evts_sorted:
            start_t = to_dt(start_evt["eventTime"])
            end_t = start_t + window

            slice_evts = [
                x for x in evts_sorted
                if start_t <= to_dt(x["eventTime"]) <= end_t
            ]

            has_create_user = any(x.get("eventName") == "CreateUser" for x in slice_evts)
            has_admin_attach = any(is_admin_attach(x) for x in slice_evts)
            has_access_key = any(x.get("eventName") == "CreateAccessKey" for x in slice_evts)

            if has_create_user and has_admin_attach and has_access_key:
                correlated.append({
                    "severity": "CRITICAL",
                    "event_name": "PrivEscChain",
                    "reason": f"CreateUser + AttachUserPolicy(Admin) + CreateAccessKey within {minutes}m for {target_user}",
                    "target_user": target_user,
                })
                break

    return correlated