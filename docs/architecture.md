# Architecture

This project is a small AWS detection engineering lab that ingests CloudTrail events from CloudWatch Logs and produces:
- **Atomic detections** (single-event rules)
- **Correlated detections** (multi-event chains)

## Data flow

1. **CloudTrail Trail** (multi-region recommended) writes management events.
2. Trail delivers to:
   - S3 (long-term storage)
   - **CloudWatch Logs** (near real-time queries)
3. `detector.py` queries CloudWatch Logs with `filter_log_events` over a lookback window.
4. Events are parsed from JSON and evaluated by:
   - `detections/atomic.py`
   - `detections/correlation.py`
5. Output:
   - Printed JSON to stdout
   - Written to `alerts.json` locally

## Components

- `detector.py`
  - CLI entry point
  - Pulls logs from CloudWatch
  - Applies atomic + correlation detections
- `detections/atomic.py`
  - Detection helpers (severity + reason)
- `detections/correlation.py`
  - Simple privilege-escalation chain correlation
- `tests/`
  - Unit tests for detection logic

## Assumptions
- CloudTrail is configured to send events to a CloudWatch Log Group named `detection-lab-cloudtrail`.
- This is a lab: rules are intentionally simple and meant to be extended.