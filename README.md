## AWS CloudTrail Detection Lab

Cloud-Native Detection Engineering | Atomic + Correlated IAM Detections

## 📌 Overview

This project demonstrates cloud detection engineering using:

AWS CloudTrail (management event telemetry)

CloudWatch Logs (log ingestion layer)

Python (detection engine)

Correlated detection logic (privilege escalation chain)

The goal is to simulate real-world IAM attack patterns and detect them using both atomic and multi-event correlation logic.

## 🏗 Architecture
IAM Activity (CreateUser, AttachUserPolicy, CreateAccessKey)
        ↓
CloudTrail (Management Events)
        ↓
CloudWatch Logs (detection-lab-cloudtrail)
        ↓
Python Detection Engine (detector.py)
        ↓
alerts.json (structured findings)

## 🚨 Atomic Detections
Event	Severity	Rationale
CreateUser	LOW	New identity created
AttachUserPolicy (AdministratorAccess)	HIGH	Direct privilege escalation
CreateAccessKey	MEDIUM	Persistence via long-term credential
StopLogging	CRITICAL	Defense evasion (audit logging disabled)

## 🔗 Correlated Detection: PrivEscChain (CRITICAL)

Triggers when the following occur for the same user within 15 minutes:

CreateUser

AttachUserPolicy with AdministratorAccess

CreateAccessKey

Why This Matters

This sequence models a high-confidence attack pattern:

Identity creation → Privilege escalation → Persistent credential issuance

This is common in real cloud breaches.

## 🧪 Example Output
{
  "severity": "CRITICAL",
  "event_name": "PrivEscChain",
  "reason": "CreateUser + AttachUserPolicy(Admin) + CreateAccessKey within 15m for test-user-1"
}
⚙️ How To Run
python detector.py --hours 6 --actor lab-admin

Optional arguments:

--hours → detection lookback window

--actor → filter by IAM user performing the action

### Correlated Privilege Escalation Detection

Python detection engine output showing correlated PrivEscChain alert.

![PrivEsc Detection Output](docs/screenshots/privesc_detection_output.png)

## 🧠 Detection Engineering Concepts Demonstrated

Cloud-native telemetry ingestion

IAM privilege escalation modeling

Event normalization

Severity scoring

Correlation window logic

False positive reduction (actor filtering)

Structured alert output (JSON)

## 🔒 Security Notes

All testing performed in a dedicated lab AWS account

Access keys rotated after testing

No production systems used

# 📈 Future Improvements

Allowlist support

Alert deduplication

Sigma rule export

Slack/SNS alert integration

Unit tests for detection logic

Detection-as-Code rule framework

## 🔎 Technical Appendix

Detection Engine Design

The detection engine is intentionally structured as modular “detection-as-code” components:

detector.py

CLI entrypoint

Queries CloudWatch Logs via filter_log_events

Applies atomic and correlated detection logic

Outputs structured JSON findings

detections/atomic.py

Event classification

Severity scoring

Privilege escalation detection (AdministratorAccess attachment)

detections/correlation.py

Time-window based correlation (default: 15 minutes)

Groups events by requestParameters.userName

Detects multi-stage privilege escalation chains

## Event Normalization Strategy

Events are:

Parsed from CloudWatch message JSON

Filtered to high-signal IAM management events

Enriched with:

actor

target_user

event_time

severity

reason

This mimics a lightweight SIEM pipeline.

## Testing Strategy

Unit tests validate:

Atomic detection correctness

Privilege escalation classification

Correlation logic for PrivEscChain

Tests are executed via:

python -m pytest -q

This ensures detection logic behaves deterministically independent of AWS runtime.

## Known Limitations

Relies on CloudTrail delivery latency

No deduplication or state store

No allowlisting of break-glass roles

No enrichment (IP geo, ASN, etc.)

These are intentional simplifications for lab scope.

👩‍💻 Author

Detection Engineering Lab by Brianna Morgan
Focused on cloud-native detection engineering and security automation.
