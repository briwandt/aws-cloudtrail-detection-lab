def is_target_event(event_name: str) -> bool:
    return event_name in {
        "CreateUser",
        "CreateAccessKey",
        "AttachUserPolicy",
        "StopLogging",
    }

def is_admin_attach(evt: dict) -> bool:
    if evt.get("eventName") != "AttachUserPolicy":
        return False
    policy_arn = (evt.get("requestParameters") or {}).get("policyArn", "") or ""
    return "AdministratorAccess" in policy_arn

def severity_and_reason(evt: dict) -> tuple[str, str]:
    name = evt.get("eventName")

    if name == "StopLogging":
        return "CRITICAL", "CloudTrail logging stopped (defense evasion)"

    if name == "AttachUserPolicy":
        policy_arn = (evt.get("requestParameters") or {}).get("policyArn", "")
        if "AdministratorAccess" in (policy_arn or ""):
            return "HIGH", f"AdministratorAccess attached: {policy_arn}"
        return "MEDIUM", f"User policy attached: {policy_arn}"

    if name == "CreateAccessKey":
        return "MEDIUM", "Access key created (persistence risk)"

    if name == "CreateUser":
        return "LOW", "New IAM user created"

    return "INFO", "Event matched"