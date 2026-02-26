from detections.atomic import is_admin_attach, is_target_event, severity_and_reason

def test_is_target_event():
    assert is_target_event("CreateUser") is True
    assert is_target_event("CreateAccessKey") is True
    assert is_target_event("AttachUserPolicy") is True
    assert is_target_event("StopLogging") is True
    assert is_target_event("ListUsers") is False

def test_is_admin_attach_true():
    evt = {
        "eventName": "AttachUserPolicy",
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    }
    assert is_admin_attach(evt) is True

def test_is_admin_attach_false_wrong_event():
    evt = {"eventName": "CreateUser", "requestParameters": {}}
    assert is_admin_attach(evt) is False

def test_severity_and_reason():
    evt = {"eventName": "CreateUser"}
    sev, _ = severity_and_reason(evt)
    assert sev == "LOW"

    evt = {"eventName": "CreateAccessKey"}
    sev, _ = severity_and_reason(evt)
    assert sev == "MEDIUM"

    evt = {
        "eventName": "AttachUserPolicy",
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    }
    sev, _ = severity_and_reason(evt)
    assert sev == "HIGH"