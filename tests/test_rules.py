"""
For every detection rule, assert it fires on the matching malicious sample
log and stays silent on the paired benign sample log. Run with:

    pytest tests/ -v
"""
import os
import pytest
from sigma_matcher import evaluate, load_rule, load_event

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules", "sigma")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "sample_logs")

CASES = [
    ("aws_cloudtrail_disabled.yml", "cloudtrail_disabled_malicious.json", "cloudtrail_disabled_benign.json"),
    ("aws_iam_admin_policy_grant.yml", "iam_admin_grant_malicious.json", "iam_admin_grant_benign.json"),
    ("aws_console_login_no_mfa.yml", "console_login_no_mfa_malicious.json", "console_login_no_mfa_benign.json"),
    ("aws_security_group_open_world.yml", "sg_open_world_malicious.json", "sg_open_world_benign.json"),
    ("aws_s3_bucket_made_public.yml", "s3_public_malicious.json", "s3_public_benign.json"),
]


@pytest.mark.parametrize("rule_file,malicious_log,benign_log", CASES)
def test_rule_detects_malicious_event(rule_file, malicious_log, benign_log):
    rule = load_rule(os.path.join(RULES_DIR, rule_file))
    event = load_event(os.path.join(LOGS_DIR, malicious_log))
    assert evaluate(rule, event) is True, f"{rule_file} failed to detect its malicious sample event"


@pytest.mark.parametrize("rule_file,malicious_log,benign_log", CASES)
def test_rule_ignores_benign_event(rule_file, malicious_log, benign_log):
    rule = load_rule(os.path.join(RULES_DIR, rule_file))
    event = load_event(os.path.join(LOGS_DIR, benign_log))
    assert evaluate(rule, event) is False, f"{rule_file} raised a false positive on its benign sample event"


def test_all_rules_have_required_sigma_fields():
    required = {"title", "id", "status", "description", "logsource", "detection", "level"}
    for fname in os.listdir(RULES_DIR):
        rule = load_rule(os.path.join(RULES_DIR, fname))
        missing = required - rule.keys()
        assert not missing, f"{fname} is missing required Sigma fields: {missing}"
