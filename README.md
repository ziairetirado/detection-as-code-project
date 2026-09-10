# Detection as Code

Security detections written, version-controlled, tested, and deployed the
same way application code is — instead of clicking rules together by hand
in a SIEM UI.

## Architecture

<img width="1408" height="768" alt="DaC Architecture Diagram" src="https://github.com/user-attachments/assets/1857c90a-5a7c-4803-a557-60116216dccd" />




## How it works

```
rules/sigma/*.yml   -->  tests/ (pytest)  -->  CI validates + tests  -->  merge to main  -->  CD converts + deploys to Elastic SIEM
```

1. **Write detection logic as YAML** — each rule lives in `rules/sigma/` as
   a [Sigma rule](https://github.com/SigmaHQ/sigma): vendor-neutral,
   human-readable, and convertible to almost any SIEM's query language.
2. **Version control** — rules are just files in this Git repo. Every
   change goes through a pull request, gets reviewed, and has a full
   history/blame — no more "who changed this alert and why."
3. **Test before deploying** — `tests/sample_logs/` has paired
   malicious/benign sample events for each rule. `tests/test_rules.py`
   runs every rule against both and asserts it fires on the attack and
   stays silent on the look-alike benign activity (catches both missed
   detections and false-positive-prone rules before they ever reach
   production).
4. **CI/CD pipeline** — `.github/workflows/detection-as-code.yml`:
   - On every PR: lints Sigma syntax (`sigma check`) and runs the test suite.
   - On merge to `main`: converts each rule to a Lucene query with
     `sigma-cli`'s Elasticsearch backend and pushes it to the Elastic
     Security Detection Engine API (`scripts/deploy_rules.py`) — fully
     automated, no manual "add rule" step in the SIEM.

Run the tests locally:

```bash
pip install -r requirements.txt
cd tests && pytest -v
```

Preview what would be deployed without touching the SIEM:

```bash
python scripts/deploy_rules.py --dry-run
```

## The 5 detection rules (common cloud threats)

| Rule | Detects | MITRE ATT&CK |
|---|---|---|
| `aws_cloudtrail_disabled.yml` | An identity stopping/deleting CloudTrail logging | T1562.008 – Impair Defenses |
| `aws_iam_admin_policy_grant.yml` | AdministratorAccess attached to a user/role | T1098 – Account Manipulation |
| `aws_console_login_no_mfa.yml` | Successful console login without MFA | T1078.004 – Valid Accounts: Cloud Accounts |
| `aws_security_group_open_world.yml` | Security group ingress opened to 0.0.0.0/0 | T1562.007 – Disable/Modify Cloud Firewall |
| `aws_s3_bucket_made_public.yml` | S3 public access block disabled or public ACL set | T1530 – Data from Cloud Storage |

Each rule follows the same Sigma anatomy: `logsource` (what data it runs
against — AWS CloudTrail here), `detection` (the match logic), `level`
(severity), and MITRE ATT&CK tags for triage context.

## Why Sigma specifically

Sigma decouples the *detection logic* from the *SIEM it runs on*. The same
rule file can be converted to Elastic/Lucene, Splunk SPL, or Microsoft
Sentinel KQL with `sigma-cli` — so if the org ever migrates SIEMs, the
detection content migrates with a conversion command, not a rewrite.
