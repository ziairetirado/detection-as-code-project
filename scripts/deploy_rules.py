"""
Deploy stage of the pipeline: convert each Sigma rule in rules/sigma/ into
an Elastic Security detection rule and push it to the SIEM via the Kibana
Detection Engine API.

In real usage, the Sigma -> Elastic query translation is done with sigma-cli
(pySigma) using the `elasticsearch` backend, e.g.:

    sigma convert -t lucene -p ecs_windows rules/sigma/my_rule.yml

This script wraps that conversion and the API push so the whole thing can
run unattended in CI/CD. It never runs on pull requests — only on merge to
main (see .github/workflows/detection-as-code.yml) — so untested rules
never reach the SIEM.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules", "sigma")


def convert_rule_to_query(rule_path: str) -> str:
    """Shell out to sigma-cli to translate a Sigma rule into a Lucene query
    Elastic can run. Requires `pip install sigma-cli sigma-backend-elasticsearch`.
    """
    result = subprocess.run(
        ["sigma", "convert", "-t", "lucene", "-p", "ecs_cloudtrail", rule_path],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def push_to_elastic(rule_name: str, query: str, level: str, kibana_url: str, api_key: str, dry_run: bool) -> None:
    severity_map = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
    payload = {
        "name": rule_name,
        "type": "query",
        "query": query,
        "language": "lucene",
        "index": ["cloudtrail-*"],
        "severity": severity_map.get(level, "medium"),
        "enabled": True,
        "interval": "5m",
        "from": "now-6m",
    }

    if dry_run:
        print(f"[dry-run] Would PUT rule '{rule_name}' to {kibana_url}/api/detection_engine/rules")
        print(json.dumps(payload, indent=2))
        return

    req = urllib.request.Request(
        url=f"{kibana_url}/api/detection_engine/rules",
        data=json.dumps(payload).encode(),
        method="PUT",
        headers={
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Authorization": f"ApiKey {api_key}",
        },
    )
    with urllib.request.urlopen(req) as resp:
        print(f"Deployed '{rule_name}': HTTP {resp.status}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Print the payload instead of calling Kibana")
    args = parser.parse_args()

    kibana_url = os.environ.get("KIBANA_URL", "")
    api_key = os.environ.get("ELASTIC_API_KEY", "")

    if not args.dry_run and (not kibana_url or not api_key):
        print("KIBANA_URL and ELASTIC_API_KEY must be set (or pass --dry-run)", file=sys.stderr)
        sys.exit(1)

    for fname in sorted(os.listdir(RULES_DIR)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        rule_path = os.path.join(RULES_DIR, fname)
        try:
            query = convert_rule_to_query(rule_path)
        except FileNotFoundError:
            print("sigma-cli not installed; install with: pip install sigma-cli sigma-backend-elasticsearch", file=sys.stderr)
            sys.exit(1)

        import yaml
        with open(rule_path) as f:
            rule = yaml.safe_load(f)

        push_to_elastic(rule["title"], query, rule.get("level", "medium"), kibana_url, api_key, args.dry_run)


if __name__ == "__main__":
    main()
