# ADR-011: Repository rules
- main is protected by a ruleset: pull request required (0 approvals because this is a solo project), the five CI checks must pass, force pushes and deletion are blocked, history stays linear.
- Work happens on short-lived branches; merge with squash only; head branches are deleted after merge.
- The Actions default token is read-only; Actions cannot approve pull requests.
- Dependabot alerts and updates, secret scanning and push protection are enabled where the plan allows.
- Emergency switch: Settings > Rules > Rulesets > set enforcement to Disabled, fix the problem, re-enable.
