# Detections

The repository currently contains nine Sigma rules from two investigation sources.

| Detection | Type | Source |
|---|---|---|
| AgentTesla-01 Self-Spawn | Case-scoped | Agent Tesla |
| AgentTesla-01 FTP Connection | Case-scoped | Agent Tesla |
| AgentTesla-01 FTP Domain Lookup | IOC | Agent Tesla |
| AgentTesla-01 IP-API Lookup | Case-scoped | Agent Tesla |
| Executable Masquerading as PDF via Double Extension | Behavioral | Threat Hunting with Splunk |
| Executable in Downloads Spawning Windows Command Shell | Behavioral | Threat Hunting with Splunk |
| Local Account Creation via Net Utility | Behavioral | Threat Hunting with Splunk |
| PowerShell Execution Policy Bypass Argument | Behavioral | Threat Hunting with Splunk |
| Threat Hunt Application Form C2 Connection | Case-scoped | Threat Hunting with Splunk |

Each rule has at least one positive fixture and is evaluated against every corpus in `ci/expectations.yml`. Benign and near-miss fixtures are used to make narrowing conditions regression-sensitive.

The rule set is intentionally small. New detections should be added only when an investigation provides evidence that can support both the rule logic and meaningful tests.
