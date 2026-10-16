# Elastic-Lab-30-End-to-End-SOC-Capstone
## Overview
In a real SOC, an analyst must determine whether relevant logs are available, identify suspicious activity, correlate related events, assess risk, collect supporting evidence, and recommend an appropriate response. A good analyst must also recognize when the available evidence is insufficient to reach a conclusion.

1. Validate telemetry
Confirm that relevant endpoint events are available and their fields are populated.
|
V
2. Detect suspicious behavior
Use ES|QL and validated detection logic to identify activity that warrants investigation.
|
V
3. Investigate and correlate
Review process details, timestamps, user context, and related events.
|
v
4. Assess and respond
Determine what the evidence supports and recommend proportionate response actions.
|
V
5. Document the case
Produce a timeline, evidence summary, investigation conclusion, and follow-up actions.

This capstone brings together endpoint telemetry validation, detection engineering, event investigation, and evidence-based SOC reporting using Elastic Security and Windows Sysmon.

The investigation focuses on potentially suspicious PowerShell execution. The objective is to validate the available process-creation telemetry, examine relevant process fields, evaluate detection logic, and determine whether the evidence supports a security concern or requires further investigation.

During the lab, broad ES|QL queries successfully returned Sysmon process-creation records and PowerShell process events. However, the detection query targeting encoded-command and hidden-window options returned zero results. This discrepancy became the main troubleshooting focus.

The investigation therefore emphasizes validating individual query conditions and actual event data before reaching conclusions about detection effectiveness.

## Lab Objectives

The objective of this lab is to investigate Windows process activity in Elastic Security and evaluate the reliability of a PowerShell detection workflow using Sysmon telemetry and ES|QL.

By completing this lab, the learner will be able to:

- **Validate endpoint telemetry:** Confirm that Windows Sysmon process-creation events are available in Elastic and identify the relevant host, provider, and dataset.
- **Investigate process execution:** Examine PowerShell activity using process names, executable paths, command-line arguments, timestamps, and user context.
- **Evaluate detection logic:** Test ES|QL conditions designed to identify potentially suspicious PowerShell options, including encoded commands and hidden-window execution.
- **Troubleshoot zero-result queries:** Determine whether empty results are related to query syntax, field values, missing command-line data, time-range restrictions, or the absence of matching events.
- **Correlate investigation evidence:** Use available process telemetry to establish what can be confirmed and identify additional evidence needed to understand the activity.
- **Build an investigation timeline:** Organize observed events chronologically while documenting gaps and limitations in the available data.
- **Apply evidence-based triage:** Distinguish confirmed observations from suspicious indicators and unverified hypotheses without automatically treating PowerShell execution as malicious.
- **Document findings and recommendations:** Produce an investigation record that includes evidence, unresolved questions, detection limitations, and practical next steps.

### Expected Outcome

The lab should demonstrate a structured Elastic Security investigation workflow and establish whether the proposed detection logic can identify matching activity in the available telemetry. If the query returns no results, the outcome must document the failure and the evidence required for further troubleshooting rather than claiming successful detection.

## Lab Scenario

A security operations team is investigating Windows endpoint activity in Elastic Security after reviewing process-creation events collected through Sysmon. The investigation focuses on PowerShell execution and whether available endpoint telemetry can support the identification of potentially suspicious command-line behavior.

The analyst uses ES|QL to examine process activity on the endpoint `desktop-9mmm37v`, review relevant event attributes, and evaluate detection conditions associated with encoded PowerShell commands and hidden-window execution. The goal is to determine whether the detection logic matches the events actually stored in Elastic, rather than assuming that a query is effective simply because its syntax appears correct.

### Investigation Challenges

During the investigation, the analyst encounters different results across related queries:

- A broad search for Sysmon process-creation events returns records, confirming that relevant telemetry is available in the selected data stream.
- A focused search identifies PowerShell process activity, including events running under the `SYSTEM` account.
- The detection query targeting selected PowerShell command-line patterns returns no matching documents.
- Some displayed command lines are truncated, making it difficult to assess the complete execution arguments from the available results.
- The available evidence does not yet establish whether the detection conditions are incorrect, the required values are absent from the indexed events, or the relevant test activity falls outside the query's effective scope.

### Analyst's Task

The analyst must investigate these differences systematically by inspecting complete event documents, checking the actual values of relevant fields, and testing detection conditions individually. Where necessary, the analyst should verify timestamps, query time-range settings, and whether controlled test executions generated corresponding indexed events.

The investigation must also consider the surrounding process context before assigning significance to an event. PowerShell execution under `SYSTEM`, encoded command-line arguments, or hidden-window options may warrant closer examination, but none independently proves malicious activity.

### Expected Investigation Result

The final assessment should establish what the available telemetry confirms, whether the proposed detection logic has been demonstrated to work, and what remains unresolved. The analyst must document the investigation timeline, detection limitations, and recommended follow-up actions without inventing evidence or claiming a confirmed compromise.

The lab is considered complete when the findings are reproducible, the detection outcome is accurately documented, and the next investigative steps are justified by the available evidence.

## Environment

| Component | Details |
|---|---|
| SIEM | Elastic Security |
| Investigation interface | Kibana |
| Query language | ES|QL |
| Data view | `logs-*` |
| Endpoint | `desktop-9mmm37v` |
| Operating system | Windows 11 |
| Telemetry source | Windows Sysmon |
| Event provider | `Microsoft-Windows-Sysmon` |
| Dataset | `windows.sysmon_operational` |
| Investigation focus | PowerShell process creation |
| Detection objective | Identify potentially suspicious PowerShell command-line options |


## 1. Baseline Telemetry Validation

The baseline query groups records matching event code `1` by host and event metadata.

```esql
FROM logs-*
| WHERE event.code == "1"
| STATS event_count = COUNT(*) BY
    host.name,
    event.provider,
    event.dataset,
    event.module
| SORT event_count DESC
| LIMIT 50
```

The supplied results showed:

- Approximately 52,000 documents processed.
- 51,901 records in the primary group.
- Host: `desktop-9mmm37v`.
- Provider: `Microsoft-Windows-Sysmon`.
- Dataset: `windows.sysmon_operational`.
- Module: `windows`.

This establishes that a substantial volume of records matching the query is associated with Sysmon process-creation telemetry.

## 2. Process-Creation Inspection

The investigation then examined individual Sysmon events:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| KEEP @timestamp, host.name, event.code,
       process.name, process.executable,
       process.command_line, process.pid
| SORT @timestamp DESC
| LIMIT 50
```

The visible records included:

- `Sysmon64.exe`, with executable path `C:\Windows\Sysmon64.exe`.
- `powershell.exe`, with an executable path under `C:\Windows\System32`.
- Process command lines that were partially truncated in the supplied screenshot.

A separate PowerShell-focused query returned records for `powershell.exe`, including entries associated with the `SYSTEM` account.

These results confirm that PowerShell process records are present in the queried dataset. They do not, by themselves, establish that the controlled test commands match the intended detection criteria.

## 3. Detection Query

The detection hypothesis focuses on PowerShell executions containing encoded-command or hidden-window indicators.

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.name IS NOT NULL
| WHERE process.command_line IS NOT NULL
| WHERE process.name LIKE "*powershell.exe"
    OR process.name LIKE "*pwsh.exe"
| WHERE process.command_line LIKE "*-enc*"
    OR process.command_line LIKE "*-encodedcommand*"
    OR process.command_line LIKE "*-windowstyle hidden*"
    OR process.command_line LIKE "*-w hidden*"
| KEEP @timestamp, host.name, user.name,
       process.name, process.command_line,
       process.pid, process.parent.name
| SORT @timestamp DESC
| LIMIT 100
```

### Observed Result

The query returned zero matching documents.

The evidence does not establish the precise reason for this result. Possible explanations include differences in actual field values, pattern matching, missing command-line data in relevant events, or the absence of the controlled test events in the selected time range.

These possibilities require further testing before a root cause can be identified.

## Key Findings

- Sysmon process-creation records are available in Elasticsearch.
- The queried dataset includes `powershell.exe` process records.
- Some visible process records are associated with the `SYSTEM` account.
- The supplied screenshots truncate command-line values, preventing complete review of those commands.
- The combined detection query returns zero matching documents.
- The detection has not yet been validated against confirmed indexed test events.
- No confirmed malicious activity was established by the supplied evidence.

## Investigation Limitations

- The complete command lines for the visible PowerShell records were not available in the screenshots.
- The displayed PID values should be verified against the underlying documents before using them for correlation.
- The exact indexed records corresponding to the controlled test commands have not been confirmed.
- The reason for the zero-result detection query remains unresolved.
- False-positive rates and scheduled-rule alert generation have not been validated.

