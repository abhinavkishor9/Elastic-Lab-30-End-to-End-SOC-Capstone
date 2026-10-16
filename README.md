# Lab 30 — End-to-End Elastic Security SOC Capstone

## Overview

This capstone brings together endpoint telemetry validation, detection engineering, event investigation, and evidence-based SOC reporting using Elastic Security and Windows Sysmon.

The investigation focuses on potentially suspicious PowerShell execution. The objective is to validate the available process-creation telemetry, examine relevant process fields, evaluate detection logic, and determine whether the evidence supports a security concern or requires further investigation.

During the lab, broad ES|QL queries successfully returned Sysmon process-creation records and PowerShell process events. However, the detection query targeting encoded-command and hidden-window options returned zero results. This discrepancy became the main troubleshooting focus.

The investigation therefore emphasizes validating individual query conditions and actual event data before reaching conclusions about detection effectiveness.

## Lab Objectives

- Validate the availability of Windows Sysmon process-creation events in Elasticsearch.
- Inspect event providers, datasets, timestamps, and process-related fields.
- Identify PowerShell process records and examine their available execution context.
- Evaluate ES|QL detection logic for encoded-command and hidden-window indicators.
- Investigate why a restrictive detection query returns zero results despite the presence of PowerShell telemetry.
- Distinguish confirmed observations from hypotheses and unresolved visibility issues.
- Develop an evidence-based investigation timeline and document recommended next steps.

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

## Investigation Scenario

A SOC analyst is asked to investigate PowerShell executions that may use encoded commands or hidden-window options.

The analyst begins by validating Sysmon process-creation telemetry and then narrows the search to PowerShell processes. These broader queries return records, but the combined detection query does not identify any matching events.

The task is to establish what the available evidence demonstrates, determine which query conditions require further validation, and document the limitations preventing a confirmed detection result.

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

## Conclusion

Lab 30 demonstrates the importance of connecting telemetry validation, detection logic, investigation, and reporting into one repeatable SOC workflow.

The broad queries confirm that Sysmon process-creation and PowerShell records are present. However, the restrictive detection query returns no results, and the evidence is insufficient to determine why.

The next step is to inspect complete event documents, verify the actual process and command-line field values, locate the controlled test events, and test each filtering condition independently.

The investigation should remain open until the detection behavior is validated or the unresolved limitations are clearly documented. Suspicious indicators and missing results must not be treated as proof of compromise.
