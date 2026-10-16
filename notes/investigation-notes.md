# Investigation Notes — Lab 30: End-to-End Elastic Security SOC Capstone

## 1. Investigation Summary

The objective was to investigate potentially suspicious PowerShell execution using Elastic Security, Kibana, ES|QL, and Windows Sysmon telemetry.

The investigation began with a baseline query for event code `1`, followed by inspection of individual process-creation records and a query focused on PowerShell executables.

The broader queries returned process records, including `Sysmon64.exe` and `powershell.exe`. However, the detection query targeting encoded-command and hidden-window options returned zero matching documents.

The current investigation therefore focuses on understanding the difference between the available process telemetry and the results produced by the restrictive detection query.

## 2. Evidence A — Baseline Event Aggregation

### Query

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

### Observations

The supplied screenshot showed approximately 52,000 documents processed and eight grouped results.

The primary group contained:

- Event count: `51,901`
- Host: `desktop-9mmm37v`
- Provider: `Microsoft-Windows-Sysmon`
- Dataset: `windows.sysmon_operational`
- Module: `windows`

Additional groups included records associated with the `system.system` dataset and other Windows event providers.

### Interpretation

The results confirm that the query can retrieve a substantial volume of records associated with Sysmon process-creation telemetry.

The aggregation does not establish that all process fields are populated or that the controlled PowerShell tests are present in the indexed records.

## 3. Evidence B — Individual Sysmon Process Events

### Query

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

### Observations

The visible results included:

- Timestamp: `Oct 15, 2026 @ 06:49:42.173`
- Process: `Sysmon64.exe`
- Executable: `C:\Windows\Sysmon64.exe`
- Command line: `"C:\Windows\Sysmon64.exe" -u`
- Another record at `Oct 15, 2026 @ 06:49:41.163` for `powershell.exe`.
- Additional `Sysmon64.exe` records in the displayed results.

Some command-line values and PID values were truncated or formatted in the screenshot.

### Interpretation

These records demonstrate that process-creation events and PowerShell process entries are available in the queried data.

The visible command lines are insufficient to determine whether the relevant events contain the encoded-command or hidden-window patterns used by the detection query.

## 4. Evidence C — PowerShell-Focused Search

### Query conditions

The PowerShell-focused query filtered event code `1` records by the Sysmon provider and matched process names containing `powershell.exe` or `pwsh.exe`.

### Observations

The screenshot showed:

- Approximately 200 documents processed.
- Up to 100 results displayed.
- Visible records for `powershell.exe`.
- Host: `desktop-9mmm37v`.
- User: `SYSTEM` in the visible rows.
- Timestamps including `Oct 15, 2026 @ 06:49:41.163`, `06:49:35.946`, and `06:49:30.714`.

The screenshot truncated the command-line values.

### Interpretation

The query confirms that PowerShell process records can be returned using the selected process-name filter.

The `SYSTEM` account context is not inherently malicious. It must be evaluated alongside the process command line, parent process, execution purpose, and surrounding evidence.

The visible timestamps do not establish that these records correspond to the controlled test commands executed during the lab.

## 5. Evidence D — Combined Detection Query

### Detection objective

Identify PowerShell process-creation events containing encoded-command or hidden-window options.

### Observed result

The supplied detection query returned zero documents processed and no matching results.

### Interpretation

The combined query did not identify matching events in the selected search context.

Potential explanations requiring investigation include:

- The actual process name differs from the assumed representation.
- The command-line field does not contain the expected text.
- One or more `LIKE` patterns do not match the indexed values.
- The controlled test events are not present in the selected time range.
- The relevant records have missing or incomplete command-line data.

None of these explanations has been confirmed.

## 6. Evidence Assessment

### Confirmed observations

- Sysmon process-creation records are present in the queried data.
- The primary baseline group is associated with `Microsoft-Windows-Sysmon` and `windows.sysmon_operational`.
- PowerShell process records are returned by a broader query.
- Some visible PowerShell records are associated with `SYSTEM`.
- The combined detection query returns zero matching documents.

### Unresolved questions

- Do the indexed documents contain the complete command lines from the controlled tests?
- Are the exact process-name and command-line values compatible with the detection patterns?
- Are the relevant test events within the selected time range?
- Which condition, if any, is excluding otherwise relevant events?
- Can the detection be validated after the relevant evidence is located?

## 7. Current Investigation Assessment

**Status:** Detection validation in progress.

The current evidence does not establish a confirmed security incident. It establishes that broad process queries return Sysmon and PowerShell records, while the combined detection query returns no matches.

The next investigation stage is to inspect the underlying event documents, locate the controlled test executions, and validate each detection condition independently.

## 8. Recommended Next Actions

1. Inspect complete Sysmon process-creation documents.
2. Verify `process.name`, `process.command_line`, `process.pid`, and `process.parent.name`.
3. Record the exact timestamps of new controlled tests.
4. Confirm whether the corresponding events are indexed.
5. Test process-name and command-line conditions separately.
6. Combine the validated conditions and repeat the test cases.
7. Document any remaining telemetry or detection limitations.
