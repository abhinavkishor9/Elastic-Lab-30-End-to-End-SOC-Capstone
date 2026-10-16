# Troubleshooting Notes — Lab 30: End-to-End Elastic Security SOC Capstone

## Issue

The combined ES|QL detection query for potentially suspicious PowerShell execution returns zero results, even though broader queries return Sysmon process-creation records and PowerShell process events.

The objective is to isolate the condition responsible for the zero-result query without making unsupported changes to the endpoint or Elastic configuration.

## 1. Confirm the Baseline

Run:

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

The supplied output showed 51,901 records in the primary group associated with:

- Host: `desktop-9mmm37v`
- Provider: `Microsoft-Windows-Sysmon`
- Dataset: `windows.sysmon_operational`

This confirms that records matching the baseline query are available. Continue by inspecting the actual event documents.

## 2. Inspect Complete Process-Creation Records

Run:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| KEEP @timestamp, host.name, event.code,
       event.provider, event.dataset,
       process.name, process.executable,
       process.command_line, process.pid,
       process.parent.name, user.name
| SORT @timestamp DESC
| LIMIT 30
```

Inspect the complete values returned by Kibana.

Verify:

- Whether `process.name` is populated.
- Whether `process.command_line` contains the full command line.
- Whether the executable path matches the process name.
- Whether the timestamp covers the controlled test period.
- Whether the provider and dataset identify the expected event source.

Do not rely on truncated screenshot text to determine the exact command-line arguments.

## 3. Validate PowerShell Process Matching

Run:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.name IS NOT NULL
| WHERE process.name LIKE "*powershell.exe"
    OR process.name LIKE "*pwsh.exe"
| KEEP @timestamp, host.name, process.name,
       process.executable, process.command_line,
       process.pid, user.name
| SORT @timestamp DESC
| LIMIT 100
```

The supplied results already show that a PowerShell-focused query can return records.

Inspect the exact values of `process.name` and compare them with the expected patterns. If necessary, use the unfiltered process-creation query to discover the field representation before changing the query.

## 4. Inspect Command-Line Availability

Run:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.name LIKE "*powershell.exe"
    OR process.name LIKE "*pwsh.exe"
| KEEP @timestamp, process.name,
       process.command_line, process.pid
| SORT @timestamp DESC
| LIMIT 100
```

Review the actual command-line values.

Check whether the encoded-command or hidden-window options are present in the indexed records. The fact that a command executed locally does not prove that its process-creation event was indexed or contains the expected field values.

## 5. Test Each Command-Line Condition Independently

Start with one condition:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.command_line IS NOT NULL
| WHERE process.command_line LIKE "*-encodedcommand*"
| KEEP @timestamp, process.name,
       process.command_line, process.pid
| SORT @timestamp DESC
| LIMIT 100
```

If this returns no results, inspect the raw command-line values and verify the field's actual representation.

Then test the remaining patterns separately:

- `*-enc*`
- `*-windowstyle hidden*`
- `*-w hidden*`

Do not assume that a pattern is valid for your indexed values simply because it looks correct in the query editor.

## 6. Confirm the Controlled Test Events

The earlier lab used harmless PowerShell commands for baseline, encoded-command, and hidden-window tests.

To validate detection properly:

1. Record the current time.
2. Execute one controlled test command.
3. Wait for the event to be collected and indexed.
4. Search the appropriate time range.
5. Confirm the corresponding process-creation event.
6. Inspect its complete command line.
7. Run the relevant detection condition against that record.

Repeat the process for each test case.

If the event cannot be found, investigate event collection and indexing separately from detection logic.

## 7. Check Query Conditions Incrementally

Once the raw records are understood, add conditions in this order:

1. Event code and Sysmon provider.
2. Process-name filter.
3. Non-null command-line condition.
4. One command-line pattern.
5. Remaining patterns.
6. Final projection and sorting.

Run the query after each addition. Record the point at which the expected test event disappears from the results.

This provides a more reliable troubleshooting path than rewriting the complete detection query without isolating the failure.

## 8. Verify Time Range and Event Correlation

The visible records include timestamps from 15 October 2026. The supplied screenshots do not prove that these records correspond to the controlled test commands executed during the lab.

Use a time range that includes the actual test execution. When correlating events, compare timestamps, host, process identifiers, and other available fields.

Do not assume that matching host names or similar process names establish that two records belong to the same process instance.

## 9. Troubleshooting Decision Table

| Observation | Recommended action |
|---|---|
| Baseline returns Sysmon records | Continue to inspect individual documents |
| PowerShell query returns records | Verify exact process-name values and command lines |
| Command-line fields are empty | Investigate the source event and field availability |
| Encoded-command pattern returns no results | Inspect raw command lines and test the pattern independently |
| Controlled test command is absent from Elasticsearch | Check the time range and event collection path |
| Individual conditions work but the combined query does not | Add conditions incrementally and identify the excluding condition |
| Detection returns expected controlled test events | Proceed to false-positive evaluation and rule validation |

## Conclusion

The root cause of the zero-result detection query remains unresolved.

The current evidence supports the presence of Sysmon process-creation records and PowerShell events, but does not establish why the combined detection conditions fail to match.

Continue with read-only document inspection, controlled test-event validation, and incremental query testing. Avoid reinstalling Sysmon, re-enrolling Elastic Agent, or changing collection configuration unless the evidence identifies a specific need.
