# Investigation Timeline — Lab 30: End-to-End Elastic Security SOC Capstone

## 15–16 October 2026 — Investigation Evidence

The timestamps below reflect the records visible in the supplied screenshots. The exact time of each controlled test execution and its corresponding indexed event has not been established.

| Timestamp / Stage | Activity | Observed evidence | Assessment |
|---|---|---|---|
| Baseline query | Aggregated records matching event code `1` | Primary group contained 51,901 records for `desktop-9mmm37v`, provider `Microsoft-Windows-Sysmon`, dataset `windows.sysmon_operational` | Sysmon process-creation records are available in the queried data |
| 15 Oct 2026, 06:49:42.173 | Process-creation record | `Sysmon64.exe`, executable `C:\Windows\Sysmon64.exe`, command line ending in `-u` | Record visible; context not fully investigated |
| 15 Oct 2026, 06:49:41.163 | Process-creation record | `powershell.exe` on `desktop-9mmm37v` | PowerShell process record is present |
| 15 Oct 2026, 06:49:35.946 | PowerShell-focused result | `powershell.exe`, user `SYSTEM` | Account context requires investigation; not inherently malicious |
| 15 Oct 2026, 06:49:30.714 | PowerShell-focused result | `powershell.exe`, user `SYSTEM` | Additional process record; full command line not visible |
| Detection validation | Executed combined PowerShell detection query | Zero matching documents | Detection not yet validated |
| Follow-up assessment | Compared broad process results with restrictive detection results | Broad queries return process records; combined detection does not | Requires field and condition-level troubleshooting |

## Evidence Limitations

- Some command-line values are truncated in the screenshots.
- Displayed PID values should be verified against the original event documents.
- The exact indexed events corresponding to the controlled test commands have not been confirmed.
- The reason for the zero-result detection query remains unresolved.

## Current Status

**Detection validation in progress.**

The evidence confirms that Sysmon process-creation records and PowerShell process records are available. It does not confirm that the suspicious-command-line detection works or that a security incident occurred.

## Next Steps

1. Inspect complete process-creation documents.
2. Locate the controlled test events in Elasticsearch.
3. Verify the actual command-line values.
4. Test each detection condition independently.
5. Validate the combined detection against controlled positive and negative cases.
6. Complete the investigation report with confirmed results and remaining limitations.
