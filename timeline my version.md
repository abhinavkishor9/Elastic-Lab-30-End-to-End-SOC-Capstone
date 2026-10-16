# Investigation Timeline 
| Timestamp / Stage | Activity | Observed evidence | Assessment |
|---|---|---|---|
| Baseline query | Aggregated records matching event code `1` | Primary group contained 51,901 records for `desktop-9mmm37v`, provider `Microsoft-Windows-Sysmon`, dataset `windows.sysmon_operational` | Sysmon process-creation records are available in the queried data |
| 15 Oct 2026, 06:49:42.173 | Process-creation record | `Sysmon64.exe`, executable `C:\Windows\Sysmon64.exe`, command line ending in `-u` | Record visible; context not fully investigated |
| 15 Oct 2026, 06:49:41.163 | Process-creation record | `powershell.exe` on `desktop-9mmm37v` | PowerShell process record is present |
| 15 Oct 2026, 06:49:35.946 | PowerShell-focused result | `powershell.exe`, user `SYSTEM` | Account context requires investigation; not inherently malicious |
| 15 Oct 2026, 06:49:30.714 | PowerShell-focused result | `powershell.exe`, user `SYSTEM` | Additional process record; full command line not visible |
| Detection validation | Executed combined PowerShell detection query | Zero matching documents | Detection not yet validated |
| Follow-up assessment | Compared broad process results with restrictive detection results | Broad queries return process records; combined detection does not | Requires field and condition-level troubleshooting |

