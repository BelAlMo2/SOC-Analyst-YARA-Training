# Threat Hunting Lab: Sigma Rule Translation and Offline Log Analysis

## Objective
The primary objective of this lab was to understand how to manually translate a built-in Sigma rule into a PowerShell query and execute it against an offline Windows Event Log (.evtx) file to identify malicious activity, specifically a malicious driver loaded onto the system.

## Tools and Technologies Used
* **Sigma / pySigma (sigmac):** A generic signature format for SIEM systems.
* **Windows Event Logs:** Security telemetry source.
* **PowerShell (Get-WinEvent):** Used for log parsing and querying.

## Methodology

### Step 1: Translating the Sigma Rule
We were provided with a built-in Sigma rule designed to detect Windows Defender threats, located at:
`C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml`

To utilize this rule in a Windows environment without a SIEM, I translated it into a native PowerShell command using the sigmac tool. 

**Command Executed:**
`python sigmac -t powershell 'C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml'`

**Translated PowerShell Query Output:**
`Get-WinEvent | where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message`

### Step 2: Modifying Query for Offline Log Analysis
By default, the translated query searches the live system logs. Since our target artifacts were located in an offline event log file, I modified the query by appending the `-Path` parameter to point to our specific evidence file (`lab_events_4.evtx`).

**Final Executed Query:**
`Get-WinEvent -Path "C:\Events\YARASigma\lab_events_4.evtx" | where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message`

## Findings and Conclusion
Upon executing the modified PowerShell command against the target log file, the query successfully filtered the events based on the Sigma rule conditions. By analyzing the Message field of the filtered output, the malicious driver was successfully identified.

**Malicious Driver Identified:** mimidrv.sys

**Evidence:**
![Threat Hunting Evidence](sigma_alert_output.jpg)
